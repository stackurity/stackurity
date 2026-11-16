package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

const deviceBase = "https://stackurity.example.com"

func newDeviceEnv(t *testing.T) *env {
	return newEnvWith(t, func(s *api.Server) { s.BaseURL = deviceBase })
}

// devicePost sends form values as an RFC 8628 client does: no credentials,
// no CSRF header. hdr may add headers (an address to come from).
func devicePost(t *testing.T, e *env, path string, v url.Values, hdr map[string]string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, x := range hdr {
		req.Header.Set(k, x)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

type deviceStart struct {
	DeviceCode string
	UserCode   string
}

func startDevice(t *testing.T, e *env, host string) deviceStart {
	t.Helper()
	code, out := devicePost(t, e, "/api/v1/device/code", url.Values{"client_id": {"stackurity-scan"}, "host": {host}}, nil)
	if code != 200 {
		t.Fatalf("device code: %d %v", code, out)
	}
	return deviceStart{DeviceCode: out["device_code"].(string), UserCode: out["user_code"].(string)}
}

func pollDevice(t *testing.T, e *env, d deviceStart) (int, map[string]any) {
	t.Helper()
	return devicePost(t, e, "/api/v1/device/token", url.Values{"grant_type": {api.DeviceGrantType}, "client_id": {"stackurity-scan"},
		"device_code": {d.DeviceCode}}, nil)
}

// allowPoll lets the next poll through at once, as if the interval had passed.
func allowPoll(t *testing.T, e *env) {
	t.Helper()
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()), `UPDATE device_authorizations SET last_polled_at = NULL`); err != nil {
		t.Fatal(err)
	}
}

func oauthErr(out map[string]any) string { s, _ := out["error"].(string); return s }

func TestDeviceLoginFlow(t *testing.T) {
	e := newDeviceEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	eng := e.login("eng@x.io")

	var meta struct{ Features []string }
	e.anon().do("GET", "/api/v1/meta", nil, &meta)
	if !strings.Contains(strings.Join(meta.Features, ","), api.FeatureDeviceLogin) {
		t.Fatalf("meta features %v lack %s", meta.Features, api.FeatureDeviceLogin)
	}

	code, out := devicePost(t, e, "/api/v1/device/code", url.Values{"client_id": {"stackurity-scan"}, "host": {"laptop-1"}}, nil)
	if code != 200 {
		t.Fatalf("device code: %d %v", code, out)
	}
	uc, _ := out["user_code"].(string)
	if !regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`).MatchString(uc) {
		t.Errorf("user_code %q", uc)
	}
	if out["verification_uri"] != deviceBase+"/device" || out["verification_uri_complete"] != deviceBase+"/device?user_code="+uc {
		t.Errorf("verification URIs: %v %v", out["verification_uri"], out["verification_uri_complete"])
	}
	if out["interval"] != float64(5) || out["expires_in"].(float64) < 590 || out["expires_in"].(float64) > 600 {
		t.Errorf("interval %v expires_in %v", out["interval"], out["expires_in"])
	}
	dc, _ := out["device_code"].(string)
	if !strings.HasPrefix(dc, "stkd_") {
		t.Errorf("device_code %q", dc)
	}
	// Only hashes are kept.
	var stored int
	if err := e.st.Pool.QueryRow(tenant.System(context.Background()), `SELECT count(*) FROM device_authorizations
		WHERE position($1::bytea in device_code_hash) > 0 OR position($2::bytea in user_code_hash) > 0`, []byte(dc), []byte(uc)).Scan(&stored); err != nil || stored != 0 {
		t.Errorf("codes stored in the clear: %d %v", stored, err)
	}
	d := deviceStart{DeviceCode: dc, UserCode: uc}

	if code, out := pollDevice(t, e, d); code != 400 || oauthErr(out) != "authorization_pending" {
		t.Fatalf("first poll: %d %v", code, out)
	}

	// The page: typed in lower case without the hyphen still works.
	var pv struct {
		Client     struct{ ID, Name string }
		Host       string
		CanApprove bool `json:"can_approve"`
		Workspace  struct{ ID int64 }
		TokenName  string `json:"token_name"`
		Projects   []any
	}
	typed := strings.ToLower(strings.ReplaceAll(uc, "-", ""))
	if code := eng.do("POST", "/api/v1/device/preview", map[string]string{"user_code": typed}, &pv); code != 200 {
		t.Fatalf("preview: %d", code)
	}
	if pv.Client.ID != "stackurity-scan" || pv.Client.Name == "" || pv.Host != "laptop-1" || !pv.CanApprove || pv.TokenName != "stackurity-scan on laptop-1" {
		t.Errorf("preview: %+v", pv)
	}
	if len(pv.Projects) != 0 {
		t.Errorf("an engineer is offered projects: %v", pv.Projects)
	}
	// An engineer cannot file the assets in a project.
	if code := eng.do("POST", "/api/v1/device/decision", map[string]any{"user_code": uc, "decision": "approve", "workspace_id": pv.Workspace.ID,
		"project_id": 1}, nil); code != 403 && code != 404 {
		t.Errorf("engineer with project_id: %d", code)
	}
	// The organisation the page showed must still be the session's.
	if code := eng.do("POST", "/api/v1/device/decision", map[string]any{"user_code": uc, "decision": "approve", "workspace_id": pv.Workspace.ID + 99}, nil); code != 409 {
		t.Errorf("another workspace_id: %d", code)
	}
	var dec struct {
		Status string
		Token  struct{ ID int64 }
	}
	if code := eng.do("POST", "/api/v1/device/decision", map[string]any{"user_code": uc, "decision": "approve", "workspace_id": pv.Workspace.ID}, &dec); code != 200 || dec.Status != "approved" {
		t.Fatalf("approve: %d %+v", code, dec)
	}
	// Decided: the code cannot be used again on the page.
	if code := eng.do("POST", "/api/v1/device/decision", map[string]any{"user_code": uc, "decision": "deny", "workspace_id": pv.Workspace.ID}, nil); code != 410 {
		t.Errorf("second decision: %d", code)
	}
	// The token is listed in Settings at once, under the person.
	var list struct {
		Items []struct {
			ID     int64
			Name   string
			Role   string
			Prefix string
		}
	}
	eng.do("GET", "/api/v1/tokens", nil, &list)
	toks := list.Items
	if len(toks) != 1 || toks[0].ID != dec.Token.ID || toks[0].Name != "stackurity-scan on laptop-1" || toks[0].Role != "collector" {
		t.Fatalf("tokens: %+v", toks)
	}

	allowPoll(t, e)
	code, out = pollDevice(t, e, d)
	if code != 200 {
		t.Fatalf("poll after approval: %d %v", code, out)
	}
	secret, _ := out["access_token"].(string)
	ws, _ := out["workspace"].(map[string]any)
	if !strings.HasPrefix(secret, "stk_") || out["token_type"] != "Bearer" || out["server_url"] != deviceBase || ws["name"] == "" || ws["name"] == nil {
		t.Fatalf("token answer: %v", out)
	}
	// One time: the same device code never gives a token again.
	allowPoll(t, e)
	if code, out := pollDevice(t, e, d); code != 400 || oauthErr(out) != "invalid_grant" {
		t.Errorf("replayed poll: %d %v", code, out)
	}

	// The token uploads, and does nothing else.
	if code := bearer(e, secret, "POST", "/api/v1/ingest", sampleBatch(), nil); code != 201 {
		t.Fatalf("ingest with the device token: %d", code)
	}
	for _, path := range []string{"/api/v1/assets", "/api/v1/auth/me", "/api/v1/tokens", "/api/v1/findings"} {
		if code := bearer(e, secret, "GET", path, nil, nil); code != 403 {
			t.Errorf("GET %s with the device token: %d, want 403", path, code)
		}
	}
	if code := bearer(e, secret, "POST", "/api/v1/tokens", []byte(`{"name":"x","role":"viewer"}`), nil); code != 403 {
		t.Errorf("token creating a token: %d", code)
	}
	if code := bearer(e, secret, "GET", "/api/v1/meta", nil, nil); code != 200 {
		t.Errorf("meta with the device token: %d", code)
	}
	// Its prefix is the real one now.
	eng.do("GET", "/api/v1/tokens", nil, &list)
	toks = list.Items
	if len(toks) != 1 || !strings.HasPrefix(secret, toks[0].Prefix) {
		t.Errorf("listed prefix %+v for %s…", toks, secret[:12])
	}

	// Audited, without the secret or the codes.
	var raw string
	if err := e.st.Pool.QueryRow(tenant.System(context.Background()), `SELECT string_agg(action || ' ' || detail::text, E'\n' ORDER BY id)
		FROM audit_events WHERE action IN ('device.approve', 'token.create', 'device.token_collected')`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"device.approve", "token.create", "device.token_collected", `"via": "device_login"`} {
		if !strings.Contains(raw, want) {
			t.Errorf("audit lacks %s:\n%s", want, raw)
		}
	}
	for _, secretish := range []string{secret, dc, uc, strings.ReplaceAll(uc, "-", "")} {
		if strings.Contains(raw, secretish) {
			t.Errorf("audit contains a secret: %s", raw)
		}
	}

	// Revoked in Settings: it stops at once.
	if code := eng.do("DELETE", "/api/v1/tokens/"+itoa(dec.Token.ID), nil, nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code := bearer(e, secret, "POST", "/api/v1/ingest", sampleBatch(), nil); code != 401 {
		t.Errorf("ingest after revoking: %d", code)
	}
}

func TestDeviceLoginTokenFollowsTheApproversRole(t *testing.T) {
	e := newDeviceEnv(t)
	e.user("eng@x.io", auth.RoleEngineer)
	eng := e.login("eng@x.io")
	d := startDevice(t, e, "")
	var pv struct{ Workspace struct{ ID int64 } }
	eng.do("POST", "/api/v1/device/preview", map[string]string{"user_code": d.UserCode}, &pv)
	if code := eng.do("POST", "/api/v1/device/decision", map[string]any{"user_code": d.UserCode, "decision": "approve", "workspace_id": pv.Workspace.ID}, nil); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	code, out := pollDevice(t, e, d)
	if code != 200 {
		t.Fatalf("poll: %d %v", code, out)
	}
	secret := out["access_token"].(string)
	if tok := out["token"].(map[string]any); tok["name"] != "stackurity-scan (signed in from a terminal)" {
		t.Errorf("token name without a host: %v", tok["name"])
	}
	if code := bearer(e, secret, "POST", "/api/v1/ingest", sampleBatch(), nil); code != 201 {
		t.Fatalf("ingest: %d", code)
	}
	// Made a viewer: the token can no longer upload.
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()), `UPDATE workspace_members SET role = 'viewer'
		WHERE user_id = (SELECT id FROM users WHERE email = 'eng@x.io')`); err != nil {
		t.Fatal(err)
	}
	if code := bearer(e, secret, "POST", "/api/v1/ingest", sampleBatch(), nil); code != 403 {
		t.Errorf("ingest after the approver became a viewer: %d", code)
	}
}

func TestDeviceLoginDenyAndExpiry(t *testing.T) {
	e := newDeviceEnv(t)
	e.user("eng@x.io", auth.RoleEngineer)
	e.user("viewer@x.io", auth.RoleViewer)
	eng := e.login("eng@x.io")
	ctx := tenant.System(context.Background())

	// A viewer sees why they cannot approve, and approving is refused; they
	// may still deny a request they did not start.
	d := startDevice(t, e, "ci-box")
	viewer := e.login("viewer@x.io")
	var pv struct {
		CanApprove    bool   `json:"can_approve"`
		CannotApprove string `json:"cannot_approve"`
		Workspace     struct{ ID int64 }
	}
	viewer.do("POST", "/api/v1/device/preview", map[string]string{"user_code": d.UserCode}, &pv)
	if pv.CanApprove || !strings.Contains(pv.CannotApprove, "Engineer") {
		t.Errorf("viewer preview: %+v", pv)
	}
	if code := viewer.do("POST", "/api/v1/device/decision", map[string]any{"user_code": d.UserCode, "decision": "approve", "workspace_id": pv.Workspace.ID}, nil); code != 403 {
		t.Errorf("viewer approve: %d", code)
	}
	if code := viewer.do("POST", "/api/v1/device/decision", map[string]any{"user_code": d.UserCode, "decision": "deny", "workspace_id": pv.Workspace.ID}, nil); code != 200 {
		t.Fatalf("deny: %d", code)
	}
	if code, out := pollDevice(t, e, d); code != 400 || oauthErr(out) != "access_denied" {
		t.Errorf("poll after deny: %d %v", code, out)
	}
	var n int
	if err := e.st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'device.deny'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("device.deny audited %d times: %v", n, err)
	}
	if code := eng.do("POST", "/api/v1/device/preview", map[string]string{"user_code": d.UserCode}, nil); code != 410 {
		t.Errorf("preview of a denied code: %d", code)
	}

	// Expired before anyone approved it.
	d2 := startDevice(t, e, "")
	if _, err := e.st.Pool.Exec(ctx, `UPDATE device_authorizations SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if code := eng.do("POST", "/api/v1/device/preview", map[string]string{"user_code": d2.UserCode}, nil); code != 410 {
		t.Errorf("preview of an expired code: %d", code)
	}
	if code, out := pollDevice(t, e, d2); code != 400 || oauthErr(out) != "expired_token" {
		t.Errorf("poll of an expired code: %d %v", code, out)
	}

	// Approved, then expired before the tool collected it: the token, whose
	// secret nobody ever saw, is revoked.
	d3 := startDevice(t, e, "")
	eng.do("POST", "/api/v1/device/preview", map[string]string{"user_code": d3.UserCode}, &pv)
	var dec struct{ Token struct{ ID int64 } }
	if code := eng.do("POST", "/api/v1/device/decision", map[string]any{"user_code": d3.UserCode, "decision": "approve", "workspace_id": pv.Workspace.ID}, &dec); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	if _, err := e.st.Pool.Exec(ctx, `UPDATE device_authorizations SET expires_at = now() - interval '1 second' WHERE token_id = $1`, dec.Token.ID); err != nil {
		t.Fatal(err)
	}
	if code, out := pollDevice(t, e, d3); code != 400 || oauthErr(out) != "expired_token" {
		t.Errorf("poll of an approved, expired code: %d %v", code, out)
	}
	var revoked bool
	if err := e.st.Pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM api_tokens WHERE id = $1`, dec.Token.ID).Scan(&revoked); err != nil || !revoked {
		t.Errorf("token of an expired approval not revoked: %v %v", revoked, err)
	}

	// Revoked in Settings before the tool collected it: access_denied.
	d4 := startDevice(t, e, "")
	eng.do("POST", "/api/v1/device/preview", map[string]string{"user_code": d4.UserCode}, &pv)
	eng.do("POST", "/api/v1/device/decision", map[string]any{"user_code": d4.UserCode, "decision": "approve", "workspace_id": pv.Workspace.ID}, &dec)
	if code := eng.do("DELETE", "/api/v1/tokens/"+itoa(dec.Token.ID), nil, nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code, out := pollDevice(t, e, d4); code != 400 || oauthErr(out) != "access_denied" {
		t.Errorf("poll after revoking before collection: %d %v", code, out)
	}
}

func TestDeviceLoginAdminProject(t *testing.T) {
	e := newDeviceEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	var proj struct{ ID int64 }
	if code := admin.do("POST", "/api/v1/projects", map[string]string{"name": "shop"}, &proj); code != 201 && code != 200 {
		t.Fatalf("create project: %d", code)
	}
	d := startDevice(t, e, "build-7")
	var pv struct {
		Workspace struct{ ID int64 }
		Projects  []struct{ ID int64 }
	}
	admin.do("POST", "/api/v1/device/preview", map[string]string{"user_code": d.UserCode}, &pv)
	if len(pv.Projects) != 1 || pv.Projects[0].ID != proj.ID {
		t.Fatalf("admin is offered projects %+v", pv.Projects)
	}
	if code := admin.do("POST", "/api/v1/device/decision", map[string]any{"user_code": d.UserCode, "decision": "approve", "workspace_id": pv.Workspace.ID,
		"project_id": proj.ID + 1000}, nil); code != 404 {
		t.Errorf("unknown project: %d", code)
	}
	if code := admin.do("POST", "/api/v1/device/decision", map[string]any{"user_code": d.UserCode, "decision": "approve", "workspace_id": pv.Workspace.ID,
		"project_id": proj.ID}, nil); code != 200 {
		t.Fatalf("approve with project: %d", code)
	}
	code, out := pollDevice(t, e, d)
	if code != 200 {
		t.Fatalf("poll: %d %v", code, out)
	}
	if p, _ := out["project"].(map[string]any); p == nil || p["name"] != "shop" {
		t.Errorf("project in the answer: %v", out["project"])
	}
	var res struct {
		AssetID   int64 `json:"asset_id"`
		InProject *bool `json:"in_project"`
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/ingest?project_id="+itoa(proj.ID), strings.NewReader(string(sampleBatch())))
	req.Header.Set("Authorization", "Bearer "+out["access_token"].(string))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if resp.StatusCode != 201 || res.InProject == nil || !*res.InProject {
		t.Errorf("upload into the token's project: %d %+v", resp.StatusCode, res)
	}
}

func TestDeviceLoginRequests(t *testing.T) {
	e := newDeviceEnv(t)
	for name, c := range map[string]struct {
		path string
		v    url.Values
		code int
		err  string
	}{
		"unknown client":   {"/api/v1/device/code", url.Values{"client_id": {"evil"}}, 401, "invalid_client"},
		"no client":        {"/api/v1/device/code", url.Values{}, 401, "invalid_client"},
		"bad host":         {"/api/v1/device/code", url.Values{"client_id": {"stackurity-scan"}, "host": {"<script>"}}, 400, "invalid_request"},
		"bad scope":        {"/api/v1/device/code", url.Values{"client_id": {"stackurity-scan"}, "scope": {"admin"}}, 400, "invalid_scope"},
		"wrong grant type": {"/api/v1/device/token", url.Values{"grant_type": {"password"}, "client_id": {"stackurity-scan"}, "device_code": {"x"}}, 400, "unsupported_grant_type"},
		"no device code":   {"/api/v1/device/token", url.Values{"grant_type": {api.DeviceGrantType}, "client_id": {"stackurity-scan"}}, 400, "invalid_request"},
		"unknown code":     {"/api/v1/device/token", url.Values{"grant_type": {api.DeviceGrantType}, "client_id": {"stackurity-scan"}, "device_code": {"stkd_nope"}}, 400, "invalid_grant"},
	} {
		code, out := devicePost(t, e, c.path, c.v, nil)
		if code != c.code || oauthErr(out) != c.err {
			t.Errorf("%s: %d %v, want %d %s", name, code, out, c.code, c.err)
		}
	}
	// JSON works as well as a form; the device code belongs to its client.
	var out map[string]any
	if code := e.anon().do("POST", "/api/v1/device/code", map[string]string{"client_id": "stackurity-scan"}, &out); code != 200 {
		t.Fatalf("JSON device code: %d %v", code, out)
	}
	code, got := devicePost(t, e, "/api/v1/device/token", url.Values{"grant_type": {api.DeviceGrantType}, "client_id": {"stackurity"},
		"device_code": {out["device_code"].(string)}}, nil)
	if code != 400 || oauthErr(got) != "invalid_grant" {
		t.Errorf("another client's device code: %d %v", code, got)
	}
	// Polling faster than the interval: slow_down, with a longer interval.
	d := deviceStart{DeviceCode: out["device_code"].(string)}
	pollDevice(t, e, d)
	if code, out := pollDevice(t, e, d); code != 400 || oauthErr(out) != "slow_down" || out["interval"] != float64(10) {
		t.Errorf("fast poll: %d %v", code, out)
	}

	// Off without a public address.
	off := newEnv(t)
	if code, _ := devicePost(t, off, "/api/v1/device/code", url.Values{"client_id": {"stackurity-scan"}}, nil); code != 404 {
		t.Errorf("device code without STACKURITY_BASE_URL: %d", code)
	}
	var meta struct{ Features []string }
	off.anon().do("GET", "/api/v1/meta", nil, &meta)
	if strings.Contains(strings.Join(meta.Features, ","), api.FeatureDeviceLogin) {
		t.Errorf("device_login offered without a base URL: %v", meta.Features)
	}
}

func TestDeviceLoginApprovalNeedsTheBrowser(t *testing.T) {
	e := newDeviceEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	d := startDevice(t, e, "")
	var pv struct{ Workspace struct{ ID int64 } }
	admin.do("POST", "/api/v1/device/preview", map[string]string{"user_code": d.UserCode}, &pv)
	body := `{"user_code":"` + d.UserCode + `","decision":"approve","workspace_id":` + itoa(pv.Workspace.ID) + `}`

	// No CSRF header: refused before the handler.
	resp := admin.req("POST", "/api/v1/device/decision", strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("without X-Stackurity-CSRF: %d", resp.StatusCode)
	}
	// From another site.
	resp = admin.req("POST", "/api/v1/device/decision", strings.NewReader(body), map[string]string{"Content-Type": "application/json",
		"X-Stackurity-CSRF": "1", "Sec-Fetch-Site": "cross-site"})
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("cross-site: %d", resp.StatusCode)
	}
	// With an API token, even an admin's: refused.
	var tok struct{ Secret string }
	if code := admin.do("POST", "/api/v1/tokens", map[string]string{"name": "t", "role": "admin"}, &tok); code != 201 {
		t.Fatalf("token: %d", code)
	}
	if code := bearer(e, tok.Secret, "POST", "/api/v1/device/decision", []byte(body), map[string]string{"Content-Type": "application/json"}); code != 403 {
		t.Errorf("decision with an API token: %d", code)
	}
	// Still pending: the tool waits.
	if code, out := pollDevice(t, e, d); code != 400 || oauthErr(out) != "authorization_pending" {
		t.Errorf("poll: %d %v", code, out)
	}
}

func TestDeviceLoginRateLimits(t *testing.T) {
	e := newDeviceEnv(t)
	e.user("eng@x.io", auth.RoleEngineer)
	eng := e.login("eng@x.io")
	// Guessing codes on the page: refused after 20 tries in 15 minutes.
	last := 0
	for i := 0; i < 21; i++ {
		last = eng.do("POST", "/api/v1/device/preview", map[string]string{"user_code": "BCDF-GHJK"}, nil)
	}
	if last != 429 {
		t.Errorf("21st code tried: %d, want 429", last)
	}
	// New requests: ten a minute per address.
	for i := 0; i < 10; i++ {
		if code, out := devicePost(t, e, "/api/v1/device/code", url.Values{"client_id": {"stackurity-scan"}}, nil); code != 200 {
			t.Fatalf("request %d: %d %v", i, code, out)
		}
	}
	if code, _ := devicePost(t, e, "/api/v1/device/code", url.Values{"client_id": {"stackurity-scan"}}, nil); code != 429 {
		t.Errorf("11th request in a minute: %d", code)
	}
}
