package api_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/tenant"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/health"
	"github.com/stackurity/stackurity/internal/intel"
	"github.com/stackurity/stackurity/internal/metrics"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/testdb"
)

const pw = "correct horse battery"

type env struct {
	t   *testing.T
	srv *httptest.Server
	st  *store.Store
	api *api.Server
}

func newEnv(t *testing.T) *env { return newEnvWith(t, nil) }

// newEnvWith is newEnv with the server adjusted before it starts.
func newEnvWith(t *testing.T, adjust func(*api.Server)) *env {
	st := store.New(testdb.New(t))
	// Tests run licensed (Enterprise) unless they say otherwise.
	holder := &license.Holder{}
	holder.Set(&license.License{Version: 1, Customer: "test", Edition: license.Enterprise, ExpiresAt: time.Now().AddDate(1, 0, 0)})
	gate := &license.Gate{Licence: holder, Plan: license.CachedPlan(st.WorkspacePlan, 0)}
	s := &api.Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test", SetupToken: "setup-123",
		Licence: holder, Gate: gate, Health: &health.Checker{Store: st, FeedsEnabled: true}, HTTPMetrics: metrics.NewHTTP(),
		CoverageGaps: func(ctx context.Context) (any, error) { return intel.CoverageGaps(ctx, st, nil) }}
	if adjust != nil {
		adjust(s)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, st: st, api: s}
}

// session is a cookie-authenticated browser-like client.
type session struct {
	e    *env
	http *http.Client
	// hdr is sent with every request (such as CF-Connecting-IP).
	hdr map[string]string
}

func (e *env) anon() *session {
	jar, _ := cookiejar.New(nil)
	return &session{e: e, http: &http.Client{Jar: jar}}
}

func (e *env) login(email string) *session {
	s := e.anon()
	if code := s.do("POST", "/api/v1/auth/login", map[string]string{"email": email, "password": pw}, nil); code != 200 {
		e.t.Fatalf("login %s: %d", email, code)
	}
	return s
}

func (e *env) user(email string, role auth.Role) {
	if _, err := e.st.CreateUser(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), email, "", role, pw); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) instanceAdmin(email string) {
	if ok, err := e.st.UpdateUserInstanceAdmin(context.Background(), email, true); err != nil || !ok {
		e.t.Fatalf("instance admin %s: %v", email, err)
	}
}

func (s *session) req(method, path string, body io.Reader, hdr map[string]string) *http.Response {
	req, _ := http.NewRequest(method, s.e.srv.URL+path, body)
	for k, v := range s.hdr {
		req.Header.Set(k, v)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		s.e.t.Fatal(err)
	}
	return resp
}

// do sends JSON with the CSRF header and decodes the response into out.
func (s *session) do(method, path string, in, out any) int {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	resp := s.req(method, path, body, map[string]string{"X-Stackurity-CSRF": "1", "Content-Type": "application/json"})
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func bearer(e *env, token, method, path string, body []byte, hdr map[string]string) int {
	req, _ := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func sampleBatch() []byte {
	b := model.NewBatch(model.Collector{ID: "t", Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: "h", Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "x"}}})
	b.Observations = []model.Observation{{Purl: "pkg:deb/debian/bash@5.2", Confidence: model.ConfidenceConfirmed}}
	out, _ := json.Marshal(b)
	return out
}

func TestSetup(t *testing.T) {
	e := newEnv(t)
	a := e.anon()
	var meta map[string]any
	a.do("GET", "/api/v1/meta", nil, &meta)
	if meta["setup_required"] != true {
		t.Fatalf("meta = %v", meta)
	}
	if code := a.do("POST", "/api/v1/setup", map[string]string{"setup_token": "wrong", "email": "a@x.io", "password": pw}, nil); code != 403 {
		t.Errorf("wrong setup token: %d", code)
	}
	if code := a.do("POST", "/api/v1/setup", map[string]string{"setup_token": "setup-123", "email": "a@x.io", "password": "short"}, nil); code != 400 {
		t.Errorf("short password: %d", code)
	}
	if code := a.do("POST", "/api/v1/setup", map[string]string{"setup_token": "setup-123", "email": "a@x.io", "password": pw}, nil); code != 200 {
		t.Fatalf("setup: %d", code)
	}
	if code := a.do("GET", "/api/v1/overview", nil, nil); code != 200 {
		t.Errorf("setup should sign the admin in: %d", code)
	}
	if code := e.anon().do("POST", "/api/v1/setup", map[string]string{"setup_token": "setup-123", "email": "b@x.io", "password": pw}, nil); code != 409 {
		t.Errorf("second setup: %d", code)
	}
}

func TestCSRFAndAuth(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	s := e.login("admin@x.io")
	resp := s.req("POST", "/api/v1/teams", bytes.NewReader([]byte(`{"name":"a"}`)), map[string]string{"Content-Type": "application/json"})
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("cookie POST without CSRF header: %d", resp.StatusCode)
	}
	if code := e.anon().do("GET", "/api/v1/assets", nil, nil); code != 401 {
		t.Errorf("anonymous read: %d", code)
	}
	if code := bearer(e, "stk_bogus", "GET", "/api/v1/assets", nil, nil); code != 401 {
		t.Errorf("bogus token: %d", code)
	}
	if code := e.anon().do("POST", "/api/v1/auth/login", map[string]string{"email": "admin@x.io", "password": "wrong password!"}, nil); code != 401 {
		t.Errorf("bad password: %d", code)
	}
}

func TestRoles(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	e.user("view@x.io", auth.RoleViewer)
	admin, eng, view := e.login("admin@x.io"), e.login("eng@x.io"), e.login("view@x.io")

	// Collector token: may ingest, may not read.
	var tok struct {
		Secret string `json:"secret"`
	}
	if code := admin.do("POST", "/api/v1/tokens", map[string]string{"name": "agent", "role": "collector"}, &tok); code != 201 {
		t.Fatalf("create collector token: %d", code)
	}
	if code := bearer(e, tok.Secret, "POST", "/api/v1/ingest", sampleBatch(), nil); code != 201 {
		t.Errorf("collector ingest: %d", code)
	}
	if code := bearer(e, tok.Secret, "GET", "/api/v1/assets", nil, nil); code != 403 {
		t.Errorf("collector read: %d", code)
	}
	if code := bearer(e, tok.Secret, "POST", "/api/v1/tokens", []byte(`{"name":"x","role":"collector"}`), nil); code != 403 {
		t.Errorf("collector minting tokens: %d", code)
	}

	// Gzip ingest.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(sampleBatch())
	_ = zw.Close()
	if code := bearer(e, tok.Secret, "POST", "/api/v1/ingest", gz.Bytes(), map[string]string{"Content-Encoding": "gzip"}); code != 201 {
		t.Errorf("gzip ingest: %d", code)
	}
	// Invalid batches are rejected with details.
	if code := bearer(e, tok.Secret, "POST", "/api/v1/ingest", []byte(`{"schema_version":"1","observations":[{"purl":"nope"}]}`), nil); code != 400 {
		t.Errorf("invalid batch: %d", code)
	}

	if code := view.do("PATCH", "/api/v1/assets/1", map[string]string{"environment": "prod"}, nil); code != 403 {
		t.Errorf("viewer edit: %d", code)
	}
	if code := eng.do("PATCH", "/api/v1/assets/1", map[string]string{"environment": "prod"}, nil); code != 200 {
		t.Errorf("engineer edit: %d", code)
	}
	if code := eng.do("DELETE", "/api/v1/assets/1", nil, nil); code != 403 {
		t.Errorf("engineer delete: %d", code)
	}
	if code := eng.do("POST", "/api/v1/tokens", map[string]string{"name": "x", "role": "admin"}, nil); code != 403 {
		t.Errorf("engineer minting admin token: %d", code)
	}
	if code := eng.do("POST", "/api/v1/tokens", map[string]string{"name": "x", "role": "collector"}, nil); code != 403 {
		t.Errorf("engineer minting collector token: %d", code)
	}
	var et struct {
		Secret string `json:"secret"`
	}
	if code := eng.do("POST", "/api/v1/tokens", map[string]string{"name": "ci", "role": "engineer"}, &et); code != 201 {
		t.Fatalf("engineer personal token: %d", code)
	}
	if code := bearer(e, et.Secret, "GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Errorf("engineer token read: %d", code)
	}

	// Demoting the engineer caps their existing token at the new role.
	var users struct {
		Items []store.User `json:"items"`
	}
	admin.do("GET", "/api/v1/users", nil, &users)
	var engID, adminID int64
	for _, u := range users.Items {
		switch u.Email {
		case "eng@x.io":
			engID = u.ID
		case "admin@x.io":
			adminID = u.ID
		}
	}
	if code := admin.do("PATCH", "/api/v1/users/"+itoa(engID), map[string]string{"role": "viewer"}, nil); code != 200 {
		t.Fatalf("demote: %d", code)
	}
	if code := bearer(e, et.Secret, "PATCH", "/api/v1/assets/1", []byte(`{"environment":"x"}`), nil); code != 403 {
		t.Errorf("token above user's new role: %d", code)
	}
	// A role change applies to the open session at once.
	if code := eng.do("GET", "/api/v1/overview", nil, nil); code != 200 {
		t.Errorf("session after role change: %d", code)
	}
	if code := eng.do("PATCH", "/api/v1/assets/1", map[string]string{"environment": "x"}, nil); code != 403 {
		t.Errorf("demoted session still has engineer rights: %d", code)
	}
	// The last admin cannot be demoted or disabled.
	if code := admin.do("PATCH", "/api/v1/users/"+itoa(adminID), map[string]bool{"disabled": true}, nil); code != 409 {
		t.Errorf("disable last admin: %d", code)
	}

	// Audit trail records these actions.
	var audit struct {
		Items []store.AuditEvent `json:"items"`
	}
	admin.do("GET", "/api/v1/audit", nil, &audit)
	seen := map[string]bool{}
	for _, a := range audit.Items {
		seen[a.Action] = true
	}
	for _, want := range []string{"token.create", "asset.update", "user.update", "auth.login"} {
		if !seen[want] {
			t.Errorf("audit missing %s: %v", want, seen)
		}
	}
}

func TestIntegrationValidation(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.instanceAdmin("admin@x.io") // these cases use server (env:) secrets
	admin := e.login("admin@x.io")
	bad := []map[string]any{
		{"kind": "git_repository", "config": map[string]string{"url": "http://github.com/a/b"}},
		{"kind": "git_repository", "config": map[string]string{"url": "https://u:p@github.com/a/b"}},
		{"kind": "git_repository", "config": map[string]string{"url": "https://github.com/a/b"}, "secret_ref": "env:STACKURITY_DATABASE_URL"},
		{"kind": "git_repository", "config": map[string]string{"url": "https://github.com/a/b"}, "schedule_minutes": 1},
		{"kind": "shell", "config": map[string]string{}},
	}
	for i, b := range bad {
		if code := admin.do("POST", "/api/v1/integrations", b, nil); code != 400 {
			t.Errorf("case %d accepted: %d", i, code)
		}
	}
	var in store.Integration
	ok := map[string]any{"kind": "git_repository", "config": map[string]string{"url": "https://github.com/a/b"}, "secret_ref": "env:STACKURITY_SECRET_GH", "schedule_minutes": 60}
	if code := admin.do("POST", "/api/v1/integrations", ok, &in); code != 201 || in.ScheduleMin != 60 || in.Name != "a/b" {
		t.Errorf("valid integration: %d %+v", code, in)
	}
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

func TestAssetFieldClearing(t *testing.T) {
	e := newEnv(t)
	e.user("eng@x.io", auth.RoleEngineer)
	eng := e.login("eng@x.io")
	if code := bearerIngest(e); code != 201 {
		t.Fatalf("seed ingest: %d", code)
	}
	var got struct {
		Asset store.Asset `json:"asset"`
	}
	eng.do("PATCH", "/api/v1/assets/1", map[string]any{"internet_exposed": true}, &got)
	if got.Asset.InternetExposed == nil || !*got.Asset.InternetExposed {
		t.Fatalf("set exposed: %+v", got.Asset)
	}
	eng.do("PATCH", "/api/v1/assets/1", map[string]any{"environment": "prod"}, &got)
	if got.Asset.InternetExposed == nil {
		t.Error("absent field must not change the value")
	}
	eng.do("PATCH", "/api/v1/assets/1", map[string]any{"internet_exposed": nil}, &got)
	if got.Asset.InternetExposed != nil {
		t.Errorf("null must reset to unknown: %+v", got.Asset)
	}
}

func bearerIngest(e *env) int {
	tok, secret, err := e.st.CreateToken(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), "c", auth.RoleCollector, nil, 0, 0)
	if err != nil || tok == nil {
		e.t.Fatal(err)
	}
	return bearer(e, secret, "POST", "/api/v1/ingest", sampleBatch(), nil)
}

func TestUIFallback(t *testing.T) {
	st := store.New(testdb.New(t))
	ui := fstest.MapFS{"index.html": {Data: []byte("<html>app</html>")}, "static/app.js": {Data: []byte("js")}, "assets/x": {Data: []byte("dir")}}
	s := &api.Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), UI: ui}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	for path, want := range map[string]string{"/": "app", "/assets": "app", "/assets/12": "app", "/static/app.js": "js", "/settings/tokens": "app"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("%s served %q", path, b)
		}
	}
}

func TestIntelEndpoints(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	e.user("view@x.io", auth.RoleViewer)
	admin, eng, view := e.login("admin@x.io"), e.login("eng@x.io"), e.login("view@x.io")
	if err := e.st.EnsureFeed(ctx, "osv:npm", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	var feeds struct {
		Items []store.Feed `json:"items"`
	}
	if code := view.do("GET", "/api/v1/feeds", nil, &feeds); code != 200 || len(feeds.Items) != 1 || !feeds.Items[0].Stale {
		t.Errorf("feeds: %d %+v", code, feeds)
	}
	if code := view.do("POST", "/api/v1/feeds/osv:npm/refresh", nil, nil); code != 403 {
		t.Errorf("viewer refresh: %d", code)
	}
	if code := eng.do("POST", "/api/v1/feeds/osv:npm/refresh", nil, nil); code != 202 {
		t.Errorf("engineer refresh: %d", code)
	}
	if code := eng.do("POST", "/api/v1/feeds/nope/refresh", nil, nil); code != 404 {
		t.Errorf("unknown feed: %d", code)
	}
	if code := eng.do("PATCH", "/api/v1/feeds/osv:npm", map[string]bool{"enabled": false}, nil); code != 403 {
		t.Errorf("engineer disable feed: %d", code)
	}
	// Feeds are shared by every workspace: a workspace admin cannot switch
	// one off for all of them, an instance admin can.
	if code := admin.do("PATCH", "/api/v1/feeds/osv:npm", map[string]bool{"enabled": false}, nil); code != 403 {
		t.Errorf("workspace admin disabled a shared feed: %d", code)
	}
	e.instanceAdmin("admin@x.io")
	if code := admin.do("PATCH", "/api/v1/feeds/osv:npm", map[string]bool{"enabled": false}, nil); code != 200 {
		t.Errorf("instance admin disable feed: %d", code)
	}
	var sum store.FindingSummary
	if code := view.do("GET", "/api/v1/findings/summary", nil, &sum); code != 200 {
		t.Errorf("summary: %d", code)
	}
	if code := view.do("GET", "/api/v1/findings?status=bogus", nil, nil); code != 400 {
		t.Errorf("bad status: %d", code)
	}
	if code := view.do("GET", "/api/v1/findings?severity=critical,high", nil, nil); code != 200 {
		t.Errorf("findings: %d", code)
	}
	if code := eng.do("POST", "/api/v1/evaluate", nil, nil); code != 202 {
		t.Errorf("evaluate: %d", code)
	}
	// Image integrations validate the reference strictly.
	for _, img := range []string{"dir:/etc", "nginx latest", "--help"} {
		if code := admin.do("POST", "/api/v1/integrations", map[string]any{"kind": "container_image", "config": map[string]string{"image": img}}, nil); code != 400 {
			t.Errorf("image %q accepted: %d", img, code)
		}
	}
	var in store.Integration
	if code := admin.do("POST", "/api/v1/integrations", map[string]any{"kind": "container_image", "config": map[string]string{"image": "ghcr.io/acme/shop:1.4", "platform": "linux/amd64"}}, &in); code != 201 || in.Name != "ghcr.io/acme/shop:1.4" {
		t.Errorf("image integration: %d %+v", code, in)
	}
}

func TestWorkflowRoles(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("eng@x.io", auth.RoleEngineer)
	e.user("sec@x.io", auth.RoleSecurity)
	e.user("view@x.io", auth.RoleViewer)
	e.user("admin@x.io", auth.RoleAdmin)
	eng, sec, view, admin := e.login("eng@x.io"), e.login("sec@x.io"), e.login("view@x.io"), e.login("admin@x.io")
	if code := bearerIngest(e); code != 201 {
		t.Fatal(code)
	}
	rows, _, _ := e.st.ListInventory(ctx, store.InventoryFilter{})
	if _, _, err := e.st.SyncFindings(ctx, []string{"vulnerability"}, []int64{rows[0].ID}, []store.FindingInput{{
		Kind: "vulnerability", Key: "CVE-1", InventoryID: rows[0].ID, AssetID: rows[0].AssetID, ComponentID: rows[0].ComponentID,
		Verification: "confirmed", Severity: "high", Sources: []string{"X"}, Evidence: map[string]any{}}}); err != nil {
		t.Fatal(err)
	}
	fs, _, _ := e.st.ListFindings(ctx, store.FindingFilter{})
	path := "/api/v1/findings/" + itoa(fs[0].ID) + "/actions"
	until := time.Now().Add(30 * 24 * time.Hour)

	if code := view.do("POST", path, map[string]any{"action": "acknowledge"}, nil); code != 403 {
		t.Errorf("viewer acknowledge: %d", code)
	}
	if code := eng.do("POST", path, map[string]any{"action": "acknowledge", "note": "looking"}, nil); code != 200 {
		t.Errorf("engineer acknowledge: %d", code)
	}
	if code := eng.do("POST", path, map[string]any{"action": "accept_risk", "note": "x", "until": until}, nil); code != 403 {
		t.Errorf("engineer accept_risk: %d", code)
	}
	if code := sec.do("POST", path, map[string]any{"action": "accept_risk", "until": until}, nil); code != 400 {
		t.Errorf("accept_risk without reason: %d", code)
	}
	if code := sec.do("POST", path, map[string]any{"action": "accept_risk", "note": "compensating control", "until": time.Now().AddDate(2, 0, 0)}, nil); code != 400 {
		t.Errorf("accept_risk beyond a year: %d", code)
	}
	if code := sec.do("POST", path, map[string]any{"action": "accept_risk", "note": "compensating control: WAF rule 12", "until": until}, nil); code != 200 {
		t.Errorf("security accept_risk: %d", code)
	}
	var evs struct {
		Items []store.FindingEvent `json:"items"`
	}
	view.do("GET", "/api/v1/findings/"+itoa(fs[0].ID)+"/events", nil, &evs)
	if len(evs.Items) != 2 || evs.Items[1].ToState != "risk_accepted" || evs.Items[1].Note == "" {
		t.Errorf("events = %+v", evs.Items)
	}
	if code := eng.do("POST", "/api/v1/findings/actions", map[string]any{"action": "acknowledge", "ids": []int64{}}, nil); code != 400 {
		t.Errorf("empty bulk: %d", code)
	}

	// Channels: admin only, secrets referenced, URLs validated.
	if code := sec.do("POST", "/api/v1/channels", map[string]any{"kind": "webhook", "name": "h", "config": map[string]string{"url": "https://h.example/x"}}, nil); code != 403 {
		t.Errorf("security creating channel: %d", code)
	}
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "slack", "name": "s", "config": map[string]string{}}, nil); code != 400 {
		t.Errorf("slack without secret: %d", code)
	}
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "webhook", "name": "h", "config": map[string]string{"url": "http://h.example/x"}}, nil); code != 400 {
		t.Errorf("http webhook accepted: %d", code)
	}
	var ch store.Channel
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "webhook", "name": "h", "config": map[string]string{"url": "https://h.example/x"}}, &ch); code != 201 {
		t.Fatalf("create webhook: %d", code)
	}
	if code := admin.do("POST", "/api/v1/routes", map[string]any{"name": "r", "channel_id": ch.ID, "enabled": true, "min_priority": "P0"}, nil); code != 400 {
		t.Errorf("bad priority: %d", code)
	}
	if code := admin.do("POST", "/api/v1/routes", map[string]any{"name": "r", "channel_id": ch.ID, "enabled": true, "quiet_start": "22:00"}, nil); code != 400 {
		t.Errorf("half quiet window: %d", code)
	}
	if code := admin.do("POST", "/api/v1/routes", map[string]any{"name": "r", "channel_id": ch.ID, "enabled": true, "min_priority": "P1",
		"quiet_start": "22:00", "quiet_end": "07:00", "timezone": "Europe/London"}, nil); code != 201 {
		t.Errorf("valid route: %d", code)
	}
	var uo store.Route
	if code := admin.do("POST", "/api/v1/routes", map[string]any{"name": "on-call", "channel_id": ch.ID, "enabled": true, "mode": "urgent_only"}, &uo); code != 201 || uo.Mode != store.ModeUrgentOnly {
		t.Errorf("urgent_only route: %d %+v", code, uo)
	}
	if code := admin.do("POST", "/api/v1/routes", map[string]any{"name": "r2", "channel_id": ch.ID, "enabled": true, "mode": "hourly"}, nil); code != 400 {
		t.Errorf("unknown mode: %d", code)
	}
	if code := sec.do("GET", "/api/v1/deliveries", nil, nil); code != 200 {
		t.Errorf("security deliveries: %d", code)
	}
	if code := eng.do("GET", "/api/v1/deliveries", nil, nil); code != 403 {
		t.Errorf("engineer deliveries: %d", code)
	}

	// Risk policy: severity-only SOS rules are rejected.
	var pol struct {
		Policy map[string]any `json:"policy"`
	}
	view.do("GET", "/api/v1/risk-policy", nil, &pol)
	pol.Policy["sos_rules"] = []map[string]any{{"name": "all critical", "min_severity": "critical"}}
	if code := admin.do("PUT", "/api/v1/risk-policy", pol.Policy, nil); code != 400 {
		t.Errorf("severity-only SOS accepted: %d", code)
	}

	// A saved rule is stored as written: it does not pick up conditions from
	// the default rule it replaces, and the response names what changed.
	pol.Policy["sos_rules"] = []map[string]any{{"name": "KEV anywhere", "known_exploited": true}}
	var put struct {
		Version         string   `json:"version"`
		PreviousVersion string   `json:"previous_version"`
		Changed         []string `json:"changed"`
	}
	if code := admin.do("PUT", "/api/v1/risk-policy", pol.Policy, &put); code != 200 || strings.Join(put.Changed, ",") != "sos_rules" ||
		put.PreviousVersion != risk.DefaultPolicy().Version() {
		t.Errorf("save rule: %d %+v", code, put)
	}
	var back struct {
		Policy  risk.Policy `json:"policy"`
		Version string      `json:"version"`
	}
	view.do("GET", "/api/v1/risk-policy", nil, &back)
	if len(back.Policy.SOS) != 1 || back.Policy.SOS[0].Production != nil || back.Version != put.Version {
		t.Errorf("rule read back as %+v (version %s, saved %s)", back.Policy.SOS, back.Version, put.Version)
	}
	if code := admin.do("PUT", "/api/v1/risk-policy", map[string]any{"known_exploited": 3, "no_such_field": 1}, nil); code != 400 {
		t.Errorf("unknown policy field accepted: %d", code)
	}
}

func TestFindingFilters(t *testing.T) {
	e := newEnv(t)
	e.user("view@x.io", auth.RoleViewer)
	view := e.login("view@x.io")
	for _, q := range []string{"priority=P1,P2", "state=active", "sos=true&overdue=true", "assignee_user=1&assignee_team=2&incident_id=3"} {
		if code := view.do("GET", "/api/v1/findings?"+q, nil, nil); code != 200 {
			t.Errorf("%s: %d", q, code)
		}
	}
	if code := view.do("GET", "/api/v1/findings?state=bogus", nil, nil); code != 400 {
		t.Errorf("bad state: %d", code)
	}
}

func TestChannelSecretClearAndDirectory(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.instanceAdmin("admin@x.io") // these cases use server (env:) secrets
	e.user("eng@x.io", auth.RoleEngineer)
	admin, eng := e.login("admin@x.io"), e.login("eng@x.io")
	var ch store.Channel
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "webhook", "name": "h", "config": map[string]string{"url": "https://h.example/x"},
		"secret_ref": "env:STACKURITY_SECRET_H"}, &ch); code != 201 {
		t.Fatalf("create: %d", code)
	}
	if code := admin.do("PATCH", "/api/v1/channels/"+itoa(ch.ID), map[string]any{"secret_ref": ""}, &ch); code != 200 || ch.SecretRef != "" {
		t.Errorf("clearing secret_ref: %d %q", code, ch.SecretRef)
	}
	var dir struct {
		Items []map[string]any `json:"items"`
	}
	if code := eng.do("GET", "/api/v1/users/directory", nil, &dir); code != 200 || len(dir.Items) != 2 {
		t.Errorf("directory: %d %+v", code, dir)
	}
	for _, u := range dir.Items {
		if _, leak := u["role"]; leak {
			t.Error("directory must not expose roles")
		}
	}
	if code := eng.do("GET", "/api/v1/findings?assignee=none", nil, nil); code != 200 {
		t.Errorf("unassigned filter: %d", code)
	}
	if code := eng.do("GET", "/api/v1/incidents?escalated=true", nil, nil); code != 200 {
		t.Errorf("escalated filter: %d", code)
	}
}

func TestJiraChannelAPI(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.instanceAdmin("admin@x.io")
	admin := e.login("admin@x.io")
	cfg := map[string]any{"url": "https://acme.atlassian.net", "username": "bot@acme.io", "project": "SEC",
		"labels": []string{"security"}, "priorities": map[string]string{"P1": "Highest"}, "resolve_transition": "Done"}
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "jira", "name": "j", "config": cfg}, nil); code != 400 {
		t.Errorf("jira without a token: %d", code)
	}
	var ch store.Channel
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "jira", "name": "j", "config": cfg,
		"secret_ref": "env:STACKURITY_SECRET_JIRA"}, &ch); code != 201 || ch.Kind != "jira" || !strings.Contains(string(ch.Config), `"project":"SEC"`) {
		t.Fatalf("create: %d %+v", code, ch)
	}
	if code := admin.do("PATCH", "/api/v1/channels/"+itoa(ch.ID), map[string]any{"secret_ref": ""}, nil); code != 400 {
		t.Errorf("removing the jira token: %d", code)
	}
	for _, bad := range []map[string]any{
		{"url": "https://acme.atlassian.net", "project": "SEC"}, // cloud needs the account email
		{"url": "https://acme.atlassian.net", "username": "bot@acme.io", "project": "SEC", "priorities": map[string]string{"P9": "x"}},
		{"url": "https://acme.atlassian.net", "username": "bot@acme.io", "project": "SEC", "token": "inline"},
	} {
		if code := admin.do("PATCH", "/api/v1/channels/"+itoa(ch.ID), map[string]any{"config": bad}, nil); code != 400 {
			t.Errorf("invalid config %v: %d", bad, code)
		}
	}
}

func TestChangeOwnPassword(t *testing.T) {
	e := newEnv(t)
	e.user("u@x.io", auth.RoleViewer)
	a, b := e.login("u@x.io"), e.login("u@x.io")
	if code := a.do("POST", "/api/v1/auth/password", map[string]string{"current_password": "wrong one entirely", "new_password": "another long passphrase"}, nil); code != 400 {
		t.Errorf("wrong current password: %d", code)
	}
	if code := a.do("POST", "/api/v1/auth/password", map[string]string{"current_password": pw, "new_password": "short"}, nil); code != 400 {
		t.Errorf("weak new password: %d", code)
	}
	if code := a.do("POST", "/api/v1/auth/password", map[string]string{"current_password": pw, "new_password": "another long passphrase"}, nil); code != 204 {
		t.Fatalf("change: %d", code)
	}
	if code := a.do("GET", "/api/v1/auth/me", nil, nil); code != 200 {
		t.Errorf("current session should survive: %d", code)
	}
	if code := b.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("other sessions must end: %d", code)
	}
	if code := e.anon().do("POST", "/api/v1/auth/login", map[string]string{"email": "u@x.io", "password": "another long passphrase"}, nil); code != 200 {
		t.Errorf("login with new password: %d", code)
	}
}

// Review findings 3 and 5: host-bound tokens.
func TestBoundTokenLimits(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	host := func(ids ...model.Identifier) []byte {
		b := model.NewBatch(model.Collector{ID: "linux-agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "h", Identifiers: ids})
		b.Observations = []model.Observation{{Purl: "pkg:deb/debian/bash@5.2?distro=debian-12", Confidence: model.ConfidenceConfirmed}}
		out, _ := json.Marshal(b)
		return out
	}
	_, collector, _ := e.st.CreateToken(ctx, "c", auth.RoleCollector, nil, 0, 0)
	if code := bearer(e, collector, "POST", "/api/v1/ingest", host(model.Identifier{Scheme: "machine-id", Value: "a"}), nil); code != 201 {
		t.Fatal(code)
	}
	_, boundSecret, err := e.st.CreateAssetToken(ctx, 1, "host", 0)
	if err != nil {
		t.Fatal(err)
	}
	tok := struct{ Secret string }{boundSecret}

	// Claiming a new hostname is ignored: the real db-7 later gets its own asset.
	if code := bearer(e, tok.Secret, "POST", "/api/v1/ingest",
		host(model.Identifier{Scheme: "machine-id", Value: "a"}, model.Identifier{Scheme: "hostname", Value: "db-7"}), nil); code != 201 {
		t.Fatalf("own ingest: %d", code)
	}
	var res struct {
		AssetID  int64 `json:"asset_id"`
		NewAsset bool  `json:"new_asset"`
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/ingest", bytes.NewReader(host(model.Identifier{Scheme: "machine-id", Value: "m7"}, model.Identifier{Scheme: "hostname", Value: "db-7"})))
	req.Header.Set("Authorization", "Bearer "+collector)
	resp, _ := http.DefaultClient.Do(req)
	_ = json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if res.AssetID == 1 || !res.NewAsset {
		t.Errorf("db-7 was absorbed into the bound host: %+v", res)
	}

	// SBOM import is held to the same rule.
	sb := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`)
	if code := bearer(e, tok.Secret, "POST", "/api/v1/sbom/import?asset_name=shop", sb, nil); code != 403 {
		t.Errorf("bound token imported an SBOM for another asset: %d", code)
	}
}

// A CI job reads back the evaluation of its own scan, and only its own.
func TestCollectionResult(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("view@x.io", auth.RoleViewer)
	view := e.login("view@x.io")
	_, ci, _ := e.st.CreateToken(ctx, "ci", auth.RoleCollector, nil, 0, 0)
	_, other, _ := e.st.CreateToken(ctx, "other", auth.RoleCollector, nil, 0, 0)

	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/ingest", bytes.NewReader(sampleBatch()))
	req.Header.Set("Authorization", "Bearer "+ci)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ing store.IngestResult
	_ = json.NewDecoder(resp.Body).Decode(&ing)
	resp.Body.Close()
	path := "/api/v1/collections/" + itoa(ing.CollectionID) + "/result"

	read := func(token string) (int, store.CollectionResult) {
		req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var res store.CollectionResult
		_ = json.NewDecoder(resp.Body).Decode(&res)
		return resp.StatusCode, res
	}
	if code, res := read(ci); code != 200 || res.Status != "pending" {
		t.Fatalf("before evaluation: %d %+v", code, res)
	}
	if code, _ := read(other); code != 404 {
		t.Errorf("another collector token read the result: %d", code)
	}

	// An evaluation that started before the batch arrived does not count.
	if err := e.st.MarkEvaluated(ctx, ing.AssetID, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool.Exec(ctx, `UPDATE jobs SET done_at = now()`); err != nil {
		t.Fatal(err)
	}
	if _, res := read(ci); res.Status != "pending" {
		t.Errorf("stale evaluation accepted: %+v", res)
	}
	start, _ := e.st.DBNow(ctx)
	if err := e.st.MarkEvaluated(ctx, ing.AssetID, start); err != nil {
		t.Fatal(err)
	}
	if code, res := read(ci); code != 200 || res.Status != "evaluated" || res.AssetID != ing.AssetID {
		t.Errorf("after evaluation: %d %+v", code, res)
	}
	var res store.CollectionResult
	if code := view.do("GET", path, nil, &res); code != 403 {
		// Viewers cannot ingest, so the ingest-only route refuses them.
		t.Errorf("viewer: %d", code)
	}
}

// The longest exception comes from the risk policy, and a mitigation is
// stored with it.
func TestExceptionPolicyAndMitigation(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("sec@x.io", auth.RoleSecurity)
	e.user("admin@x.io", auth.RoleAdmin)
	sec, admin := e.login("sec@x.io"), e.login("admin@x.io")
	if code := bearerIngest(e); code != 201 {
		t.Fatal(code)
	}
	rows, _, _ := e.st.ListInventory(ctx, store.InventoryFilter{})
	if _, _, err := e.st.SyncFindings(ctx, []string{"vulnerability"}, []int64{rows[0].ID}, []store.FindingInput{{
		Kind: "vulnerability", Key: "CVE-1", InventoryID: rows[0].ID, AssetID: rows[0].AssetID, ComponentID: rows[0].ComponentID,
		Verification: "confirmed", Severity: "high", Sources: []string{"X"}, Evidence: map[string]any{}}}); err != nil {
		t.Fatal(err)
	}
	fs, _, _ := e.st.ListFindings(ctx, store.FindingFilter{})
	path := "/api/v1/findings/" + itoa(fs[0].ID) + "/actions"

	var got struct {
		Policy map[string]any `json:"policy"`
	}
	admin.do("GET", "/api/v1/risk-policy", nil, &got)
	pol := got.Policy
	if pol["exception_max_days"] != float64(365) {
		t.Errorf("default exception_max_days = %v", pol["exception_max_days"])
	}
	delete(pol, "exception_max_days")
	if code := admin.do("PUT", "/api/v1/risk-policy", pol, nil); code != 200 {
		t.Errorf("policy without the new field: %d", code)
	}
	admin.do("GET", "/api/v1/risk-policy", nil, &got)
	if got.Policy["exception_max_days"] != float64(365) {
		t.Errorf("omitted exception_max_days should read back as 365: %v", got.Policy["exception_max_days"])
	}
	pol = got.Policy
	pol["exception_max_days"] = 731
	if code := admin.do("PUT", "/api/v1/risk-policy", pol, nil); code != 400 {
		t.Errorf("731-day exception_max_days accepted: %d", code)
	}
	pol["exception_max_days"] = 14
	if code := admin.do("PUT", "/api/v1/risk-policy", pol, nil); code != 200 {
		t.Fatalf("set policy: %d", code)
	}
	if code := sec.do("POST", path, map[string]any{"action": "accept_risk", "note": "no fix yet", "until": time.Now().AddDate(0, 0, 30)}, nil); code != 400 {
		t.Errorf("30-day exception accepted under a 14-day policy: %d", code)
	}
	if code := sec.do("POST", path, map[string]any{"action": "accept_risk", "note": "no fix yet",
		"mitigation": "endpoint blocked at the edge", "until": time.Now().AddDate(0, 0, 7)}, nil); code != 200 {
		t.Fatalf("7-day exception: %d", code)
	}
	f, err := e.st.GetFinding(ctx, fs[0].ID)
	if err != nil || f.State != "risk_accepted" || f.Mitigation != "endpoint blocked at the edge" {
		t.Errorf("finding = %+v %v", f, err)
	}
	if code := sec.do("POST", path, map[string]any{"action": "reopen"}, nil); code != 200 {
		t.Fatalf("reopen: %d", code)
	}
	if f, _ := e.st.GetFinding(ctx, fs[0].ID); f.Mitigation != "" {
		t.Errorf("mitigation kept after reopen: %q", f.Mitigation)
	}
}

func TestAssetDrift(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("eng@x.io", auth.RoleEngineer)
	eng := e.login("eng@x.io")
	host := func(id, purl string) int64 {
		b := model.NewBatch(model.Collector{ID: "linux-agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: id,
			Identifiers: []model.Identifier{{Scheme: "machine-id", Value: id}}})
		b.Observations = []model.Observation{{Purl: purl, Confidence: model.ConfidenceConfirmed}}
		b.Complete = true
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		r, err := e.st.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}
	primary := host("db-1", "pkg:deb/debian/mariadb-server@1:10.11.6-0+deb12u1?distro=debian-12")
	standby := host("db-2", "pkg:deb/debian/mariadb-server@1:10.11.4-1~deb12u1?distro=debian-12")
	path := "/api/v1/assets/" + itoa(standby) + "/drift"
	if code := eng.do("GET", path, nil, nil); code != 400 {
		t.Errorf("drift without a relation: %d", code)
	}
	if code := eng.do("POST", "/api/v1/assets/"+itoa(standby)+"/relations", map[string]any{"to_asset": primary, "kind": "replica_of"}, nil); code != 204 {
		t.Fatalf("add replica_of: %d", code)
	}
	var res struct {
		Drift     store.Drift `json:"drift"`
		Reference store.Asset `json:"reference"`
	}
	if code := eng.do("GET", path, nil, &res); code != 200 || res.Reference.ID != primary || len(res.Drift.Items) != 1 || res.Drift.Items[0].Status != "behind" {
		t.Errorf("drift: %d %+v", code, res)
	}
	if code := eng.do("GET", "/api/v1/assets/"+itoa(primary)+"/drift?with="+itoa(standby), nil, &res); code != 200 || res.Drift.Items[0].Status != "ahead" {
		t.Errorf("reverse drift: %d %+v", code, res.Drift)
	}
}

func TestApplicationBatches(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	_, collector, _ := e.st.CreateToken(ctx, "c", auth.RoleCollector, nil, 0, 0)
	send := func(token string, b *model.ObservationBatch) (int, store.IngestResult) {
		raw, _ := json.Marshal(b)
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/ingest", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var res store.IngestResult
		_ = json.NewDecoder(resp.Body).Decode(&res)
		return resp.StatusCode, res
	}
	hostIDs := func(m string) []model.Identifier { return []model.Identifier{{Scheme: "machine-id", Value: m}} }
	host := func(m string) *model.ObservationBatch {
		b := model.NewBatch(model.Collector{ID: "linux-agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: m, Identifiers: hostIDs(m)})
		b.Observations = []model.Observation{{Purl: "pkg:deb/debian/nginx@1.22.1", Confidence: model.ConfidenceConfirmed}}
		return b
	}
	app := func(m string, git bool) *model.ObservationBatch {
		b := model.NewBatch(model.Collector{ID: "linux-apps", Method: "agent"}, model.AssetRef{Kind: model.AssetApplication, Name: "shop on " + m,
			Identifiers: []model.Identifier{{Scheme: model.AppPathScheme, Value: "/srv/shop"}}})
		b.Observations = []model.Observation{{Purl: "pkg:npm/express@4.17.1", Location: "/srv/shop/node_modules/express", Confidence: model.ConfidenceConfirmed}}
		b.Relations = []model.RelationRef{{Kind: "runs_on", To: hostIDs(m)}}
		if git {
			b.Relations = append(b.Relations, model.RelationRef{Kind: "built_from", To: []model.Identifier{{Scheme: "git-url", Value: "https://github.com/acme/shop"}}})
		}
		b.Complete = true
		return b
	}

	if code, _ := send(collector, app("m1", false)); code != 409 {
		t.Errorf("application before its host: %d", code)
	}
	bad := app("m1", false)
	bad.Relations = nil
	if code, _ := send(collector, bad); code != 400 {
		t.Errorf("application without runs_on: %d", code)
	}
	if code, _ := send(collector, host("m1")); code != 201 {
		t.Fatal(code)
	}
	if code, _ := send(collector, host("m2")); code != 201 {
		t.Fatal(code)
	}
	repo := model.NewBatch(model.Collector{ID: "lockfile", Method: "lockfile"}, model.AssetRef{Kind: model.AssetRepository, Name: "shop",
		Identifiers: []model.Identifier{{Scheme: "git-url", Value: "https://github.com/acme/shop"}}})
	if code, _ := send(collector, repo); code != 201 {
		t.Fatal(code)
	}
	code, a1 := send(collector, app("m1", true))
	if code != 201 || !a1.NewAsset {
		t.Fatalf("app on m1: %d %+v", code, a1)
	}
	_, a2 := send(collector, app("m2", false))
	if a2.AssetID == a1.AssetID {
		t.Error("the same path on two hosts must be two applications")
	}
	if _, again := send(collector, app("m1", true)); again.AssetID != a1.AssetID {
		t.Error("an application must keep its identity across collections")
	}
	rels, _ := e.st.AssetRelations(ctx, a1.AssetID)
	kinds := map[string]bool{}
	for _, r := range rels {
		kinds[r.Kind+":"+r.ToName] = true
	}
	if !kinds["runs_on:m1"] || !kinds["built_from:shop"] || len(rels) != 2 {
		t.Errorf("relations = %+v", rels)
	}
	// A manual relation survives; the collector's built_from goes when no
	// longer reported.
	if code := admin.do("POST", "/api/v1/assets/"+itoa(a1.AssetID)+"/relations", map[string]any{"to_asset": a2.AssetID, "kind": "depends_on"}, nil); code != 204 {
		t.Fatal(code)
	}
	send(collector, app("m1", false))
	rels, _ = e.st.AssetRelations(ctx, a1.AssetID)
	kinds = map[string]bool{}
	for _, r := range rels {
		kinds[r.Kind] = true
	}
	if kinds["built_from"] || !kinds["runs_on"] || !kinds["depends_on"] {
		t.Errorf("after update: %+v", rels)
	}

	// A host-bound token reports its own host's applications only.
	m1, _ := e.st.AssetByIdentifier(ctx, "machine-id", "m1")
	_, boundSecret, err := e.st.CreateAssetToken(ctx, m1, "host", 0)
	if err != nil {
		t.Fatal(err)
	}
	tok := struct{ Secret string }{boundSecret}
	if code, _ := send(tok.Secret, app("m2", false)); code != 403 {
		t.Errorf("bound token reported another host's application: %d", code)
	}
	if code, r := send(tok.Secret, app("m1", false)); code != 201 || r.AssetID != a1.AssetID {
		t.Errorf("bound token, own application: %d %+v", code, r)
	}
}

func TestAssetStack(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("view@x.io", auth.RoleViewer)
	view := e.login("view@x.io")
	ingest := func(b *model.ObservationBatch) int64 {
		b.Complete = true
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		r, err := e.st.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}
	obs := func(purls ...string) []model.Observation {
		var out []model.Observation
		for _, p := range purls {
			out = append(out, model.Observation{Purl: p, Confidence: model.ConfidenceConfirmed})
		}
		return out
	}
	hostB := model.NewBatch(model.Collector{ID: "linux-agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "web-1",
		Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "m1"}}})
	hostB.Observations = obs("pkg:deb/debian/nginx@1.22.1", "pkg:deb/debian/libssl3@3.0.11", "pkg:deb/debian/postgresql-15@15.4",
		"pkg:generic/debian@10", "pkg:generic/nodejs@16.20.2")
	hostB.Observations[3].Evidence = map[string]string{"kind": "operating-system"}
	hostB.Observations[4].Evidence = map[string]string{"kind": "runtime"}
	host := ingest(hostB)
	repoB := model.NewBatch(model.Collector{ID: "lockfile", Method: "lockfile"}, model.AssetRef{Kind: model.AssetRepository, Name: "shop",
		Identifiers: []model.Identifier{{Scheme: "git-url", Value: "https://github.com/acme/shop"}}})
	repoB.Observations = obs("pkg:npm/lodash@4.17.20")
	repo := ingest(repoB)
	appB := model.NewBatch(model.Collector{ID: "linux-apps", Method: "agent"}, model.AssetRef{Kind: model.AssetApplication, Name: "shop on web-1",
		Identifiers: []model.Identifier{{Scheme: "app-path", Value: "/srv/shop"}}})
	appB.Observations = obs("pkg:npm/express@4.17.1")
	appB.Relations = []model.RelationRef{{Kind: "runs_on", To: []model.Identifier{{Scheme: "machine-id", Value: "m1"}}},
		{Kind: "built_from", To: []model.Identifier{{Scheme: "git-url", Value: "https://github.com/acme/shop"}}}}
	app := ingest(appB)

	// One finding per inventory row.
	rows, _, _ := e.st.ListInventory(ctx, store.InventoryFilter{})
	var in []store.FindingInput
	var ids []int64
	for _, r := range rows {
		ids = append(ids, r.ID)
		in = append(in, store.FindingInput{Kind: "vulnerability", Key: "CVE-" + r.Name, InventoryID: r.ID, AssetID: r.AssetID,
			ComponentID: r.ComponentID, Verification: "confirmed", Severity: "high", Sources: []string{"X"}, Evidence: map[string]any{}})
	}
	if _, _, err := e.st.SyncFindings(ctx, []string{"vulnerability"}, ids, in); err != nil {
		t.Fatal(err)
	}

	var st store.Stack
	if code := view.do("GET", "/api/v1/assets/"+itoa(app)+"/stack", nil, &st); code != 200 {
		t.Fatalf("stack: %d", code)
	}
	roles := map[int64]string{}
	for _, m := range st.Members {
		roles[m.AssetID] = m.Role
	}
	if roles[app] != "self" || roles[host] != "host" || roles[repo] != "source" || len(roles) != 3 {
		t.Errorf("members = %+v", st.Members)
	}
	layers := map[string]int{}
	for _, l := range st.Layers {
		layers[l.Layer] = l.Open
	}
	want := map[string]int{"web_server": 1, "os": 2, "data_store": 1, "runtime": 1, "libraries": 1, "declared": 1}
	for k, v := range want {
		if layers[k] != v {
			t.Errorf("layer %s = %d, want %d (all %v)", k, layers[k], v, layers)
		}
	}
	if st.Layers[0].Layer != "web_server" || len(st.Findings) != 7 {
		t.Errorf("layers %+v, %d findings", st.Layers, len(st.Findings))
	}

	// From the host: what runs on it.
	if code := view.do("GET", "/api/v1/assets/"+itoa(host)+"/stack", nil, &st); code != 200 || len(st.Members) != 2 || st.Members[1].Role != "workload" {
		t.Errorf("host stack: %d %+v", code, st.Members)
	}
	// From the repository: where it is deployed and on which host.
	if code := view.do("GET", "/api/v1/assets/"+itoa(repo)+"/stack", nil, &st); code != 200 || len(st.Members) != 3 {
		t.Errorf("repo stack: %d %+v", code, st.Members)
	}
	if code := view.do("GET", "/api/v1/assets/999/stack", nil, nil); code != 404 {
		t.Errorf("missing asset: %d", code)
	}
}

func TestEnrollmentAndInstaller(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	admin, eng := e.login("admin@x.io"), e.login("eng@x.io")

	if code := eng.do("POST", "/api/v1/enrollments", map[string]any{}, nil); code != 403 {
		t.Errorf("engineer created an enrollment: %d", code)
	}
	for _, bad := range []map[string]any{
		{"app_dirs": []string{"relative/dir"}},
		{"app_dirs": []string{"/srv/a b"}},
		{"app_dirs": []string{"/srv/a,/srv/b"}},
		{"environment": "prod; rm -rf /"},
		{"uses": 1000},
		{"ttl_hours": 10000},
	} {
		if code := admin.do("POST", "/api/v1/enrollments", bad, nil); code != 400 {
			t.Errorf("accepted %v: %d", bad, code)
		}
	}
	var created struct {
		Enrollment store.Enrollment `json:"enrollment"`
		Code       string           `json:"code"`
	}
	if code := admin.do("POST", "/api/v1/enrollments", map[string]any{"label": "web servers", "environment": "production",
		"app_dirs": []string{"/srv/shop"}, "discover_apps": true}, &created); code != 201 || !strings.HasPrefix(created.Code, "enr_") {
		t.Fatalf("create: %d %+v", code, created)
	}

	redeem := func(code string) (int, map[string]any) {
		var out map[string]any
		c := e.anon().do("POST", "/api/v1/enroll", map[string]string{"code": code, "hostname": "web-9"}, &out)
		return c, out
	}
	status, got := redeem(created.Code)
	if status != 200 || got["environment"] != "production" || got["discover_apps"] != true {
		t.Fatalf("redeem: %d %v", status, got)
	}
	tok, _ := got["token"].(string)
	if code := bearer(e, tok, "POST", "/api/v1/ingest", sampleBatch(), nil); code != 201 {
		t.Errorf("enrolled token cannot ingest: %d", code)
	}
	if code := bearer(e, tok, "GET", "/api/v1/findings", nil, nil); code != 403 {
		t.Errorf("enrolled token can read findings: %d", code)
	}
	if status, _ := redeem(created.Code); status != 403 {
		t.Errorf("single-use code redeemed twice: %d", status)
	}
	if status, _ := redeem("enr_nope"); status != 403 {
		t.Errorf("unknown code: %d", status)
	}

	// A revoked code stops working and leaves the list.
	admin.do("POST", "/api/v1/enrollments", map[string]any{"uses": 5}, &created)
	if code := admin.do("DELETE", "/api/v1/enrollments/"+itoa(created.Enrollment.ID), nil, nil); code != 204 {
		t.Fatal(code)
	}
	if status, _ := redeem(created.Code); status != 403 {
		t.Errorf("revoked code redeemed: %d", status)
	}
	var list struct {
		Items []store.Enrollment `json:"items"`
	}
	admin.do("GET", "/api/v1/enrollments", nil, &list)
	if len(list.Items) != 0 {
		t.Errorf("used and revoked codes still listed: %+v", list.Items)
	}

	resp := e.anon().req("GET", "/install/agent.sh", nil, nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), `SERVER="${STACKURITY_SERVER:-`+e.srv.URL+`}"`) {
		t.Errorf("installer: %d\n%s", resp.StatusCode, body[:200])
	}
	resp = e.anon().req("GET", "/download/agent/linux-amd64", nil, nil)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("download without agent builds: %d", resp.StatusCode)
	}
}

func TestAgentDownload(t *testing.T) {
	st := store.New(testdb.New(t))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stackurity-linux-arm64"), []byte("binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &api.Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), AgentDir: dir, BaseURL: "https://stk.example.com/"}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	get := func(p string) (int, string) {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := get("/download/agent/linux-arm64"); code != 200 || body != "binary" {
		t.Errorf("download: %d %q", code, body)
	}
	for _, p := range []string{"/download/agent/linux-amd64", "/download/agent/..%2f..%2fetc%2fpasswd", "/download/agent/windows-amd64"} {
		if code, _ := get(p); code != 404 {
			t.Errorf("%s: %d", p, code)
		}
	}
	if _, body := get("/install/agent.sh"); !strings.Contains(body, "https://stk.example.com/install/agent.sh") {
		t.Error("installer should use the configured base URL")
	}
}

// Two copies of one application on a host are told apart by their path;
// the same name on different hosts needs nothing; a name a person set
// stays as it is.
func TestApplicationNamesOnOneHost(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	_, collector, _ := e.st.CreateToken(ctx, "c", auth.RoleCollector, nil, 0, 0)
	send := func(b *model.ObservationBatch) store.IngestResult {
		raw, _ := json.Marshal(b)
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/ingest", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+collector)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var res store.IngestResult
		_ = json.NewDecoder(resp.Body).Decode(&res)
		if resp.StatusCode != 201 {
			t.Fatalf("ingest %s: %d", b.Asset.Name, resp.StatusCode)
		}
		return res
	}
	hostIDs := func(m string) []model.Identifier { return []model.Identifier{{Scheme: "machine-id", Value: m}} }
	for _, m := range []string{"DBC", "WEB"} {
		send(model.NewBatch(model.Collector{ID: "linux-agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: m, Identifiers: hostIDs(m)}))
	}
	app := func(host, dir string) int64 {
		b := model.NewBatch(model.Collector{ID: "linux-apps", Method: "agent"}, model.AssetRef{Kind: model.AssetApplication, Name: "phpmyadmin on " + host,
			Identifiers: []model.Identifier{{Scheme: model.AppPathScheme, Value: dir}}, Attributes: map[string]string{"app_dir": dir, "host": host}})
		b.Relations = []model.RelationRef{{Kind: "runs_on", To: hostIDs(host)}}
		b.Complete = true
		return send(b).AssetID
	}
	name := func(id int64) string {
		var a struct{ Asset store.Asset }
		admin.do("GET", "/api/v1/assets/"+itoa(id), nil, &a)
		return a.Asset.Name
	}
	first := app("DBC", "/var/www/html/phpmyadmin")
	other := app("WEB", "/var/www/html/phpmyadmin")
	if n := name(first); n != "phpmyadmin on DBC" {
		t.Errorf("first copy = %q", n)
	}
	second := app("DBC", "/var/www/html/demo/phpmyadmin")
	if n := name(second); n != "phpmyadmin (/demo/phpmyadmin) on DBC" {
		t.Errorf("second copy = %q", n)
	}
	if n := name(first); n != "phpmyadmin (/phpmyadmin) on DBC" {
		t.Errorf("first copy after the second = %q", n)
	}
	if n := name(other); n != "phpmyadmin on WEB" {
		t.Errorf("same name on another host = %q", n)
	}
	// Reporting again changes nothing.
	app("DBC", "/var/www/html/phpmyadmin")
	if n := name(first); n != "phpmyadmin (/phpmyadmin) on DBC" {
		t.Errorf("after a second report = %q", n)
	}
	// A person's name stays, even when it is the generated one.
	if code := admin.do("PATCH", "/api/v1/assets/"+itoa(other), map[string]any{"name": "phpmyadmin on WEB"}, nil); code != 200 {
		t.Fatalf("rename: %d", code)
	}
	third := app("WEB", "/srv/tools/phpmyadmin")
	if n := name(other); n != "phpmyadmin on WEB" {
		t.Errorf("renamed by a person = %q", n)
	}
	if n := name(third); n != "phpmyadmin (/srv/tools/phpmyadmin) on WEB" {
		t.Errorf("third copy = %q", n)
	}
}
