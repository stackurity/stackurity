package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/tenant"
)

// AI assistants (assistants.go): the remote MCP endpoint, OAuth sign-in,
// and the tools' isolation between organisations and projects.

const redirectURI = "https://assistant.example/oauth/callback"

type oauthFx struct {
	e        *env
	clientID string
	secret   string
	// readOnly leaves "Allow changes" off on the consent page.
	readOnly bool
}

// withBaseURL turns assistants on: they need STACKURITY_BASE_URL.
func withBaseURL(e *env) {
	if e.api.BaseURL == "" {
		e.api.BaseURL = e.srv.URL
	}
}

// workspaceOf is the organisation a session works in, as the consent page
// shows it.
func workspaceOf(s *session) int64 {
	var me struct{ Workspace struct{ ID int64 } }
	s.do("GET", "/api/v1/auth/me", nil, &me)
	return me.Workspace.ID
}

func jsonPost(e *env, path string, body any, hdr map[string]string) (int, map[string]any, http.Header) {
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Header
}

// registerAssistant registers a public client by dynamic client registration.
func registerAssistant(t *testing.T, e *env, redirects ...string) *oauthFx {
	t.Helper()
	withBaseURL(e)
	if len(redirects) == 0 {
		redirects = []string{redirectURI}
	}
	code, out, _ := jsonPost(e, "/oauth/register", map[string]any{"client_name": "Sweep Assistant", "redirect_uris": redirects,
		"token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"}}, nil)
	if code != 201 || out["client_id"] == nil || out["client_secret"] != nil {
		t.Fatalf("register: %d %v", code, out)
	}
	return &oauthFx{e: e, clientID: out["client_id"].(string)}
}

func pkcePair(seed string) (verifier, challenge string) {
	verifier = strings.Repeat("v", 43-len(seed)) + seed
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func (o *oauthFx) params(challenge string) map[string]any {
	return map[string]any{"response_type": "code", "client_id": o.clientID, "redirect_uri": redirectURI, "code_challenge": challenge,
		"code_challenge_method": "S256", "state": "st-1", "resource": o.e.srv.URL + "/mcp"}
}

// authorize allows the connection as s and returns the code from the
// redirect.
func (o *oauthFx) authorize(t *testing.T, s *session, challenge string, role auth.Role, project int64) string {
	t.Helper()
	p := o.params(challenge)
	p["decision"], p["role"], p["project_id"] = "allow", role, project
	p["workspace_id"], p["allow_changes"] = workspaceOf(s), !o.readOnly
	var out struct{ Redirect string }
	if code := s.do("POST", "/api/v1/oauth/authorize", p, &out); code != 200 {
		t.Fatalf("authorize: %d", code)
	}
	u, err := url.Parse(out.Redirect)
	if err != nil || !strings.HasPrefix(out.Redirect, redirectURI+"?") || u.Query().Get("state") != "st-1" || u.Query().Get("iss") != o.e.srv.URL {
		t.Fatalf("redirect = %q", out.Redirect)
	}
	return u.Query().Get("code")
}

func (o *oauthFx) token(form url.Values) (int, map[string]any) {
	if form.Get("client_id") == "" && o.secret == "" {
		form.Set("client_id", o.clientID)
	}
	req, _ := http.NewRequest("POST", o.e.srv.URL+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if o.secret != "" {
		req.SetBasicAuth(o.clientID, o.secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		o.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if cc := resp.Header.Get("Cache-Control"); resp.StatusCode == 200 && cc != "no-store" {
		o.e.t.Errorf("token response Cache-Control %q", cc)
	}
	return resp.StatusCode, out
}

func (o *oauthFx) exchange(t *testing.T, code, verifier string) (access, refresh string) {
	t.Helper()
	status, out := o.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"redirect_uri": {redirectURI}, "resource": {o.e.srv.URL + "/mcp"}})
	if status != 200 || out["token_type"] != "Bearer" {
		t.Fatalf("exchange: %d %v", status, out)
	}
	return out["access_token"].(string), out["refresh_token"].(string)
}

// connect runs the whole flow as s and returns the access token.
func (o *oauthFx) connect(t *testing.T, s *session, role auth.Role, project int64) string {
	t.Helper()
	v, c := pkcePair(fmt.Sprint(time.Now().UnixNano() % 1000000))
	access, _ := o.exchange(t, o.authorize(t, s, c, role, project), v)
	return access
}

// mcp sends one JSON-RPC message to /mcp with token.
func mcpPost(e *env, token string, msg map[string]any) (int, map[string]any, http.Header) {
	msg["jsonrpc"] = "2.0"
	hdr := map[string]string{"Accept": "application/json, text/event-stream"}
	if token != "" {
		hdr["Authorization"] = "Bearer " + token
	}
	return jsonPost(e, "/mcp", msg, hdr)
}

// callTool calls a tool through /mcp and returns its text and whether it
// was a tool error.
func callMCPTool(t *testing.T, e *env, token, name string, args map[string]any) (string, bool) {
	t.Helper()
	code, out, _ := mcpPost(e, token, map[string]any{"id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	if code != 200 || out["result"] == nil {
		t.Fatalf("%s: %d %v", name, code, out)
	}
	res := out["result"].(map[string]any)
	return res["content"].([]any)[0].(map[string]any)["text"].(string), res["isError"] == true
}

// TestAssistantOAuth walks the sign-in an assistant makes: discovery,
// registration, consent, the code with PKCE, refresh, and every way a
// connection ends.
func TestAssistantOAuth(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	admin := e.signIn("admin@x.io")

	// Without STACKURITY_BASE_URL assistants are off: the issuer and the
	// resource would come from the Host header.
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource/mcp"} {
		if code := e.anon().do("GET", path, nil, nil); code != 404 {
			t.Errorf("%s without a base URL: %d", path, code)
		}
	}
	if code, _, _ := mcpPost(e, "", map[string]any{"id": 1, "method": "ping"}); code != 404 {
		t.Errorf("/mcp without a base URL: %d", code)
	}
	withBaseURL(e)

	// Discovery: /mcp says where to sign in.
	code, _, h := mcpPost(e, "", map[string]any{"id": 1, "method": "tools/list"})
	if code != 401 || !strings.Contains(h.Get("WWW-Authenticate"), `resource_metadata="`+e.srv.URL+`/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("unauthenticated /mcp: %d %q", code, h.Get("WWW-Authenticate"))
	}
	var prm, asm map[string]any
	e.anon().do("GET", "/.well-known/oauth-protected-resource/mcp", nil, &prm)
	e.anon().do("GET", "/.well-known/oauth-authorization-server", nil, &asm)
	if prm["resource"] != e.srv.URL+"/mcp" || prm["authorization_servers"].([]any)[0] != e.srv.URL {
		t.Errorf("protected resource metadata = %v", prm)
	}
	if asm["issuer"] != e.srv.URL || asm["code_challenge_methods_supported"].([]any)[0] != "S256" || asm["registration_endpoint"] != e.srv.URL+"/oauth/register" ||
		asm["client_id_metadata_document_supported"] != true || asm["authorization_response_iss_parameter_supported"] != true {
		t.Errorf("authorization server metadata = %v", asm)
	}
	// A browser-based client's preflight.
	req, _ := http.NewRequest("OPTIONS", e.srv.URL+"/oauth/token", nil)
	req.Header.Set("Origin", "https://inspector.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("preflight: %d %v", resp.StatusCode, resp.Header)
	}

	// Registration refuses redirect URIs that are not HTTPS, loopback or an
	// app's own scheme.
	for _, bad := range []string{"http://evil.example/cb", "javascript:alert(1)", "https://x.example/cb#frag", "https://user@x.example/cb", "/relative",
		"myapp:/callback", "intent://cb#Intent;scheme=x;end", "ms-word:ofe|u|https://x"} {
		if code, out, _ := jsonPost(e, "/oauth/register", map[string]any{"redirect_uris": []string{bad}, "token_endpoint_auth_method": "none"}, nil); code != 400 || out["error"] != "invalid_redirect_uri" {
			t.Errorf("register %q: %d %v", bad, code, out)
		}
	}
	if code, out, _ := jsonPost(e, "/oauth/register", map[string]any{"redirect_uris": []string{"com.example.app:/oauth/cb"}, "token_endpoint_auth_method": "none"}, nil); code != 201 {
		t.Errorf("register a reverse-DNS app scheme: %d %v", code, out)
	}
	o := registerAssistant(t, e, redirectURI, "http://127.0.0.1:33418/callback")

	// The consent page's preview: the client, the organisation and the
	// roles this person may give.
	v, c := pkcePair("a")
	var pv struct {
		Client struct {
			Name         string
			RedirectHost string `json:"redirect_host"`
		}
		Roles     []string
		Workspace struct{ Name string }
	}
	if code := admin.do("POST", "/api/v1/oauth/authorize/preview", o.params(c), &pv); code != 200 || pv.Client.Name != "Sweep Assistant" ||
		pv.Client.RedirectHost != "assistant.example" || len(pv.Roles) != 4 {
		t.Fatalf("preview: %d %+v", code, pv)
	}
	var engPv struct{ Roles []string }
	if e.signIn("eng@x.io").do("POST", "/api/v1/oauth/authorize/preview", o.params(c), &engPv); strings.Join(engPv.Roles, ",") != "viewer,engineer" {
		t.Errorf("an engineer may give %v", engPv.Roles)
	}
	// A redirect URI the client did not register is shown, never followed.
	bad := o.params(c)
	bad["redirect_uri"] = "https://evil.example/cb"
	var perr struct {
		Error struct{ Code, Redirect string }
	}
	if code := admin.do("POST", "/api/v1/oauth/authorize/preview", bad, &perr); code != 400 || perr.Error.Redirect != "" {
		t.Errorf("unregistered redirect: %d %+v", code, perr)
	}
	// PKCE is required: the error goes back to the client.
	noPKCE := o.params("")
	delete(noPKCE, "code_challenge_method")
	if code := admin.do("POST", "/api/v1/oauth/authorize/preview", noPKCE, &perr); code != 400 || !strings.HasPrefix(perr.Error.Redirect, redirectURI+"?") ||
		!strings.Contains(perr.Error.Redirect, "error=invalid_request") {
		t.Errorf("no PKCE: %d %+v", code, perr)
	}
	// Another resource is refused.
	other := o.params(c)
	other["resource"] = "https://other.example/mcp"
	if code := admin.do("POST", "/api/v1/oauth/authorize/preview", other, &perr); code != 400 || !strings.Contains(perr.Error.Redirect, "invalid_target") {
		t.Errorf("other resource: %d %+v", code, perr)
	}
	// The loopback port may differ (native apps); the path may not.
	loop := o.params(c)
	loop["redirect_uri"] = "http://127.0.0.1:51234/callback"
	if code := admin.do("POST", "/api/v1/oauth/authorize/preview", loop, nil); code != 200 {
		t.Errorf("loopback with another port: %d", code)
	}
	loop["redirect_uri"] = "http://127.0.0.1:51234/other"
	if code := admin.do("POST", "/api/v1/oauth/authorize/preview", loop, nil); code != 400 {
		t.Errorf("loopback with another path: %d", code)
	}
	// Only a browser session may allow: an API token cannot.
	var tok struct{ Secret string }
	admin.do("POST", "/api/v1/tokens", map[string]any{"name": "t", "role": "admin"}, &tok)
	if code, _, _ := jsonPost(e, "/api/v1/oauth/authorize/preview", o.params(c), map[string]string{"Authorization": "Bearer " + tok.Secret}); code != 403 {
		t.Errorf("preview with a token: %d", code)
	}
	// Declining sends access_denied back.
	deny := o.params(c)
	deny["decision"], deny["workspace_id"] = "deny", workspaceOf(admin)
	var out struct{ Redirect string }
	admin.do("POST", "/api/v1/oauth/authorize", deny, &out)
	if !strings.Contains(out.Redirect, "error=access_denied") || !strings.Contains(out.Redirect, "state=st-1") {
		t.Errorf("deny: %q", out.Redirect)
	}
	// A role above one's own is refused.
	above := o.params(c)
	above["decision"], above["role"], above["workspace_id"] = "allow", "admin", workspaceOf(admin)
	if code := e.signIn("eng@x.io").do("POST", "/api/v1/oauth/authorize", above, nil); code != 403 {
		t.Errorf("engineer giving admin: %d", code)
	}

	// The page showed another organisation than the session's now: refused.
	moved := o.params(c)
	moved["decision"], moved["role"], moved["workspace_id"] = "allow", "viewer", workspaceOf(admin)+1
	if code := admin.do("POST", "/api/v1/oauth/authorize", moved, nil); code != 409 {
		t.Errorf("decision for another organisation: %d", code)
	}
	// The token request must repeat the code's redirect URI.
	if status, _ := o.token(url.Values{"grant_type": {"authorization_code"}, "code": {o.authorize(t, admin, c, auth.RoleViewer, 0)},
		"code_verifier": {v}}); status != 400 {
		t.Errorf("token request without redirect_uri: %d", status)
	}

	// The code: a wrong verifier fails and uses it up.
	code1 := o.authorize(t, admin, c, auth.RoleAdmin, 0)
	if status, out := o.token(url.Values{"grant_type": {"authorization_code"}, "code": {code1}, "code_verifier": {strings.Repeat("w", 43)},
		"redirect_uri": {redirectURI}}); status != 400 || out["error"] != "invalid_grant" {
		t.Errorf("wrong verifier: %d %v", status, out)
	}
	if status, _ := o.token(url.Values{"grant_type": {"authorization_code"}, "code": {code1}, "code_verifier": {v}, "redirect_uri": {redirectURI}}); status != 400 {
		t.Errorf("code after a failed exchange: %d", status)
	}
	// Another client cannot use a code.
	o2 := registerAssistant(t, e)
	code2 := o.authorize(t, admin, c, auth.RoleAdmin, 0)
	if status, _ := o2.token(url.Values{"grant_type": {"authorization_code"}, "code": {code2}, "code_verifier": {v}, "redirect_uri": {redirectURI}}); status != 400 {
		t.Errorf("code of another client: %d", status)
	}
	// The right exchange works once; a second use ends the connection.
	code3 := o.authorize(t, admin, c, auth.RoleAdmin, 0)
	access, refresh := o.exchange(t, code3, v)
	if !strings.HasPrefix(access, "stka_") || !strings.HasPrefix(refresh, "stkr_") {
		t.Fatalf("tokens: %s %s", access, refresh)
	}
	if code, out, _ := mcpPost(e, access, map[string]any{"id": 1, "method": "tools/list"}); code != 200 || len(out["result"].(map[string]any)["tools"].([]any)) != 21 {
		t.Errorf("tools/list: %d %v", code, out)
	}
	if status, _ := o.token(url.Values{"grant_type": {"authorization_code"}, "code": {code3}, "code_verifier": {v}, "redirect_uri": {redirectURI}}); status != 400 {
		t.Errorf("code reused: %d", status)
	}
	if code, _, _ := mcpPost(e, access, map[string]any{"id": 1, "method": "tools/list"}); code != 401 {
		t.Errorf("after the code was reused the connection must end: %d", code)
	}

	// An access token works only through /mcp.
	access, refresh = o.exchange(t, o.authorize(t, admin, c, auth.RoleAdmin, 0), v)
	if code := bearer(e, access, "GET", "/api/v1/assets", nil, nil); code != 401 {
		t.Errorf("assistant token on the API: %d", code)
	}
	// Refresh rotates; replaying the old refresh token ends the connection.
	status, r1 := o.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
	if status != 200 || r1["refresh_token"] == refresh {
		t.Fatalf("refresh: %d %v", status, r1)
	}
	if code, _, _ := mcpPost(e, r1["access_token"].(string), map[string]any{"id": 1, "method": "ping"}); code != 200 {
		t.Errorf("refreshed token: %d", code)
	}
	if status, _ := o2.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r1["refresh_token"].(string)}}); status != 400 {
		t.Errorf("refresh by another client: %d", status)
	}
	if status, _ := o.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}); status != 400 {
		t.Errorf("replayed refresh token: %d", status)
	}
	if code, _, _ := mcpPost(e, r1["access_token"].(string), map[string]any{"id": 1, "method": "ping"}); code != 401 {
		t.Errorf("after a replayed refresh token the connection must end: %d", code)
	}
	if status, _ := o.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r1["refresh_token"].(string)}}); status != 400 {
		t.Errorf("refresh after the replay: %d", status)
	}

	// Expiry: an access token past its hour stops working.
	access, refresh = o.exchange(t, o.authorize(t, admin, c, auth.RoleAdmin, 0), v)
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()), `UPDATE oauth_access_tokens SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if code, _, h := mcpPost(e, access, map[string]any{"id": 1, "method": "ping"}); code != 401 || !strings.Contains(h.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("expired token: %d %q", code, h.Get("WWW-Authenticate"))
	}
	// A refresh token unused for 30 days stops working too.
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()), `UPDATE oauth_grants SET refresh_expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if status, _ := o.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}); status != 400 {
		t.Errorf("expired refresh token: %d", status)
	}

	// Revocation by the assistant (RFC 7009).
	access, refresh = o.exchange(t, o.authorize(t, admin, c, auth.RoleAdmin, 0), v)
	form := url.Values{"token": {refresh}, "client_id": {o.clientID}}
	resp, err = http.PostForm(e.srv.URL+"/oauth/revoke", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("revoke: %d", resp.StatusCode)
	}
	if code, _, _ := mcpPost(e, access, map[string]any{"id": 1, "method": "ping"}); code != 401 {
		t.Errorf("after revocation: %d", code)
	}

	// Settings: the person's connected assistants, and Disconnect.
	access = o.connect(t, admin, auth.RoleViewer, 0)
	var list struct {
		Items []struct {
			ID           int64
			ClientName   string `json:"client_name"`
			Role         string
			AllowChanges bool `json:"allow_changes"`
		}
	}
	if code := admin.do("GET", "/api/v1/assistants", nil, &list); code != 200 || len(list.Items) != 1 || list.Items[0].Role != "viewer" {
		t.Fatalf("connected assistants: %d %+v", code, list)
	}
	if code := e.signIn("eng@x.io").do("DELETE", fmt.Sprint("/api/v1/assistants/", list.Items[0].ID), nil, nil); code != 404 {
		t.Errorf("someone else disconnecting: %d", code)
	}
	if code := admin.do("DELETE", fmt.Sprint("/api/v1/assistants/", list.Items[0].ID), nil, nil); code != 204 {
		t.Errorf("disconnect: %d", code)
	}
	if code, _, _ := mcpPost(e, access, map[string]any{"id": 1, "method": "ping"}); code != 401 {
		t.Errorf("after disconnect: %d", code)
	}
	if admin.do("GET", "/api/v1/assistants", nil, &list); len(list.Items) != 0 {
		t.Errorf("still listed: %+v", list)
	}
	// Everything is in the audit log.
	var audit struct{ Items []struct{ Action string } }
	admin.do("GET", "/api/v1/audit?limit=500", nil, &audit)
	seen := map[string]int{}
	for _, a := range audit.Items {
		seen[a.Action]++
	}
	if seen["assistant.authorize"] == 0 || seen["assistant.connect"] == 0 || seen["assistant.revoke"] < 2 {
		t.Errorf("audit: %v", seen)
	}

	// "Allow changes" off: read tools only, and the API refuses changes
	// even if a tool were reached; it can be turned on in Settings.
	ro := &oauthFx{e: e, clientID: o.clientID, readOnly: true}
	roToken := ro.connect(t, admin, auth.RoleAdmin, 0)
	if _, out, _ := mcpPost(e, roToken, map[string]any{"id": 1, "method": "tools/list"}); len(out["result"].(map[string]any)["tools"].([]any)) != 11 {
		t.Errorf("read-only connection lists %v", out)
	}
	if code, out, _ := mcpPost(e, roToken, map[string]any{"id": 1, "method": "tools/call", "params": map[string]any{"name": "create_project",
		"arguments": map[string]any{"name": "x"}}}); code != 200 || out["error"] == nil {
		t.Errorf("write tool on a read-only connection: %d %v", code, out)
	}
	admin.do("GET", "/api/v1/assistants", nil, &list)
	if len(list.Items) != 1 || list.Items[0].AllowChanges {
		t.Fatalf("read-only connection listed as %+v", list.Items)
	}
	if code := e.signIn("eng@x.io").do("PATCH", fmt.Sprint("/api/v1/assistants/", list.Items[0].ID), map[string]any{"allow_changes": true}, nil); code != 404 {
		t.Errorf("someone else allowing changes: %d", code)
	}
	if code := admin.do("PATCH", fmt.Sprint("/api/v1/assistants/", list.Items[0].ID), map[string]any{"allow_changes": true}, nil); code != 200 {
		t.Errorf("allow changes: %d", code)
	}
	if _, out, _ := mcpPost(e, roToken, map[string]any{"id": 1, "method": "tools/list"}); len(out["result"].(map[string]any)["tools"].([]any)) != 21 {
		t.Errorf("after allowing changes: %v", out)
	}
	// Tokens that do not work are limited per address.
	limited := false
	for range 40 {
		if code, _, _ := mcpPost(e, "stka_wrong", map[string]any{"id": 1, "method": "ping"}); code == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("no limit on wrong tokens at /mcp")
	}

	// A personal API token works on /mcp too; collector tokens do not.
	if code, _, _ := mcpPost(e, tok.Secret, map[string]any{"id": 1, "method": "ping"}); code != 200 {
		t.Errorf("personal token on /mcp: %d", code)
	}
	var col struct{ Secret string }
	admin.do("POST", "/api/v1/tokens", map[string]any{"name": "c", "role": "collector"}, &col)
	if code, _, _ := mcpPost(e, col.Secret, map[string]any{"id": 1, "method": "ping"}); code != 403 {
		t.Errorf("collector token on /mcp: %d", code)
	}
	// No GET stream, no sessions; cookies are not credentials here.
	if code := admin.do("GET", "/mcp", nil, nil); code != 405 {
		t.Errorf("GET /mcp: %d", code)
	}
	if code := admin.do("POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}, nil); code != 401 {
		t.Errorf("POST /mcp with a session cookie: %d", code)
	}
	if code, _, _ := jsonPost(e, "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"},
		map[string]string{"Authorization": "Bearer " + tok.Secret, "Origin": "null"}); code != 403 {
		t.Errorf("Origin null: %d", code)
	}
}

// TestAssistantClientKinds: a confidential client (secret with HTTP
// Basic), and a client ID metadata document.
func TestAssistantClientKinds(t *testing.T) {
	doc := map[string]any{"client_name": "Doc Client", "redirect_uris": []string{redirectURI}, "token_endpoint_auth_method": "none"}
	meta := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := map[string]any{"client_id": "https://" + r.Host + r.URL.Path}
		for k, v := range doc {
			d[k] = v
		}
		if r.URL.Path == "/wrong.json" {
			d["client_id"] = "https://elsewhere.example/client.json"
		}
		_ = json.NewEncoder(w).Encode(d)
	}))
	defer meta.Close()
	e := newEnvWith(t, func(s *api.Server) { s.ClientMetadataHTTP = meta.Client() })
	withBaseURL(e)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.signIn("admin@x.io")
	v, c := pkcePair("k")

	code, reg, _ := jsonPost(e, "/oauth/register", map[string]any{"client_name": "Secret Client", "redirect_uris": []string{redirectURI}}, nil)
	if code != 201 || reg["client_secret"] == nil || reg["token_endpoint_auth_method"] != "client_secret_basic" {
		t.Fatalf("confidential registration: %d %v", code, reg)
	}
	conf := &oauthFx{e: e, clientID: reg["client_id"].(string), secret: reg["client_secret"].(string)}
	cc := conf.authorize(t, admin, c, auth.RoleViewer, 0)
	wrong := &oauthFx{e: e, clientID: conf.clientID, secret: "stks_wrong"}
	if status, out := wrong.token(url.Values{"grant_type": {"authorization_code"}, "code": {cc}, "code_verifier": {v}, "redirect_uri": {redirectURI}}); status != 401 || out["error"] != "invalid_client" {
		t.Errorf("wrong secret: %d %v", status, out)
	}
	conf.exchange(t, cc, v)

	md := &oauthFx{e: e, clientID: meta.URL + "/client.json"}
	var pv struct{ Client struct{ Name string } }
	if code := admin.do("POST", "/api/v1/oauth/authorize/preview", md.params(c), &pv); code != 200 || pv.Client.Name != "Doc Client" {
		t.Fatalf("metadata client preview: %d %+v", code, pv)
	}
	access := md.connect(t, admin, auth.RoleViewer, 0)
	if code, _, _ := mcpPost(e, access, map[string]any{"id": 1, "method": "ping"}); code != 200 {
		t.Errorf("metadata client token: %d", code)
	}
	bad := &oauthFx{e: e, clientID: meta.URL + "/wrong.json"}
	if code := admin.do("POST", "/api/v1/oauth/authorize/preview", bad.params(c), nil); code != 400 {
		t.Errorf("document naming another client_id: %d", code)
	}
	// Without the test's client, the guard refuses loopback addresses.
	e.api.ClientMetadataHTTP = nil
	guarded := &oauthFx{e: e, clientID: meta.URL + "/other.json"}
	if code := admin.do("POST", "/api/v1/oauth/authorize/preview", guarded.params(c), nil); code != 400 {
		t.Errorf("metadata document on a loopback address: %d", code)
	}
}

// TestAssistantRoles: a connection never acts above its role or above the
// person's current role, write tools change nothing without confirmation,
// and every change is audited as the assistant.
func TestAssistantRoles(t *testing.T) {
	o := newOrg(t)
	e := o.e
	oc := registerAssistant(t, e)
	viewer := oc.connect(t, o.admin, auth.RoleViewer, 0)
	admin := oc.connect(t, o.admin, auth.RoleAdmin, 0)

	args := map[string]any{"name": "Assistant project"}
	text, isErr := callMCPTool(t, e, admin, "create_project", args)
	var pv map[string]any
	_ = json.Unmarshal([]byte(text), &pv)
	if isErr || pv["status"] != "preview" {
		t.Fatalf("preview: %s", text)
	}
	var projects struct{ Items []struct{ Name string } }
	o.admin.do("GET", "/api/v1/projects", nil, &projects)
	for _, p := range projects.Items {
		if p.Name == "Assistant project" {
			t.Fatal("the preview created the project")
		}
	}
	args["confirm"] = pv["confirm"]
	// The viewer connection's preview code is the same (the arguments are),
	// but its role does not allow the change.
	if text, isErr := callMCPTool(t, e, viewer, "create_project", args); !isErr || !strings.Contains(text, "403") && !strings.Contains(text, "requires role") {
		t.Errorf("viewer connection created a project: %s", text)
	}
	if text, isErr := callMCPTool(t, e, admin, "create_project", args); isErr || !strings.Contains(text, `"status": "done"`) {
		t.Errorf("confirmed: %s", text)
	}
	var audit struct {
		Items []struct {
			Action    string
			ActorType string `json:"actor_type"`
			ActorName string `json:"actor_name"`
		}
	}
	o.admin.do("GET", "/api/v1/audit?object_type=project&limit=50", nil, &audit)
	found := false
	for _, a := range audit.Items {
		if a.Action == "project.create" && a.ActorType == "assistant" && strings.Contains(a.ActorName, "assistant Sweep Assistant") {
			found = true
		}
	}
	if !found {
		t.Errorf("project.create not audited as the assistant: %+v", audit.Items)
	}
	// An install code from an assistant: small, and audited as the assistant.
	eargs := map[string]any{"servers": 3.0}
	text, _ = callMCPTool(t, e, admin, "create_enrollment", eargs)
	_ = json.Unmarshal([]byte(text), &pv)
	eargs["confirm"] = pv["confirm"]
	if text, isErr := callMCPTool(t, e, admin, "create_enrollment", eargs); isErr || !strings.Contains(text, "STACKURITY_ENROLL_CODE=enr_") {
		t.Errorf("enrollment: %s", text)
	}
	var enrs struct {
		Items []struct {
			UsesLeft  int       `json:"uses_left"`
			ExpiresAt time.Time `json:"expires_at"`
		}
	}
	o.admin.do("GET", "/api/v1/enrollments", nil, &enrs)
	if len(enrs.Items) != 1 || enrs.Items[0].UsesLeft != 3 || time.Until(enrs.Items[0].ExpiresAt) > 25*time.Hour {
		t.Errorf("enrollment = %+v", enrs.Items)
	}
	o.admin.do("GET", "/api/v1/audit?object_type=enrollment&limit=50", nil, &audit)
	if len(audit.Items) == 0 || audit.Items[0].ActorType != "assistant" {
		t.Errorf("enrollment.create audit: %+v", audit.Items)
	}

	// The person is demoted: the admin connection acts as a viewer now.
	if code := o.admin.do("PATCH", fmt.Sprintf("/api/v1/users/%d", o.adminID), map[string]any{"role": "viewer"}, nil); code != 200 {
		// The last admin cannot be demoted; make another admin first.
		e.user("admin2@x.io", auth.RoleAdmin)
		if code := e.signIn("admin2@x.io").do("PATCH", fmt.Sprintf("/api/v1/users/%d", o.adminID), map[string]any{"role": "viewer"}, nil); code != 200 {
			t.Fatalf("demote: %d", code)
		}
	}
	args = map[string]any{"name": "After demotion"}
	text, _ = callMCPTool(t, e, admin, "create_project", args)
	_ = json.Unmarshal([]byte(text), &pv)
	args["confirm"] = pv["confirm"]
	if text, isErr := callMCPTool(t, e, admin, "create_project", args); !isErr {
		t.Errorf("a demoted person's admin connection still creates projects: %s", text)
	}
}

// assistantCalls are every tool with arguments naming the target's
// objects (tag's assets, findings, fix, project): used to check that an
// assistant of another organisation or project gets none of them.
func assistantCalls(ids map[string]string) map[string]map[string]any {
	n := func(k string) float64 {
		var v float64
		_, _ = fmt.Sscan(ids[k], &v)
		return v
	}
	future := time.Now().AddDate(0, 1, 0).Format("2006-01-02")
	return map[string]map[string]any{
		"search":                     {"query": ids["tag"]},
		"list_assets":                {},
		"action_plan":                {"asset_id": n("asset")},
		"asset_stack":                {"asset_id": n("asset")},
		"list_findings":              {"asset_id": n("asset")},
		"get_finding":                {"finding_id": n("finding")},
		"find_component":             {"name": ids["tag"] + "-private-lib"},
		"explain_finding":            {"finding_id": n("finding")},
		"upgrade_recommendation":     {"component_id": n("component")},
		"remediation_plan":           {"asset_id": n("asset")},
		"verify_since":               {"since": "2000-01-01", "asset_id": n("asset")},
		"create_project":             {"name": "new " + ids["tag"], "asset_ids": []any{n("asset")}},
		"rename_project":             {"project_id": n("project"), "name": "renamed"},
		"add_assets_to_project":      {"project_id": n("project"), "asset_ids": []any{n("asset2")}},
		"remove_assets_from_project": {"project_id": n("project"), "asset_ids": []any{n("asset")}},
		"create_enrollment":          {"servers": 2.0, "project_id": n("project")},
		"assign":                     {"fix_group": ids["fixgroup"], "assignee": "me"},
		"snooze":                     {"finding_ids": []any{n("finding")}, "until": future},
		"ignore":                     {"finding_ids": []any{n("finding")}, "reason": "mitigated", "note": "n", "expiry": "date", "until": future},
		"check_again":                {"fix_group": ids["fixgroup"]},
		"invite_to_project":          {"email": "someone@x.io", "project_id": n("project"), "role": "viewer"},
	}
}

// probeTools calls every tool as token with the target's ids, then again
// with the preview's confirm code if a preview came back, and returns each
// answer (a preview of another tenant's objects is itself a leak).
func probeTools(t *testing.T, e *env, token string, ids map[string]string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for name, args := range assistantCalls(ids) {
		text, _ := callMCPTool(t, e, token, name, args)
		out[name] = text
		var pv map[string]any
		if json.Unmarshal([]byte(text), &pv) == nil && pv["status"] == "preview" {
			args["confirm"] = pv["confirm"]
			text, _ = callMCPTool(t, e, token, name, args)
			out[name+" (confirmed)"] = text
		}
	}
	return out
}

// TestAssistantWorkspaceIsolation: an assistant connected to organisation
// B, with B's admin role, calls every tool with A's ids. Nothing of A's
// comes back and A is unchanged.
func TestAssistantWorkspaceIsolation(t *testing.T) {
	e := newEnv(t)
	box, err := secrets.NewBox([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	e.api.SecretBox = box
	ctx := context.Background()
	e.user("admin-alpha@x.io", auth.RoleAdmin)
	betaWS, _, err := e.st.CreateWorkspace(ctx, "Beta Corp", "", "admin-beta@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.EnsureFeed(tenant.System(ctx), "osv:npm", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	b := e.tenant(t, betaWS.ID, "beta", e.login("admin-beta@x.io"))
	a := e.tenant(t, tenant.DefaultWorkspace, "alpha", e.login("admin-alpha@x.io"))
	before := e.snapshot(t, a)
	oc := registerAssistant(t, e)
	token := oc.connect(t, b.sess["admin"], auth.RoleAdmin, 0)
	for name, text := range probeTools(t, e, token, a.ids) {
		if low := strings.ToLower(withoutEchoes(text, "alpha-private-lib", "new alpha", "alpha")); strings.Contains(low, "alpha") {
			t.Errorf("%s with A's ids leaks A: %s", name, text)
		}
		if strings.Contains(text, `"status": "done"`) && name != "create_enrollment (confirmed)" && name != "create_project (confirmed)" {
			t.Errorf("%s changed something with A's ids: %s", name, text)
		}
	}
	// B's own data is there (the assistant is not just refused).
	if text, _ := callMCPTool(t, e, token, "list_assets", map[string]any{}); !strings.Contains(text, "host-beta") {
		t.Errorf("B's assistant does not see B: %s", text)
	}
	if after := e.snapshot(t, a); after != before {
		t.Errorf("A changed:\nbefore %s\nafter  %s", before, after)
	}
}

// TestAssistantProjectIsolation: assistants connected to Project Alpha (by
// an organisation admin who chose the project, and by members with access
// to Alpha only) call every tool with Project Beta's ids: nothing of Beta
// comes back and Beta is unchanged. Organisation tools are refused to a
// connection limited to a project.
func TestAssistantProjectIsolation(t *testing.T) {
	o := newOrg(t)
	e := o.e
	oc := registerAssistant(t, e)
	tokens := map[string]string{"admin bound to Alpha": oc.connect(t, o.admin, auth.RoleAdmin, o.id("alpha-project"))}
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleSecurity, auth.RoleAdmin} {
		email := "pa-mcp-" + string(role) + "@x.io"
		o.grant(t, email, o.id("alpha-project"), 0, role)
		tokens["member "+string(role)] = oc.connect(t, e.signIn(email), role, 0)
	}
	before := o.betaSnapshot(t)
	o.ids["team-x"] = o.id("beta-team")
	beta := o.betaFixture()
	for who, token := range tokens {
		for name, text := range probeTools(t, e, token, beta.ids) {
			if low := strings.ToLower(withoutBetaEchoes(text, "beta-private-lib", "new beta", "beta")); strings.Contains(low, "beta") {
				t.Errorf("%s: %s with Beta's ids leaks Beta: %s", who, name, text)
			}
		}
		// Beta's people are not offered for assignment.
		args := map[string]any{"finding_ids": []any{float64(o.id("alpha-finding"))}, "assignee": "beta-viewer@x.io"}
		if text, isErr := callMCPTool(t, e, token, "assign", args); !isErr || strings.Contains(text, "preview") {
			t.Errorf("%s: assign to Beta's viewer: %s", who, text)
		}
		text, _ := callMCPTool(t, e, token, "list_assets", map[string]any{})
		if !strings.Contains(text, "host-alpha") || strings.Contains(text, "host-beta") || strings.Contains(text, "unfiled-beta") {
			t.Errorf("%s sees: %s", who, text)
		}
	}
	if after := o.betaSnapshot(t); after != before {
		t.Errorf("Project Beta changed:\nbefore %s\nafter  %s", before, after)
	}
	// The bound connection cannot reach organisation routes, nor ask for
	// another project.
	bound := tokens["admin bound to Alpha"]
	args := map[string]any{"servers": 1.0}
	text, _ := callMCPTool(t, e, bound, "create_enrollment", args)
	var pv map[string]any
	_ = json.Unmarshal([]byte(text), &pv)
	args["confirm"] = pv["confirm"]
	if text, isErr := callMCPTool(t, e, bound, "create_enrollment", args); !isErr || !strings.Contains(text, "one project") {
		t.Errorf("bound connection created an enrollment: %s", text)
	}
	code, out, _ := jsonPost(e, "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "list_assets", "arguments": map[string]any{}}},
		map[string]string{"Authorization": "Bearer " + bound, "X-Stackurity-Project": o.s("beta-project")})
	if raw, _ := json.Marshal(out); code != 200 || strings.Contains(string(raw), "host-beta") || !strings.Contains(string(raw), "another project") {
		t.Errorf("bound connection asking for Beta: %d %s", code, raw)
	}
	// It does act inside Alpha.
	args = map[string]any{"asset_id": float64(o.id("alpha-asset"))}
	text, _ = callMCPTool(t, e, bound, "check_again", args)
	_ = json.Unmarshal([]byte(text), &pv)
	args["confirm"] = pv["confirm"]
	if text, isErr := callMCPTool(t, e, bound, "check_again", args); isErr || !strings.Contains(text, `"status": "done"`) {
		t.Errorf("check again in Alpha: %s", text)
	}
	// It cannot ignore an issue on every asset (a rule for every project),
	// although the person could: refused, and no rule is made.
	var rulesBefore struct{ Items []struct{ ID int64 } }
	o.admin.do("GET", "/api/v1/ignore-rules?status=all", nil, &rulesBefore)
	args = map[string]any{"finding_ids": []any{float64(o.id("alpha-finding"))}, "reason": "false_positive", "note": "n",
		"scope": "everywhere", "expiry": "never"}
	text, _ = callMCPTool(t, e, bound, "ignore", args)
	_ = json.Unmarshal([]byte(text), &pv)
	args["confirm"] = pv["confirm"]
	if text, isErr := callMCPTool(t, e, bound, "ignore", args); !isErr || !strings.Contains(text, "one project") {
		t.Errorf("bound connection ignoring everywhere: %s", text)
	}
	var rulesAfter struct{ Items []struct{ ID int64 } }
	o.admin.do("GET", "/api/v1/ignore-rules?status=all", nil, &rulesAfter)
	if len(rulesAfter.Items) != len(rulesBefore.Items) {
		t.Errorf("a rule was made: %d before, %d after", len(rulesBefore.Items), len(rulesAfter.Items))
	}

	// The project is archived: the connection limited to it sees nothing.
	if code := o.admin.do("PATCH", "/api/v1/projects/"+o.s("alpha-project"), map[string]any{"archived": true}, nil); code != 200 {
		t.Fatalf("archive: %d", code)
	}
	if text, _ := callMCPTool(t, e, bound, "list_assets", map[string]any{}); strings.Contains(text, "host-alpha") {
		t.Errorf("connection to an archived project: %s", text)
	}
}

// Settings, AI assistants shows the address to add, or that assistants are
// off until STACKURITY_BASE_URL is set.
func TestAssistantsListMCPURL(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	s := e.login("admin@x.io")
	var res struct {
		Items  []map[string]any `json:"items"`
		MCPURL *string          `json:"mcp_url"`
	}
	if code := s.do("GET", "/api/v1/assistants", nil, &res); code != 200 || res.MCPURL == nil || *res.MCPURL != "" || res.Items == nil {
		t.Fatalf("without a base URL: %d %+v", code, res)
	}
	withBaseURL(e)
	if code := s.do("GET", "/api/v1/assistants", nil, &res); code != 200 || res.MCPURL == nil || *res.MCPURL != e.srv.URL+"/mcp" {
		t.Fatalf("with a base URL: %d %v", code, res.MCPURL)
	}
}
