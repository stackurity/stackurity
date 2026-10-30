package api_test

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
)

func TestParseLegacyHosts(t *testing.T) {
	const base = "https://app.stackurity.ai"
	for _, tc := range []struct {
		list, base string
		want       []string
		bad        bool
	}{
		{"", base, nil, false},
		{" , ", "", nil, false},
		{"app.stackurity.dev", base, []string{"app.stackurity.dev"}, false},
		{" App.Stackurity.dev , old.example ,", base, []string{"app.stackurity.dev", "old.example"}, false},
		{"app.stackurity.dev", "", nil, true},
		{"app.stackurity.ai", base, nil, true},
		{"APP.stackurity.ai", base + "/", nil, true},
		{"https://app.stackurity.dev", base, nil, true},
		{"app.stackurity.dev:443", base, nil, true},
		{"app.stackurity.dev/x", base, nil, true},
		{"app stackurity.dev", base, nil, true},
		{".stackurity.dev", base, nil, true},
	} {
		got, err := api.ParseLegacyHosts(tc.list, tc.base)
		if (err != nil) != tc.bad || fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("ParseLegacyHosts(%q, %q) = %v, %v", tc.list, tc.base, got, err)
		}
	}
}

// legacyDo sends a request with Host set to host and does not follow
// redirects.
func legacyDo(t *testing.T, e *env, method, host, path, auth string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func TestLegacyHosts(t *testing.T) {
	e := newEnvWith(t, func(s *api.Server) {
		s.UI = fstest.MapFS{"index.html": {Data: []byte("<!doctype html>dashboard")}, "static/app.js": {Data: []byte("x")}}
	})
	withBaseURL(e)
	e.api.LegacyHosts = []string{"app.old.example"}
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.signIn("admin@x.io")
	base := e.srv.URL

	// Dashboard pages on the old host move to the base URL, query kept.
	for _, tc := range []struct{ method, host, path, want string }{
		{"GET", "app.old.example", "/", base + "/"},
		{"GET", "APP.old.example:443", "/findings?status=open&q=a%20b", base + "/findings?status=open&q=a%20b"},
		{"HEAD", "app.old.example", "/reset-password", base + "/reset-password"},
		{"GET", "app.old.example", "/oauth/authorize?client_id=c&state=s", base + "/oauth/authorize?client_id=c&state=s"},
		{"GET", "app.old.example", "/static/app.js", base + "/static/app.js"},
		{"GET", "app.old.example", "//evil.example/x", base + "//evil.example/x"},
	} {
		resp := legacyDo(t, e, tc.method, tc.host, tc.path, "", "")
		if resp.StatusCode != 301 || resp.Header.Get("Location") != tc.want {
			t.Errorf("%s %s%s: %d %q, want 301 %q", tc.method, tc.host, tc.path, resp.StatusCode, resp.Header.Get("Location"), tc.want)
		}
	}
	// The base URL's host and other hosts are served.
	for _, host := range []string{strings.TrimPrefix(base, "http://"), "other.example"} {
		if resp := legacyDo(t, e, "GET", host, "/findings", "", ""); resp.StatusCode != 200 {
			t.Errorf("GET %s/findings: %d", host, resp.StatusCode)
		}
	}

	// Everything else on the old host is served in place: the API (with a
	// token, as agents and CI call it), health, discovery, /mcp.
	var created struct {
		Secret string `json:"secret"`
	}
	if code := admin.do("POST", "/api/v1/tokens", map[string]any{"name": "ci", "role": auth.RoleViewer}, &created); code != 201 {
		t.Fatalf("create token: %d", code)
	}
	tok := created.Secret
	for _, tc := range []struct{ method, path, auth string }{
		{"GET", "/api/v1/meta", ""},
		{"GET", "/api/v1/findings", "Bearer " + tok},
		{"GET", "/healthz", ""},
		{"GET", "/install/agent.sh", ""},
		{"GET", "/.well-known/oauth-authorization-server", ""},
		{"GET", "/.well-known/oauth-protected-resource/mcp", ""},
	} {
		if resp := legacyDo(t, e, tc.method, "app.old.example", tc.path, tc.auth, ""); resp.StatusCode != 200 {
			t.Errorf("%s %s on the old host: %d", tc.method, tc.path, resp.StatusCode)
		}
	}
	if resp := legacyDo(t, e, "POST", "app.old.example", "/mcp", "Bearer "+tok, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); resp.StatusCode != 200 {
		t.Errorf("POST /mcp on the old host: %d", resp.StatusCode)
	}
	// A POST to a page path is not redirected (a 301 would turn it into a GET).
	if resp := legacyDo(t, e, "POST", "app.old.example", "/findings", "", "{}"); resp.StatusCode == 301 {
		t.Errorf("POST on the old host redirected")
	}

	// An assistant connected through the old host refreshes its token
	// naming the old resource; other hosts are still refused.
	o := registerAssistant(t, e)
	v, c := pkcePair(fmt.Sprint(time.Now().UnixNano() % 1000000))
	_, refresh := o.exchange(t, o.authorize(t, admin, c, auth.RoleViewer, 0), v)
	for _, res := range []string{"http://app.old.example/mcp", "HTTP://APP.OLD.EXAMPLE/mcp/", "http://app.old.example"} {
		status, out := o.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "resource": {res}})
		if status != 200 {
			t.Fatalf("refresh with resource %s: %d %v", res, status, out)
		}
		refresh = out["refresh_token"].(string)
	}
	for _, res := range []string{"http://other.example/mcp", "https://app.old.example/mcp", "http://app.old.example/other"} {
		if status, out := o.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "resource": {res}}); status != 400 || out["error"] != "invalid_target" {
			t.Errorf("refresh with resource %s: %d %v", res, status, out)
		}
	}

	// Without legacy hosts the old host is an ordinary host.
	e.api.LegacyHosts = nil
	if resp := legacyDo(t, e, "GET", "app.old.example", "/findings", "", ""); resp.StatusCode != 200 {
		t.Errorf("GET without legacy hosts: %d", resp.StatusCode)
	}
	if status, _ := o.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "resource": {"http://app.old.example/mcp"}}); status != 400 {
		t.Errorf("refresh with the old resource and no legacy hosts: %d", status)
	}
}
