//go:build !windows

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

// ciCommunityKey is the free Community key the ui job of CI uses
// (.github/workflows/ci.yml, "Stackurity CI"): signed by the free-key
// issuer, it unlocks nothing paid.
const ciCommunityKey = "eyJ2IjoxLCJpZCI6ImNrX2NiY2Q1ZDk3YTkzMmRlNmIiLCJjdXN0b21lciI6IlN0YWNrdXJpdHkgQ0kiLCJuYW1lIjoiU3RhY2t1cml0eSBDSSIsImVkaXRpb24iOiJjb21tdW5pdHkiLCJtYXhfYXNzZXRzIjowLCJpc3N1ZWRfYXQiOiIyMDI2LTExLTAxVDE3OjQ4OjIwWiIsImV4cGlyZXNfYXQiOiIyMTI2LTEwLTA4VDE3OjQ4OjIwWiJ9.ZwnzCfVB4Yt_o-o4ziglboCXWIrZhkIp_kgnNyysRZXmfnRcsw9SFkZmoy2GokuMc62J8z_5NeM9jKIiV6FiCQ"

// "Get a free key" on the real server (the same wiring as `stackurity
// server`): from setting up the first administrator to the key installed
// and the dashboard open, the server connects to nothing. The browser's
// trip to Stackurity Cloud is the only network step, and it is not the
// server's.
func TestNoEgressForKeyLink(t *testing.T) {
	g := installGuard(t)
	if editionEnv != nil {
		t.Skip("Stackurity Cloud needs no key")
	}
	s := startServer(t, map[string]string{
		"STACKURITY_FEEDS": "off", "STACKURITY_UPDATE_CHECK": "off", "STACKURITY_BREACHED_PASSWORD_CHECK": "off",
		"STACKURITY_BASE_URL": "http://stackurity.internal.example:8080", "STACKURITY_COOKIE_SECURE": "false",
		"STACKURITY_SETUP_TOKEN": "egress-keylink-setup-token",
	})
	s.settle(t)

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	call := func(method, path string, body any, out any) int {
		t.Helper()
		var rd *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		} else {
			rd = bytes.NewReader(nil)
		}
		req, _ := http.NewRequest(method, "http://"+s.addr+path, rd)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Stackurity-CSRF", "1")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		if out != nil {
			_ = json.NewDecoder(resp.Body).Decode(out)
		}
		return resp.StatusCode
	}
	if code := call("POST", "/api/v1/setup", map[string]string{"setup_token": "egress-keylink-setup-token",
		"email": "admin@example.com", "name": "Admin", "password": "a long and unusual passphrase 7"}, nil); code/100 != 2 {
		t.Fatalf("setup: %d", code)
	}
	if code := call("GET", "/api/v1/assets", nil, nil); code != 403 {
		t.Fatalf("a new install should wait for its key: GET /assets %d", code)
	}

	var link struct {
		URL string `json:"url"`
	}
	if code := call("POST", "/api/v1/admin/license/link", map[string]any{}, &link); code != 201 {
		t.Fatalf("start: %d", code)
	}
	u, err := url.Parse(link.URL)
	frag, _ := url.ParseQuery(u.Fragment)
	if err != nil || u.Host != "app.stackurity.dev" || u.RawQuery != "" || frag.Get("return") != "http://stackurity.internal.example:8080" {
		t.Fatalf("link: %q", link.URL)
	}
	// Stackurity Cloud sends the browser back with the key; the page posts
	// it with the state.
	if code := call("POST", "/api/v1/admin/license/link/claim", map[string]string{"key": ciCommunityKey, "state": frag.Get("state")}, nil); code != 200 {
		t.Fatalf("claim: %d", code)
	}
	if code := call("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Errorf("with the key installed: GET /assets %d", code)
	}
	s.settle(t)

	if got := g.attempts(); len(got) > 0 {
		t.Errorf("getting the free key in one click made the server connect out; recorded:\n%s", list(got))
	}
	if strings.Contains(link.URL, "admin@example.com") {
		t.Errorf("the link carries the administrator's email: %q", link.URL)
	}
}
