package api_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// sessionCookie is the session cookie s holds.
func sessionCookie(t *testing.T, s *session) string {
	t.Helper()
	u, _ := url.Parse(s.e.srv.URL)
	for _, c := range s.http.Jar.Cookies(u) {
		if c.Name == "stackurity_session" {
			return c.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

// withCookie is a client that sends only the given session cookie.
func withCookie(e *env, secret string) *session {
	s := &session{e: e, http: &http.Client{}}
	s.hdr = map[string]string{"Cookie": "stackurity_session=" + secret}
	return s
}

func TestSessionIdleAndAbsoluteExpiry(t *testing.T) {
	e := newEnv(t)
	e.st.SessionIdle = 30 * time.Minute
	e.user("ann@x.io", auth.RoleAdmin)
	ctx := context.Background()

	idle := e.login("ann@x.io")
	if code := idle.do("GET", "/api/v1/auth/me", nil, nil); code != 200 {
		t.Fatalf("fresh session: %d", code)
	}
	if _, err := e.st.Pool.Exec(ctx, `UPDATE sessions SET last_seen_at = now() - interval '31 minutes'`); err != nil {
		t.Fatal(err)
	}
	if code := idle.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Fatalf("idle session: %d", code)
	}

	// Used now and then, a session lives until its 12 hours are up.
	abs := e.login("ann@x.io")
	if _, err := e.st.Pool.Exec(ctx, `UPDATE sessions SET last_seen_at = now() - interval '29 minutes'`); err != nil {
		t.Fatal(err)
	}
	if code := abs.do("GET", "/api/v1/auth/me", nil, nil); code != 200 {
		t.Fatalf("active session: %d", code)
	}
	if _, err := e.st.Pool.Exec(ctx, `UPDATE sessions SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if code := abs.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Fatalf("session past 12 hours: %d", code)
	}

	// One nobody comes back to is ended by housekeeping, and recorded too.
	e.login("ann@x.io")
	if _, err := e.st.Pool.Exec(ctx, `UPDATE sessions SET last_seen_at = now() - interval '2 hours'`); err != nil {
		t.Fatal(err)
	}
	if err := e.st.PurgeExpiredSessions(ctx); err != nil {
		t.Fatal(err)
	}
	var reasons []string
	rows, err := e.st.Pool.Query(tenant.System(ctx), `SELECT detail->>'reason' FROM audit_events WHERE action = 'auth.session_expired' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var r string
		_ = rows.Scan(&r)
		reasons = append(reasons, r)
	}
	if len(reasons) != 3 || reasons[0] != "idle" || reasons[1] != "absolute" || reasons[2] != "idle" {
		t.Errorf("session_expired events %v, want idle, absolute, idle", reasons)
	}

	// Signing out is recorded.
	out := e.login("ann@x.io")
	if code := out.do("POST", "/api/v1/auth/logout", nil, nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	if !auditActions(t, e, e.login("ann@x.io"))["auth.logout"] {
		t.Error("no auth.logout event")
	}
}

// Signing in always gives a new session ID and ends the one the browser
// had (a planted session cannot be carried into a sign-in).
func TestSessionRotation(t *testing.T) {
	e := newEnv(t)
	e.user("ann@x.io", auth.RoleAdmin)
	s := e.login("ann@x.io")
	before := sessionCookie(t, s)
	if code := s.do("POST", "/api/v1/auth/login", map[string]string{"email": "ann@x.io", "password": pw}, nil); code != 200 {
		t.Fatalf("second login: %d", code)
	}
	after := sessionCookie(t, s)
	if after == before {
		t.Fatal("sign-in kept the session ID")
	}
	if code := withCookie(e, before).do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("previous session after a new sign-in: %d", code)
	}

	// A password change rotates the current session too.
	if code := s.do("POST", "/api/v1/auth/password", map[string]string{"current_password": pw, "new_password": "another long passphrase"}, nil); code != 200 {
		t.Fatalf("change: %d", code)
	}
	if sessionCookie(t, s) == after {
		t.Error("password change kept the session ID")
	}
	if code := withCookie(e, after).do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("old session ID after a password change: %d", code)
	}
	if code := s.do("GET", "/api/v1/auth/me", nil, nil); code != 200 {
		t.Errorf("current session after a password change: %d", code)
	}
}

// A password change ends the other sessions and disconnects assistants by
// default, keeps API tokens (and says how many), and revokes them when asked.
func TestPasswordChangeRevocation(t *testing.T) {
	e := newEnv(t)
	e.user("ann@x.io", auth.RoleAdmin)
	s, other := e.login("ann@x.io"), e.login("ann@x.io")
	var tok struct{ Secret string }
	s.do("POST", "/api/v1/tokens", map[string]any{"name": "ci", "role": "viewer"}, &tok)
	o := registerAssistant(t, e)
	access := o.connect(t, s, auth.RoleViewer, 0)
	if code, _, _ := mcpPost(e, access, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}); code != 200 {
		t.Fatalf("assistant before: %d", code)
	}

	var res struct {
		Revoked    store.Revoked
		TokensKept int `json:"tokens_kept"`
	}
	if code := s.do("POST", "/api/v1/auth/password", map[string]string{"current_password": pw, "new_password": "another long passphrase"}, &res); code != 200 {
		t.Fatalf("change: %d", code)
	}
	if res.Revoked.Sessions != 1 || res.Revoked.Assistants != 1 || res.Revoked.Tokens != 0 || res.TokensKept != 1 {
		t.Errorf("answer %+v", res)
	}
	if code := other.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("other session: %d", code)
	}
	if code, _, _ := mcpPost(e, access, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}); code != 401 {
		t.Errorf("assistant after a password change: %d", code)
	}
	if code := bearer(e, tok.Secret, "GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Errorf("kept token: %d", code)
	}

	if code := s.do("POST", "/api/v1/auth/password", map[string]any{"current_password": "another long passphrase", "new_password": "a third long passphrase",
		"revoke_tokens": true}, &res); code != 200 || res.Revoked.Tokens != 1 || res.TokensKept != 0 {
		t.Fatalf("change revoking tokens: %d %+v", code, res)
	}
	if code := bearer(e, tok.Secret, "GET", "/api/v1/assets", nil, nil); code != 401 {
		t.Errorf("revoked token: %d", code)
	}
}
