package api_test

import (
	"context"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

func init() {
	// Your account → Active sessions (account_sessions.go). Ending one of
	// A's sessions by its ID must fail for every principal of B; the sweep
	// sends no body to revoke-others, so it never ends B's own.
	for r, rule := range map[string]routeRule{
		"GET /api/v1/auth/sessions":                {class: "account"},
		"DELETE /api/v1/auth/sessions/{id}":        {class: "object", obj: id("session")},
		"POST /api/v1/auth/sessions/revoke-others": {class: "account"},
	} {
		routeRules[r] = rule
	}
	for r, sc := range map[string]string{
		"GET /api/v1/auth/sessions":                "account",
		"DELETE /api/v1/auth/sessions/{id}":        "account",
		"POST /api/v1/auth/sessions/revoke-others": "account",
	} {
		projectScopes[r] = sc
	}
}

type sessionList struct {
	Items  []store.ActiveSession `json:"items"`
	Pinned bool                  `json:"pinned"`
}

func (s *session) cookie() string {
	u, _ := url.Parse(s.e.srv.URL + "/api/v1/")
	for _, c := range s.http.Jar.Cookies(u) {
		if c.Name == "stackurity_session" {
			return c.Value
		}
	}
	return ""
}

func loginFrom(e *env, email, userAgent, ip string) *session {
	s := e.anon()
	s.hdr = map[string]string{"User-Agent": userAgent, "CF-Connecting-IP": ip}
	if code := s.do("POST", "/api/v1/auth/login", map[string]string{"email": email, "password": pw}, nil); code != 200 {
		e.t.Fatalf("login %s: %d", email, code)
	}
	return s
}

func TestAccountSessions(t *testing.T) {
	e := newEnvWith(t, func(s *api.Server) { s.TrustProxy = true })
	e.user("ann@x.io", auth.RoleEngineer)
	e.user("bob@x.io", auth.RoleEngineer)
	laptop := loginFrom(e, "ann@x.io", "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_5) Firefox/140.0", "203.0.113.7")
	phone := loginFrom(e, "ann@x.io", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) Mobile/15E148 Safari/604.1", "198.51.100.2")
	bob := e.login("bob@x.io")

	// The list: Ann's two, this one marked, the address the trusted proxy
	// gave; nothing that signs in.
	resp := laptop.req("GET", "/api/v1/auth/sessions", nil, nil)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("list: %d %s", resp.StatusCode, raw)
	}
	for _, secret := range []string{laptop.cookie(), phone.cookie(), bob.cookie()} {
		if secret == "" || strings.Contains(string(raw), secret) {
			t.Fatalf("the list shows a session secret: %s", raw)
		}
	}
	if strings.Contains(string(raw), "token") {
		t.Errorf("the list mentions tokens: %s", raw)
	}
	var l sessionList
	laptop.do("GET", "/api/v1/auth/sessions", nil, &l)
	if len(l.Items) != 2 || l.Pinned {
		t.Fatalf("ann's sessions: %+v", l)
	}
	var this, other store.ActiveSession
	for _, a := range l.Items {
		if a.Current {
			this = a
		} else {
			other = a
		}
	}
	if this.IP != "203.0.113.7" || !strings.Contains(this.UserAgent, "Firefox") || this.LoginMethod != "password" {
		t.Errorf("this session: %+v", this)
	}
	if other.IP != "198.51.100.2" || other.Current || other.ID == "" {
		t.Errorf("the phone: %+v", other)
	}

	// Bob neither sees nor ends Ann's sessions.
	var bl sessionList
	bob.do("GET", "/api/v1/auth/sessions", nil, &bl)
	if len(bl.Items) != 1 || !bl.Items[0].Current {
		t.Fatalf("bob's sessions: %+v", bl)
	}
	if code := bob.do("DELETE", "/api/v1/auth/sessions/"+other.ID, nil, nil); code != 404 {
		t.Errorf("bob ends ann's phone: %d", code)
	}
	if code := phone.do("GET", "/api/v1/auth/me", nil, nil); code != 200 {
		t.Fatalf("ann's phone after bob's attempt: %d", code)
	}

	// A write needs the CSRF header; an API token is not a session.
	resp = laptop.req("DELETE", "/api/v1/auth/sessions/"+other.ID, nil, nil)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("without the CSRF header: %d", resp.StatusCode)
	}
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	annID := userIDByEmail(t, e, "ann@x.io")
	_, tok, err := e.st.CreateToken(ctx, "cli", auth.RoleEngineer, &annID, annID, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"GET /api/v1/auth/sessions", "DELETE /api/v1/auth/sessions/" + other.ID, "POST /api/v1/auth/sessions/revoke-others"} {
		method, path, _ := strings.Cut(m, " ")
		if code := bearer(e, tok, method, path, nil, nil); code != 403 {
			t.Errorf("%s with an API token: %d", m, code)
		}
	}

	// This session is signed out with Sign out, not by its ID.
	if code := laptop.do("DELETE", "/api/v1/auth/sessions/"+this.ID, nil, nil); code != 409 {
		t.Errorf("ending this session by ID: %d", code)
	}
	// Signing out the phone works at its very next request.
	if code := laptop.do("DELETE", "/api/v1/auth/sessions/"+other.ID, nil, nil); code != 204 {
		t.Fatalf("ending the phone: %d", code)
	}
	if code := phone.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("the phone after it was signed out: %d", code)
	}
	if code := laptop.do("DELETE", "/api/v1/auth/sessions/"+other.ID, nil, nil); code != 404 {
		t.Errorf("ending it again: %d", code)
	}

	// All others: two more sessions end, this one and Bob's stay.
	tablet := loginFrom(e, "ann@x.io", "tablet", "192.0.2.1")
	desk := loginFrom(e, "ann@x.io", "desk", "192.0.2.2")
	var out struct {
		SessionsEnded int `json:"sessions_ended"`
	}
	if code := laptop.do("POST", "/api/v1/auth/sessions/revoke-others", nil, &out); code != 200 || out.SessionsEnded != 2 {
		t.Fatalf("all others: %d %+v", code, out)
	}
	for name, s := range map[string]*session{"tablet": tablet, "desk": desk} {
		if code := s.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
			t.Errorf("%s after all others: %d", name, code)
		}
	}
	for name, s := range map[string]*session{"laptop": laptop, "bob": bob} {
		if code := s.do("GET", "/api/v1/auth/me", nil, nil); code != 200 {
			t.Errorf("%s after all others: %d", name, code)
		}
	}

	// Each is in the activity log.
	events, _, err := e.st.ListAudit(ctx, "user", itoa(annID), store.Page{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, ev := range events {
		seen[ev.Action] = string(ev.Detail)
	}
	if d, ok := seen["auth.session_revoked"]; !ok || !strings.Contains(d, other.ID) {
		t.Errorf("auth.session_revoked: %q", d)
	}
	if d, ok := seen["auth.other_sessions_revoked"]; !ok || !strings.Contains(d, `"sessions_ended": 2`) && !strings.Contains(d, `"sessions_ended":2`) {
		t.Errorf("auth.other_sessions_revoked: %q", d)
	}

	// A new session ID for the same sign-in (a new password) keeps its
	// public ID, and when and where it was signed in.
	if code := laptop.do("POST", "/api/v1/auth/password", map[string]string{"current_password": pw, "new_password": "another long passphrase"}, nil); code != 200 {
		t.Fatalf("new password: %d", code)
	}
	var after sessionList
	laptop.do("GET", "/api/v1/auth/sessions", nil, &after)
	if len(after.Items) != 1 || !after.Items[0].Current || after.Items[0].IP != "203.0.113.7" || !after.Items[0].SignedInAt.Equal(this.SignedInAt) ||
		after.Items[0].ID != this.ID {
		t.Errorf("after a new password: %+v, was %+v", after.Items, this)
	}
}

// Without a trusted proxy, the address a client claims is not recorded.
func TestAccountSessionsUntrustedAddress(t *testing.T) {
	e := newEnv(t)
	e.user("ann@x.io", auth.RoleViewer)
	s := loginFrom(e, "ann@x.io", "Mozilla/5.0", "203.0.113.7")
	var l sessionList
	if code := s.do("GET", "/api/v1/auth/sessions", nil, &l); code != 200 || len(l.Items) != 1 {
		t.Fatalf("list: %d %+v", code, l)
	}
	if ip := l.Items[0].IP; ip == "203.0.113.7" || ip == "" {
		t.Errorf("recorded address %q", ip)
	}
}

// A session pinned by an organisation's single sign-on lists and ends only
// the sessions pinned there: the identity provider vouches for that
// organisation, not for where the person signs in elsewhere.
func TestAccountSessionsPinned(t *testing.T) {
	e := newEnv(t)
	e.user("ann@x.io", auth.RoleEngineer)
	plain := e.login("ann@x.io")
	annID := userIDByEmail(t, e, "ann@x.io")
	secret, err := e.st.CreateSSOSession(context.Background(), annID, tenant.DefaultWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	pinned := e.anon()
	pinned.hdr = map[string]string{"Cookie": "stackurity_session=" + secret}
	var all, mine sessionList
	plain.do("GET", "/api/v1/auth/sessions", nil, &all)
	if len(all.Items) != 2 || all.Pinned {
		t.Fatalf("from the ordinary session: %+v", all)
	}
	if code := pinned.do("GET", "/api/v1/auth/sessions", nil, &mine); code != 200 || len(mine.Items) != 1 || !mine.Pinned || !mine.Items[0].Current ||
		mine.Items[0].LoginMethod != "sso" {
		t.Fatalf("from the pinned session: %d %+v", code, mine)
	}
	for _, a := range all.Items {
		if a.Current {
			if code := pinned.do("DELETE", "/api/v1/auth/sessions/"+a.ID, nil, nil); code != 404 {
				t.Errorf("the pinned session ends the ordinary one: %d", code)
			}
		}
	}
	var out struct {
		SessionsEnded int `json:"sessions_ended"`
	}
	if code := pinned.do("POST", "/api/v1/auth/sessions/revoke-others", nil, &out); code != 200 || out.SessionsEnded != 0 {
		t.Errorf("all others from the pinned session: %d %+v", code, out)
	}
	if code := plain.do("GET", "/api/v1/auth/me", nil, nil); code != 200 {
		t.Errorf("the ordinary session afterwards: %d", code)
	}
	// The ordinary session can end the pinned one.
	for _, a := range all.Items {
		if !a.Current {
			if code := plain.do("DELETE", "/api/v1/auth/sessions/"+a.ID, nil, nil); code != 204 {
				t.Errorf("ending the pinned session: %d", code)
			}
		}
	}
	if code := pinned.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("the pinned session after it was ended: %d", code)
	}
}
