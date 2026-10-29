package api_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
)

func init() {
	for r, rule := range map[string]routeRule{
		"POST /api/v1/auth/password-reset":         {class: "skip"},
		"POST /api/v1/auth/password-reset/preview": {class: "public", body: func(*tenantFx) any { return map[string]string{"token": "pwr_guessed"} }},
		"POST /api/v1/auth/password-reset/confirm": {class: "public", body: func(*tenantFx) any {
			return map[string]string{"token": "pwr_guessed", "new_password": pw + " new"}
		}},
	} {
		routeRules[r] = rule
	}
	for _, r := range []string{"POST /api/v1/auth/password-reset", "POST /api/v1/auth/password-reset/preview", "POST /api/v1/auth/password-reset/confirm"} {
		projectScopes[r] = "public"
	}
}

// fakeMail records what the server emails.
type fakeMail struct {
	mu   sync.Mutex
	sent []fakeMsg
	got  chan struct{}
}

type fakeMsg struct {
	to  string
	msg notify.Message
}

func newFakeMail() *fakeMail { return &fakeMail{got: make(chan struct{}, 100)} }

func (f *fakeMail) From() string { return "Stackurity <no-reply@example.test>" }

func (f *fakeMail) SendMail(_ context.Context, to []string, m notify.Message) error {
	f.mu.Lock()
	for _, t := range to {
		f.sent = append(f.sent, fakeMsg{t, m})
	}
	f.mu.Unlock()
	f.got <- struct{}{}
	return nil
}

func (f *fakeMail) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

// wait waits for one more email, or fails.
func (f *fakeMail) wait(t *testing.T) fakeMsg {
	t.Helper()
	select {
	case <-f.got:
	case <-time.After(20 * time.Second):
		t.Fatal("no email sent")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent[len(f.sent)-1]
}

// resetToken is the token in a reset email's link.
func resetToken(t *testing.T, m fakeMsg) string {
	t.Helper()
	for _, l := range m.msg.Summary {
		if i := strings.Index(l, "/reset-password#"); i >= 0 {
			return strings.Fields(l[i+len("/reset-password#"):])[0]
		}
	}
	t.Fatalf("no link in %+v", m.msg.Summary)
	return ""
}

func newResetEnv(t *testing.T) (*env, *fakeMail) {
	mail := newFakeMail()
	return newEnvWith(t, func(s *api.Server) {
		s.AccountMail = mail
		s.BaseURL = "https://stackurity.example.test"
	}), mail
}

func TestPasswordReset(t *testing.T) {
	e, mail := newResetEnv(t)
	e.user("ann@x.io", auth.RoleAdmin)
	ann := e.login("ann@x.io")
	var tok struct{ Secret string }
	ann.do("POST", "/api/v1/tokens", map[string]any{"name": "ci", "role": "viewer"}, &tok)

	var meta struct {
		PasswordReset string `json:"password_reset"`
	}
	e.anon().do("GET", "/api/v1/meta", nil, &meta)
	if meta.PasswordReset != "email" {
		t.Fatalf("meta password_reset %q", meta.PasswordReset)
	}

	// The answer is the same for an address without an account, and
	// nothing is sent to it.
	var a, b map[string]string
	if code := e.anon().do("POST", "/api/v1/auth/password-reset", map[string]string{"email": "nobody@x.io"}, &a); code != 202 {
		t.Fatalf("unknown address: %d", code)
	}
	if code := e.anon().do("POST", "/api/v1/auth/password-reset", map[string]string{"email": "ANN@x.io "}, &b); code != 202 {
		t.Fatalf("known address: %d", code)
	}
	if a["status"] != b["status"] {
		t.Errorf("answers differ: %q / %q", a, b)
	}
	m := mail.wait(t)
	if m.to != "ann@x.io" || m.msg.Title != "Reset your Stackurity password" {
		t.Fatalf("email %+v", m)
	}
	if mail.count() != 1 {
		t.Fatalf("%d emails, want only ann's", mail.count())
	}
	token := resetToken(t, m)
	if !strings.Contains(strings.Join(m.msg.Summary, " "), "https://stackurity.example.test/reset-password#pwr_") {
		t.Errorf("link not built from STACKURITY_BASE_URL: %v", m.msg.Summary)
	}

	var pv struct {
		Email  string
		Tokens int
	}
	if code := e.anon().do("POST", "/api/v1/auth/password-reset/preview", map[string]string{"token": token}, &pv); code != 200 || pv.Email != "ann@x.io" || pv.Tokens != 1 {
		t.Fatalf("preview: %d %+v", code, pv)
	}
	if code := e.anon().do("POST", "/api/v1/auth/password-reset/confirm", map[string]any{"token": token, "new_password": "short"}, nil); code != 400 {
		t.Fatalf("short password: %d", code)
	}
	var done struct{ Revoked store.Revoked }
	if code := e.anon().do("POST", "/api/v1/auth/password-reset/confirm", map[string]any{"token": token, "new_password": "a brand new passphrase"}, &done); code != 200 {
		t.Fatalf("reset: %d", code)
	}
	if done.Revoked.Sessions != 1 || done.Revoked.Tokens != 0 {
		t.Errorf("revoked %+v", done.Revoked)
	}
	// Every session ended; the token was kept (not asked to revoke).
	if code := ann.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("old session after reset: %d", code)
	}
	if code := bearer(e, tok.Secret, "GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Errorf("kept token: %d", code)
	}
	// The link works once.
	if code := e.anon().do("POST", "/api/v1/auth/password-reset/confirm", map[string]any{"token": token, "new_password": "another new passphrase"}, nil); code != 410 {
		t.Errorf("used link: %d", code)
	}
	s := e.anon()
	if code := s.do("POST", "/api/v1/auth/login", map[string]string{"email": "ann@x.io", "password": "a brand new passphrase"}, nil); code != 200 {
		t.Fatalf("sign in with the new password: %d", code)
	}

	// Revoking tokens on request; an expired link is refused.
	e.anon().do("POST", "/api/v1/auth/password-reset", map[string]string{"email": "ann@x.io"}, nil)
	token = resetToken(t, mail.wait(t))
	if code := e.anon().do("POST", "/api/v1/auth/password-reset/confirm", map[string]any{"token": token, "new_password": "third new passphrase", "revoke_tokens": true}, &done); code != 200 || done.Revoked.Tokens != 1 {
		t.Fatalf("reset revoking tokens: %d %+v", code, done.Revoked)
	}
	if code := bearer(e, tok.Secret, "GET", "/api/v1/assets", nil, nil); code != 401 {
		t.Errorf("revoked token: %d", code)
	}
	e.anon().do("POST", "/api/v1/auth/password-reset", map[string]string{"email": "ann@x.io"}, nil)
	token = resetToken(t, mail.wait(t))
	if _, err := e.st.Pool.Exec(context.Background(), `UPDATE password_resets SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if code := e.anon().do("POST", "/api/v1/auth/password-reset/confirm", map[string]any{"token": token, "new_password": "fourth new passphrase"}, nil); code != 410 {
		t.Errorf("expired link: %d", code)
	}

	// Limited per address (and per email), whether or not the account exists.
	limited := false
	for i := 0; i < 8; i++ {
		if code := e.anon().do("POST", "/api/v1/auth/password-reset", map[string]string{"email": fmt.Sprintf("x%d@x.io", i)}, nil); code == 429 {
			limited = true
		}
	}
	if !limited {
		t.Error("password reset requests are not limited per address")
	}
}

func TestPasswordResetLimitedPerEmail(t *testing.T) {
	e, _ := newResetEnv(t)
	codes := []int{}
	for i := 0; i < 4; i++ {
		s := e.anon()
		s.hdr = map[string]string{"X-Forwarded-For": fmt.Sprintf("203.0.113.%d", i)}
		codes = append(codes, s.do("POST", "/api/v1/auth/password-reset", map[string]string{"email": "who@x.io"}, nil))
	}
	// Without a trusted proxy every request has the same address, so this
	// also counts per address; the fourth is refused either way.
	if codes[3] != 429 {
		t.Errorf("fourth request for one address: %v", codes)
	}
}

// The second factor still applies after a reset: a reset is not a way
// around it.
func TestPasswordResetKeepsMFA(t *testing.T) {
	mail := newFakeMail()
	e := newMFAEnvWith(t, func(s *api.Server) {
		s.AccountMail = mail
		s.BaseURL = "https://stackurity.example.test"
	})
	e.user("bob@x.io", auth.RoleViewer)
	enrol(t, e.login("bob@x.io"))
	e.anon().do("POST", "/api/v1/auth/password-reset", map[string]string{"email": "bob@x.io"}, nil)
	token := resetToken(t, mail.wait(t))
	if code := e.anon().do("POST", "/api/v1/auth/password-reset/confirm", map[string]any{"token": token, "new_password": "a brand new passphrase"}, nil); code != 200 {
		t.Fatalf("reset: %d", code)
	}
	var out map[string]any
	e.anon().do("POST", "/api/v1/auth/login", map[string]string{"email": "bob@x.io", "password": "a brand new passphrase"}, &out)
	if out["mfa_required"] != true {
		t.Errorf("sign-in after reset did not ask for a code: %v", out)
	}
}

// Without email, the sign-in page says to ask an administrator, whose
// temporary password must be changed at the next sign-in.
func TestTemporaryPassword(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("dev@x.io", auth.RoleEngineer)
	var meta struct {
		PasswordReset string `json:"password_reset"`
	}
	e.anon().do("GET", "/api/v1/meta", nil, &meta)
	if meta.PasswordReset != "admin" {
		t.Fatalf("meta password_reset %q", meta.PasswordReset)
	}
	if code := e.anon().do("POST", "/api/v1/auth/password-reset", map[string]string{"email": "dev@x.io"}, nil); code != 404 {
		t.Fatalf("reset without email: %d", code)
	}
	admin := e.login("admin@x.io")
	var users struct{ Items []store.User }
	admin.do("GET", "/api/v1/users", nil, &users)
	var dev int64
	for _, u := range users.Items {
		if u.Email == "dev@x.io" {
			dev = u.ID
		}
	}
	temp := "temporary passphrase 1"
	if code := admin.do("PATCH", fmt.Sprintf("/api/v1/users/%d", dev), map[string]string{"password": temp}, nil); code != 200 {
		t.Fatalf("set temporary password: %d", code)
	}
	s := e.anon()
	if code := s.do("POST", "/api/v1/auth/login", map[string]string{"email": "dev@x.io", "password": temp}, nil); code != 200 {
		t.Fatalf("sign in: %d", code)
	}
	var me struct {
		PasswordChangeRequired bool `json:"password_change_required"`
	}
	s.do("GET", "/api/v1/auth/me", nil, &me)
	if !me.PasswordChangeRequired {
		t.Fatal("no password_change_required")
	}
	if code := s.do("GET", "/api/v1/assets", nil, nil); code != 403 {
		t.Fatalf("assets with a temporary password: %d", code)
	}
	if code := s.do("POST", "/api/v1/auth/password", map[string]string{"current_password": temp, "new_password": "my own passphrase"}, nil); code != 204 && code != 200 {
		t.Fatalf("change: %d", code)
	}
	if code := s.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("assets after the change: %d", code)
	}
	// An admin changing their own password is not making it temporary.
	var self struct{ User store.User }
	admin.do("GET", "/api/v1/auth/me", nil, &self)
	admin.do("PATCH", fmt.Sprintf("/api/v1/users/%d", self.User.ID), map[string]string{"password": "admin new passphrase"}, nil)
	a2 := e.anon()
	a2.do("POST", "/api/v1/auth/login", map[string]string{"email": "admin@x.io", "password": "admin new passphrase"}, nil)
	if code := a2.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Errorf("admin after setting their own password: %d", code)
	}
}
