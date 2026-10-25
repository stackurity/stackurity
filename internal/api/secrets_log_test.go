package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/tenant"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestSecretsNeverLogged drives every flow that handles a credential
// (setup token, passwords, API and enrollment tokens, stored secrets, Git
// URLs with credentials) and checks that no credential appears in the
// server log (at debug level), in any API answer other than the one that
// hands it out, or in any audit entry.
func TestSecretsNeverLogged(t *testing.T) {
	e := newEnv(t)
	var logs syncBuffer
	e.api.Log = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	box, _ := secrets.NewBox([]byte("0123456789abcdef0123456789abcdef"))
	e.api.SecretBox = box

	const (
		newPassword = "N3w-Passw0rd-Secret-Value"
		wrongPass   = "Wr0ng-Passw0rd-Typed-Here"
		stored      = "ghp_StoredSecretValue123456"
		gitPass     = "gitPassw0rdInUrl"
		queryToken  = "glpatQueryTokenValue"
		bogusToken  = "stk_bogusTokenSecretValue"
	)
	var answers []string // every response body except the one-time hand-outs
	record := func(resp *http.Response) {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		answers = append(answers, string(b))
	}
	anon := e.anon()
	send := func(s *session, method, path string, body any) int {
		raw, _ := json.Marshal(body)
		resp := s.req(method, path, bytes.NewReader(raw), map[string]string{"X-Stackurity-CSRF": "1", "Content-Type": "application/json"})
		code := resp.StatusCode
		record(resp)
		return code
	}
	if code := send(anon, "POST", "/api/v1/setup", map[string]string{"setup_token": "wrong-setup-token", "email": "a@x.io", "password": pw}); code != 403 {
		t.Fatalf("setup with a wrong token: %d", code)
	}
	if code := send(anon, "POST", "/api/v1/setup", map[string]string{"setup_token": "setup-123", "email": "a@x.io", "password": pw}); code != 200 {
		t.Fatalf("setup: %d", code)
	}
	send(e.anon(), "POST", "/api/v1/auth/login", map[string]string{"email": "a@x.io", "password": wrongPass})
	send(e.anon(), "POST", "/api/v1/auth/login", map[string]string{"email": wrongPass, "password": wrongPass})
	admin := e.login("a@x.io")

	// One-time hand-outs: kept out of answers.
	var tok struct{ Secret string }
	admin.do("POST", "/api/v1/tokens", map[string]any{"name": "ci", "role": "admin"}, &tok)
	var enr struct{ Code string }
	admin.do("POST", "/api/v1/enrollments", map[string]any{"label": "web"}, &enr)
	var enrolled struct{ Token string }
	e.anon().do("POST", "/api/v1/enroll", map[string]string{"code": enr.Code, "hostname": "web-1"}, &enrolled)
	if tok.Secret == "" || enr.Code == "" || enrolled.Token == "" {
		t.Fatalf("hand-outs: %+v %+v %+v", tok, enr, enrolled)
	}

	send(admin, "PUT", "/api/v1/secrets/GH", map[string]string{"value": stored})
	send(admin, "GET", "/api/v1/secrets", nil)
	for _, u := range []string{
		"https://x-access-token:" + gitPass + "@github.com/a/b",
		"https://x-access-token:" + gitPass + "@github.com/%zz",
		"https://gitlab.example/a/b.git?private_token=" + queryToken,
	} {
		if code := send(admin, "POST", "/api/v1/integrations", map[string]any{"kind": "git_repository", "config": map[string]string{"url": u}}); code != 400 {
			t.Errorf("integration with credentials in the URL: %d", code)
		}
	}
	send(admin, "POST", "/api/v1/integrations", map[string]any{"kind": "git_repository", "config": map[string]string{"url": "https://github.com/a/b"}, "secret_ref": "secret:GH"})
	send(admin, "GET", "/api/v1/integrations", nil)
	send(admin, "POST", "/api/v1/channels", map[string]any{"kind": "slack", "name": "s", "secret_ref": "secret:GH"})
	send(admin, "GET", "/api/v1/channels", nil)
	send(admin, "POST", "/api/v1/users", map[string]any{"email": "b@x.io", "role": "viewer", "password": newPassword})
	send(admin, "POST", "/api/v1/auth/password", map[string]string{"current_password": wrongPass, "new_password": newPassword})
	send(admin, "POST", "/api/v1/auth/password", map[string]string{"current_password": pw, "new_password": newPassword})
	for _, secret := range []string{tok.Secret, enrolled.Token, bogusToken} {
		for _, path := range []string{"/api/v1/auth/me", "/api/v1/assets", "/api/v1/tokens", "/api/v1/nope"} {
			req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
			req.Header.Set("Authorization", "Bearer "+secret)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			record(resp)
		}
	}
	reauth := e.anon()
	if code := reauth.do("POST", "/api/v1/auth/login", map[string]string{"email": "a@x.io", "password": newPassword}, nil); code != 200 {
		t.Fatalf("login with the new password: %d", code)
	}
	send(reauth, "GET", "/api/v1/audit?limit=500", nil)
	send(reauth, "GET", "/api/v1/enrollments", nil)
	send(reauth, "GET", "/api/v1/tokens", nil)

	var audit []string
	rows, err := e.st.Pool.Query(tenant.System(context.Background()), `SELECT actor_name || ' ' || action || ' ' || object_id || ' ' || detail::text || ' ' || remote_addr FROM audit_events`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		audit = append(audit, s)
	}
	rows.Close()
	if len(audit) < 10 || !strings.Contains(logs.String(), `"msg":"http"`) {
		t.Fatalf("too little captured: %d audit entries, logs %q", len(audit), logs.String()[:min(200, len(logs.String()))])
	}

	for name, secret := range map[string]string{
		"password": pw, "new password": newPassword, "mistyped password": wrongPass, "setup token": "setup-123",
		"wrong setup token": "wrong-setup-token", "API token": tok.Secret, "enrollment code": enr.Code,
		"enrolled agent token": enrolled.Token, "bogus token": bogusToken, "stored secret": stored,
		"Git URL password": gitPass, "token in a Git URL query": queryToken,
	} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("%s in the server log", name)
		}
		for i, a := range answers {
			if strings.Contains(a, secret) {
				t.Errorf("%s in API answer %d: %s", name, i, a)
			}
		}
		for _, a := range audit {
			if strings.Contains(a, secret) {
				t.Errorf("%s in the audit log: %s", name, a)
			}
		}
	}
}
