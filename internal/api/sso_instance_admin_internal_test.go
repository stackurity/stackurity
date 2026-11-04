package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// TestSSOSessionNeverInstanceAdmin: single sign-on is exempt from the
// two-factor policy, so a session it started never has instance-admin
// powers, even when the account was made an instance administrator by
// SQL while linked (which UpdateUserInstanceAdmin refuses): no server-wide
// routes, and no API token that carries them. A password session of the
// same account keeps them.
func TestSSOSessionNeverInstanceAdmin(t *testing.T) {
	st := store.New(testdb.New(t))
	bg := context.Background()
	ws1 := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	u, err := st.CreateUser(ws1, "linked@acme.io", "", auth.RoleAdmin, "Correct horse battery 1!")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(tenant.System(bg), `UPDATE users SET oidc_issuer = 'https://idp.acme.io', oidc_subject = 'u-1',
		instance_admin = true WHERE id = $1`, u.ID); err != nil {
		t.Fatal(err)
	}
	holder := &license.Holder{}
	s := &Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Licence: holder, Gate: &license.Gate{Licence: holder}}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	call := func(session, token, method, path, body string) (int, []byte) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if session != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
			req.Header.Set("X-Stackurity-CSRF", "1")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}

	sso, err := st.CreateSessionWith(bg, u.ID, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginSSO})
	if err != nil {
		t.Fatal(err)
	}
	if status, b := call(sso, "", "GET", "/api/v1/admin/workspaces", ""); status != 403 {
		t.Errorf("SSO session of an instance admin on admin routes: %d %s", status, b)
	}
	// Nor does it make a token, which would carry the account's powers.
	status, b := call(sso, "", "POST", "/api/v1/tokens", `{"name":"ops","role":"admin","ttl_hours":0}`)
	if status != 403 || !strings.Contains(string(b), "instance administrators sign in with their password and second factor") {
		t.Errorf("token from an SSO session of an instance admin: %d %s", status, b)
		var created struct {
			Secret string `json:"secret"`
		}
		if json.Unmarshal(b, &created) == nil && created.Secret != "" {
			if status, _ := call("", created.Secret, "GET", "/api/v1/admin/workspaces", ""); status != 403 {
				t.Errorf("and the token has instance-admin powers: %d", status)
			}
		}
	}
	// A pinned session (an organisation's own single sign-on) is held the
	// same way.
	pinned, err := st.CreateSSOSession(bg, u.ID, tenant.DefaultWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	if status, b := call(pinned, "", "POST", "/api/v1/tokens", `{"name":"ops2","role":"admin","ttl_hours":0}`); status != 403 {
		t.Errorf("token from a pinned session of an instance admin: %d %s", status, b)
	}
	// An SSO session of an account that is not an instance admin still
	// makes tokens.
	if _, err := st.Pool.Exec(tenant.System(bg), `UPDATE users SET instance_admin = false WHERE id = $1`, u.ID); err != nil {
		t.Fatal(err)
	}
	secretOf := func(b []byte) string {
		var created struct {
			Secret string `json:"secret"`
		}
		_ = json.Unmarshal(b, &created)
		return created.Secret
	}
	status, b = call(sso, "", "POST", "/api/v1/tokens", `{"name":"ops3","role":"admin","ttl_hours":0}`)
	if status != 201 {
		t.Fatalf("token from an SSO session of an ordinary admin: %d %s", status, b)
	}
	early := secretOf(b)
	// Made an instance admin by SQL afterwards: that token gains nothing
	// while the account is linked.
	if _, err := st.Pool.Exec(tenant.System(bg), `UPDATE users SET instance_admin = true WHERE id = $1`, u.ID); err != nil {
		t.Fatal(err)
	}
	if status, b := call("", early, "GET", "/api/v1/admin/workspaces", ""); status != 403 {
		t.Errorf("token minted before the promotion, account linked: %d %s", status, b)
	}
	if status, _ := call("", early, "GET", "/api/v1/auth/me", ""); status != 200 {
		t.Errorf("the token's ordinary use: %d", status)
	}

	// The same account's password session keeps the role (the policy is
	// optional here).
	pw, err := st.CreateSessionWith(bg, u.ID, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginPassword})
	if err != nil {
		t.Fatal(err)
	}
	if status, b := call(pw, "", "GET", "/api/v1/admin/workspaces", ""); status != 200 {
		t.Errorf("password session of an instance admin: %d %s", status, b)
	}
	// A token it makes while the account is still linked has no
	// instance-admin powers either (the documented rule: remove the link
	// first); once the link is removed, the same token has them.
	status, b = call(pw, "", "POST", "/api/v1/tokens", `{"name":"ops4","role":"admin","ttl_hours":0}`)
	if status != 201 {
		t.Fatalf("token from a password session: %d %s", status, b)
	}
	fromPassword := secretOf(b)
	if status, b := call("", fromPassword, "GET", "/api/v1/admin/workspaces", ""); status != 403 {
		t.Errorf("password-session token of a linked instance admin: %d %s", status, b)
	}
	if _, err := st.Pool.Exec(tenant.System(bg), `UPDATE users SET oidc_issuer = NULL, oidc_subject = NULL WHERE id = $1`, u.ID); err != nil {
		t.Fatal(err)
	}
	if status, b := call("", fromPassword, "GET", "/api/v1/admin/workspaces", ""); status != 200 {
		t.Errorf("password-session token after the link is removed: %d %s", status, b)
	}
}
