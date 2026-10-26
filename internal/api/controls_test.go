package api_test

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/plugins"
	"github.com/stackurity/stackurity/internal/tenant"
)

// TestSessionCookieAttributes: the session cookie is HttpOnly and
// SameSite=Strict, and Secure when the server is configured for HTTPS.
func TestSessionCookieAttributes(t *testing.T) {
	for _, secure := range []bool{false, true} {
		e := newEnv(t)
		e.api.CookieSecure = secure
		e.user("a@x.io", auth.RoleAdmin)
		resp := e.anon().req("POST", "/api/v1/auth/login", strings.NewReader(`{"email":"a@x.io","password":"`+pw+`"}`),
			map[string]string{"X-Stackurity-CSRF": "1", "Content-Type": "application/json"})
		resp.Body.Close()
		var c *http.Cookie
		for _, k := range resp.Cookies() {
			if k.Name == "stackurity_session" {
				c = k
			}
		}
		if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Secure != secure || c.Path != "/" {
			t.Errorf("secure=%v: cookie %+v", secure, c)
		}
	}
}

// TestSecretsAtRest: API tokens, sessions and enrollment codes are stored
// only as hashes, passwords with argon2id, and stored secrets encrypted.
func TestSecretsAtRest(t *testing.T) {
	e := newEnv(t)
	e.user("a@x.io", auth.RoleAdmin)
	admin := e.login("a@x.io")
	var tok struct{ Secret string }
	admin.do("POST", "/api/v1/tokens", map[string]any{"name": "ci", "role": "viewer"}, &tok)
	var enr struct{ Code string }
	admin.do("POST", "/api/v1/enrollments", map[string]any{"label": "x"}, &enr)
	var session string
	for _, c := range admin.http.Jar.Cookies(mustURL(e.srv.URL)) {
		if c.Name == "stackurity_session" {
			session = c.Value
		}
	}
	if tok.Secret == "" || enr.Code == "" || session == "" {
		t.Fatalf("credentials: %q %q %q", tok.Secret, enr.Code, session)
	}
	ctx := tenant.System(context.Background())
	var dump string
	if err := e.st.Pool.QueryRow(ctx, `SELECT
		(SELECT string_agg(row_to_json(t)::text, ' ') FROM api_tokens t) || ' ' ||
		(SELECT string_agg(row_to_json(s)::text, ' ') FROM sessions s) || ' ' ||
		(SELECT string_agg(row_to_json(n)::text, ' ') FROM enrollments n) || ' ' ||
		(SELECT string_agg(row_to_json(u)::text, ' ') FROM users u)`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	for name, secret := range map[string]string{"API token": tok.Secret, "session": session, "enrollment code": enr.Code, "password": pw} {
		if strings.Contains(dump, secret) {
			t.Errorf("%s stored in clear", name)
		}
	}
	var hash string
	if err := e.st.Pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE email = 'a@x.io'`).Scan(&hash); err != nil || !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("password hash %q (%v)", hash, err)
	}
	var stored bool
	if err := e.st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM api_tokens WHERE token_hash = $1)`, auth.HashToken(tok.Secret)).Scan(&stored); err != nil || !stored {
		t.Errorf("the token's hash is not what is stored (%v)", err)
	}
}

// TestPluginsNeedCredentialsOutsideDefault: without credentials a plugin
// would use the server's own (an AWS instance role), so only a workspace
// allowed on private networks may run one without a stored secret.
func TestPluginsNeedCredentialsOutsideDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script plugin")
	}
	dir := t.TempDir()
	meta := `{"protocol_version":"1","metadata":{"id":"cloud","name":"c","version":"1","maintainer":"m","license":"MIT","schema_version":"1","permissions":[],"network_access":[],"known_limitations":[]}}`
	script := "#!/bin/sh\ncat >/dev/null\nif [ \"$1\" = metadata ]; then echo '" + meta + "'; else echo '{\"protocol_version\":\"1\",\"validation\":{\"ok\":true}}'; fi\n"
	if err := os.WriteFile(filepath.Join(dir, "cloud"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	e.api.Plugins = &plugins.Runner{Dir: dir, WorkDir: t.TempDir(), Timeout: time.Minute}
	e.user("a@x.io", auth.RoleAdmin)
	if _, _, err := e.st.CreateWorkspace(context.Background(), "Beta", "", "b@x.io", "", pw); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"kind": "plugin", "config": map[string]any{"plugin": "cloud", "config": map[string]any{}}}
	var out struct{ Error struct{ Message string } }
	if code := e.login("b@x.io").do("POST", "/api/v1/integrations", body, &out); code != 400 || !strings.Contains(out.Error.Message, "need credentials") {
		t.Errorf("plugin without credentials in another workspace: %d %+v", code, out)
	}
	if code := e.login("a@x.io").do("POST", "/api/v1/integrations", body, nil); code != 201 {
		t.Errorf("plugin without credentials in the default workspace: %d", code)
	}
}

func mustURL(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}
