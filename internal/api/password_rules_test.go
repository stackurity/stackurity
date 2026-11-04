package api_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
)

type weakAnswer struct {
	Error struct {
		Code    string
		Message string
		Details []string
	}
}

// expectWeak sends a password that breaks the rules and wants 400
// password_too_weak naming exactly what is missing.
func expectWeak(t *testing.T, what string, send func(password string, out any) int) {
	t.Helper()
	for pw, want := range map[string]struct {
		msg     string
		details []string
	}{
		"abcdefghijk1":   {"Add an uppercase letter and a symbol.", []string{"uppercase", "symbol"}},
		"Sh0rt!":         {"Use at least 12 characters.", []string{"length"}},
		"Nodigits here!": {"Add a digit.", []string{"digit"}},
	} {
		var out weakAnswer
		if code := send(pw, &out); code != 400 || out.Error.Code != "password_too_weak" || out.Error.Message != want.msg ||
			!reflect.DeepEqual(out.Error.Details, want.details) {
			t.Errorf("%s with %q: %d %+v, want 400 password_too_weak %q %v", what, pw, code, out, want.msg, want.details)
		}
	}
}

// Every request that sets a password applies the rules; a password set
// before them keeps working.
func TestWeakPasswordsRefused(t *testing.T) {
	e, mail := newResetEnv(t)
	expectWeak(t, "setup", func(p string, out any) int {
		return e.anon().do("POST", "/api/v1/setup", map[string]string{"setup_token": "setup-123", "email": "first@x.io", "password": p}, out)
	})
	e.user("admin@x.io", auth.RoleAdmin)
	e.instanceAdmin("admin@x.io")
	admin := e.login("admin@x.io")

	expectWeak(t, "change own password", func(p string, out any) int {
		return admin.do("POST", "/api/v1/auth/password", map[string]string{"current_password": pw, "new_password": p}, out)
	})
	expectWeak(t, "new user", func(p string, out any) int {
		return admin.do("POST", "/api/v1/users", map[string]any{"email": "new@x.io", "role": "viewer", "password": p}, out)
	})
	e.user("member@x.io", auth.RoleViewer)
	var users struct{ Items []store.User }
	admin.do("GET", "/api/v1/users", nil, &users)
	var member int64
	for _, u := range users.Items {
		if u.Email == "member@x.io" {
			member = u.ID
		}
	}
	expectWeak(t, "admin sets a password", func(p string, out any) int {
		return admin.do("PATCH", fmt.Sprintf("/api/v1/users/%d", member), map[string]string{"password": p}, out)
	})
	var proj struct{ ID int64 }
	if code := admin.do("POST", "/api/v1/projects", map[string]any{"name": "shop"}, &proj); code != 201 {
		t.Fatalf("project: %d", code)
	}
	expectWeak(t, "project access for a new account", func(p string, out any) int {
		return admin.do("POST", "/api/v1/access-grants", map[string]any{"project_id": proj.ID, "email": "guest@x.io", "role": "viewer", "password": p}, out)
	})
	expectWeak(t, "new workspace", func(p string, out any) int {
		return admin.do("POST", "/api/v1/admin/workspaces", map[string]any{"name": "Gamma Ltd", "admin_email": "gamma@x.io", "admin_password": p}, out)
	})

	// Reset link.
	if code := e.anon().do("POST", "/api/v1/auth/password-reset", map[string]string{"email": "member@x.io"}, nil); code != 202 {
		t.Fatalf("reset: %d", code)
	}
	token := resetToken(t, mail.wait(t))
	expectWeak(t, "reset", func(p string, out any) int {
		return e.anon().do("POST", "/api/v1/auth/password-reset/confirm", map[string]any{"token": token, "new_password": p}, out)
	})
	// The link is not spent by a refused password.
	if code := e.anon().do("POST", "/api/v1/auth/password-reset/confirm", map[string]any{"token": token, "new_password": "Velvet otter lamp 82!"}, nil); code != 200 {
		t.Errorf("reset with a good password: %d", code)
	}

	// A password set before the rules keeps working: the sign-in does not
	// check it against them.
	weak := "old weak password"
	hash, err := auth.HashPassword(weak)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool.Exec(t.Context(), `UPDATE users SET password_hash = $1 WHERE email = 'member@x.io'`, hash); err != nil {
		t.Fatal(err)
	}
	if code := e.anon().do("POST", "/api/v1/auth/login", map[string]string{"email": "member@x.io", "password": weak}, nil); code != 200 {
		t.Errorf("sign-in with a password set before the rules: %d", code)
	}
}
