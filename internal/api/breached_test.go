package api_test

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
)

// A password in known breaches is refused wherever one is chosen; only a
// five-character prefix of its SHA-1 is sent; an unreachable service does
// not stop anyone.
func TestBreachedPasswordsRefused(t *testing.T) {
	const breached = "Password1234!"
	sum := sha1.Sum([]byte(breached))
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var calls atomic.Int32
	var badPrefix atomic.Bool
	hibp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if len(strings.TrimPrefix(r.URL.Path, "/range/")) != 5 {
			badPrefix.Store(true)
		}
		fmt.Fprintf(w, "%s:12345\r\n", h[5:])
	}))
	defer hibp.Close()
	e := newEnvWith(t, func(s *api.Server) { s.Breached = &auth.BreachChecker{URL: hibp.URL + "/range/"} })
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	var out struct{ Error struct{ Message string } }
	code := admin.do("POST", "/api/v1/auth/password", map[string]string{"current_password": pw, "new_password": breached}, &out)
	if code != 400 || !strings.Contains(out.Error.Message, "data breaches") {
		t.Fatalf("change to a breached password: %d %+v", code, out)
	}
	if code := admin.do("POST", "/api/v1/users", map[string]any{"email": "n@x.io", "role": "viewer", "password": breached}, nil); code != 400 {
		t.Errorf("new user with a breached password: %d", code)
	}
	var me struct{ User store.User }
	admin.do("GET", "/api/v1/auth/me", nil, &me)
	if code := admin.do("PATCH", fmt.Sprintf("/api/v1/users/%d", me.User.ID), map[string]string{"password": breached}, nil); code != 400 {
		t.Errorf("admin sets a breached password: %d", code)
	}
	if code := admin.do("POST", "/api/v1/auth/password", map[string]string{"current_password": pw, "new_password": "not in any list at all"}, nil); code != 204 {
		t.Errorf("change to a fine password: %d", code)
	}
	if calls.Load() == 0 || badPrefix.Load() {
		t.Errorf("calls %d, a request sent more than the prefix: %v", calls.Load(), badPrefix.Load())
	}

	// Unreachable: accepted (and logged).
	hibp.Close()
	if code := admin.do("POST", "/api/v1/auth/password", map[string]string{"current_password": "not in any list at all", "new_password": breached}, nil); code != 204 {
		t.Errorf("check unreachable: %d, want the password accepted", code)
	}
}
