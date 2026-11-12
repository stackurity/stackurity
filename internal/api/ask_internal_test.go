package api

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// askAPI only reads, and only the paths the read-only tools use: anything
// else is refused before it reaches the router.
func TestAskAPIRefusesBeforeTheRouter(t *testing.T) {
	a := &askAPI{session: "secret-session-value", workspace: 1} // no server: any call that got through would panic
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/findings/1/snooze"},
		{"PUT", "/api/v1/findings?x=1"},
		{"DELETE", "/api/v1/assets/1"},
		{"GET", "/api/v1/tokens"},
		{"GET", "/api/v1/users"},
		{"GET", "/api/v1/ask/conversations"},
		{"GET", "/api/v1/findings/1/../../tokens"},
		{"GET", "https://evil.example/api/v1/findings?"},
		{"GET", "/mcp"},
	} {
		err := a.Do(context.Background(), c.method, c.path, nil, nil, nil)
		if !errors.Is(err, errAskPath) {
			t.Errorf("%s %s: %v", c.method, c.path, err)
		}
		if err != nil && strings.Contains(err.Error(), "secret-session-value") {
			t.Errorf("%s %s: the error shows the session", c.method, c.path)
		}
	}
	if viaAsk(context.Background()) {
		t.Error("a plain context is marked as Ask's")
	}
}

// The apply endpoint's API reaches only the calls of the proposable tools:
// never users, roles, MFA, tokens, SSO, billing, invitations, install
// codes, deletes or disconnects. The model's own API stays GET-only with
// proposals on.
func TestAskActingAPIRoutes(t *testing.T) {
	for _, c := range []struct {
		method, path string
		ok           bool
	}{
		{"POST", "/api/v1/findings/actions", true},
		{"POST", "/api/v1/ignore-requests", true},
		{"POST", "/api/v1/assets/12/check", true},
		{"POST", "/api/v1/fix-groups/3:package_upgrade:1/check", true},
		{"POST", "/api/v1/projects/4/assets", true},
		{"PATCH", "/api/v1/projects/4", true},
		{"GET", "/api/v1/auth/me", true},
		{"DELETE", "/api/v1/projects/4/assets", false},
		{"DELETE", "/api/v1/assets/12", false},
		{"POST", "/api/v1/projects", false},
		{"POST", "/api/v1/invitations", false},
		// A server hand-off's Apply creates one install code (askApplyEnrollment).
		{"POST", "/api/v1/enrollments", true},
		{"DELETE", "/api/v1/enrollments/1", false},
		{"POST", "/api/v1/enrollments?fleet=1", false},
		{"POST", "/api/v1/tokens", false},
		{"PATCH", "/api/v1/users/3", false},
		{"POST", "/api/v1/auth/mfa/step-up", false},
		{"PUT", "/api/v1/ask/settings", false},
		{"POST", "/api/v1/ask/conversations/1/proposals/1/apply", false},
		{"PATCH", "/api/v1/projects/4/../../users/1", false},
		{"POST", "/api/v1/findings/actions?x=1", false},
	} {
		if got := askActAllowed(c.method, c.path); got != c.ok {
			t.Errorf("%s %s: allowed %v, want %v", c.method, c.path, got, c.ok)
		}
	}
	a := &askAPI{session: "s", workspace: 1, propose: true}
	for _, p := range []string{"/api/v1/findings/actions", "/api/v1/projects/4"} {
		for _, m := range []string{"POST", "PATCH", "DELETE"} {
			if err := a.Do(context.Background(), m, p, nil, nil, nil); !errors.Is(err, errAskPath) {
				t.Errorf("the model's API with proposals on: %s %s = %v", m, p, err)
			}
		}
	}
	if err := a.Do(context.Background(), "GET", "/api/v1/tokens", nil, nil, nil); !errors.Is(err, errAskPath) {
		t.Errorf("GET tokens with proposals on: %v", err)
	}
}
