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
	a := &askAPI{session: "secret-session-value"} // no server: any call that got through would panic
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
