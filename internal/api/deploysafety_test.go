package api_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/tenant"
)

// When a newer version migrates the database under a running server (an
// upgrade that started new replicas before stopping this one), /readyz fails
// with the reason so orchestrators stop routing to it, and Platform health
// shows a critical problem.
func TestReadyzFailsOnNewerSchema(t *testing.T) {
	e := newEnv(t)
	guard := &db.SchemaGuard{}
	e.api.Schema = guard
	e.api.Health.Schema = guard
	e.user("owner@x.io", auth.RoleAdmin)
	e.instanceAdmin("owner@x.io")
	owner := e.login("owner@x.io")
	ctx := tenant.System(context.Background())

	if code := e.anon().do("GET", "/readyz", nil, nil); code != 200 {
		t.Fatalf("readyz before: %d", code)
	}
	if err := guard.Check(ctx, e.st.Pool); err != nil {
		t.Fatal(err)
	}
	if code := e.anon().do("GET", "/readyz", nil, nil); code != 200 {
		t.Fatalf("readyz after a check of a current schema: %d", code)
	}

	if _, err := e.st.Pool.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ('9999_from_a_newer_release')`); err != nil {
		t.Fatal(err)
	}
	if err := guard.Check(ctx, e.st.Pool); err == nil {
		t.Fatal("check did not find the newer schema")
	}
	var out struct {
		Error struct{ Code, Message string }
	}
	if code := e.anon().do("GET", "/readyz", nil, &out); code != 503 {
		t.Fatalf("readyz with a newer schema: %d, want 503", code)
	}
	if out.Error.Code != "schema_newer" || !strings.Contains(out.Error.Message, "upgraded by a newer Stackurity") {
		t.Errorf("readyz error: %+v", out.Error)
	}
	// Liveness is unaffected: the process is fine, it must just not serve.
	if code := e.anon().do("GET", "/healthz", nil, nil); code != 200 {
		t.Errorf("healthz: %d", code)
	}

	var rep struct {
		Status   string
		Problems []struct{ Severity, Kind, Key, Title string }
	}
	if code := owner.do("GET", "/api/v1/admin/health", nil, &rep); code != 200 {
		t.Fatalf("health: %d", code)
	}
	found := false
	for _, p := range rep.Problems {
		found = found || p.Kind == "schema" && p.Severity == "critical"
	}
	if !found || rep.Status != "critical" {
		t.Errorf("health report: %+v", rep)
	}
}
