package api_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/metrics"
	"github.com/stackurity/stackurity/internal/tenant"
)

func TestAdminHealth(t *testing.T) {
	e := newEnv(t)
	e.user("owner@x.io", auth.RoleAdmin)
	e.user("admin@x.io", auth.RoleAdmin)
	e.instanceAdmin("owner@x.io")
	owner, admin := e.login("owner@x.io"), e.login("admin@x.io")
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()),
		`INSERT INTO periodic_tasks (name, every, created_at, last_error, consecutive_failures)
		 VALUES ('alerts', '1 minute', now() - interval '1 hour', 'workspace 7: secret detail', 60)`); err != nil {
		t.Fatal(err)
	}

	if code := e.anon().do("GET", "/api/v1/admin/health", nil, nil); code != 401 {
		t.Errorf("anonymous: %d", code)
	}
	// A workspace admin must not see platform state (task errors name other workspaces).
	if code := admin.do("GET", "/api/v1/admin/health", nil, nil); code != 403 {
		t.Errorf("workspace admin: %d", code)
	}
	var tok struct {
		Secret string `json:"secret"`
	}
	if code := owner.do("POST", "/api/v1/tokens", map[string]string{"name": "agent", "role": "collector"}, &tok); code != 201 {
		t.Fatalf("collector token: %d", code)
	}
	if code := bearer(e, tok.Secret, "GET", "/api/v1/admin/health", nil, nil); code != 403 {
		t.Errorf("instance admin's collector token: %d", code)
	}
	var eng struct {
		Secret string `json:"secret"`
	}
	if code := owner.do("POST", "/api/v1/tokens", map[string]string{"name": "ci", "role": "engineer"}, &eng); code != 201 {
		t.Fatalf("engineer token: %d", code)
	}
	if code := bearer(e, eng.Secret, "GET", "/api/v1/admin/health", nil, nil); code != 403 {
		t.Errorf("instance admin's engineer token: %d", code)
	}

	var rep struct {
		Status   string
		Problems []struct{ Severity, Kind, Key, Detail string }
		Tasks    []struct{ Name string }
	}
	if code := owner.do("GET", "/api/v1/admin/health", nil, &rep); code != 200 {
		t.Fatalf("instance admin: %d", code)
	}
	found := false
	for _, p := range rep.Problems {
		if p.Kind == "task" && p.Key == "alerts" && p.Severity == "critical" && strings.Contains(p.Detail, "secret detail") {
			found = true
		}
	}
	if rep.Status != "critical" || !found || len(rep.Tasks) != 1 {
		t.Errorf("report: %+v", rep)
	}
}

// Requests are counted under their route pattern, never the raw path.
func TestHTTPMetricsUseRoutePatterns(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	admin.do("GET", "/api/v1/assets/12345", nil, nil)
	admin.do("GET", "/api/v1/assets/67890", nil, nil)
	e.anon().do("GET", "/api/v1/no/such/thing", nil, nil)
	e.anon().do("GET", "/some/dashboard/page", nil, nil)
	var b bytes.Buffer
	e.api.HTTPMetrics.Write(metrics.NewWriter(&b))
	out := b.String()
	if !strings.Contains(out, `stackurity_http_requests_total{method="GET",route="/api/v1/assets/{id}",code="4xx"} 2`) {
		t.Errorf("asset requests not grouped by pattern:\n%s", out)
	}
	for _, raw := range []string{"12345", "67890", "no/such", "dashboard"} {
		if strings.Contains(out, raw) {
			t.Errorf("raw path %q became a label:\n%s", raw, out)
		}
	}
}
