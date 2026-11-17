package api_test

import (
	"context"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// usageCounts reads the default workspace's usage counts as event/key → n.
func usageCounts(t *testing.T, e *env) map[string]int64 {
	t.Helper()
	rows, err := e.st.Pool.Query(tenant.System(context.Background()),
		`SELECT event || '/' || key, n FROM usage_counts WHERE workspace_id = $1`, tenant.DefaultWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			t.Fatal(err)
		}
		out[k] = n
	}
	return out
}

// TestUsageCounts: teaser views and clicks and browser exports reported by
// the dashboard, plan refusals and server-side exports are counted per
// organisation and day with a fixed key only; unknown keys are ignored,
// a wrong event is refused, and signed-out requests are not counted.
func TestUsageCounts(t *testing.T) {
	e := newEnv(t)
	e.user("usage-admin@x.io", auth.RoleAdmin)
	s := e.login("usage-admin@x.io")
	post := func(event, key string) int {
		return s.do("POST", "/api/v1/usage-counts", map[string]string{"event": event, "key": key}, nil)
	}

	for _, c := range []struct{ event, key string }{
		{"teaser_view", "remediation"}, {"teaser_view", "remediation"}, {"teaser_click", "remediation"},
		{"teaser_view", "sso"}, {"export", "evidence_json"}, {"export", "outcomes_print"},
		// Not on the lists: answered 204, not stored.
		{"teaser_view", "something_else"}, {"export", "sbom_cyclonedx"}, {"teaser_view", "Remediation; DROP"},
	} {
		if code := post(c.event, c.key); code != 204 {
			t.Errorf("%s %s: %d", c.event, c.key, code)
		}
	}
	if code := post("page_view", "remediation"); code != 400 {
		t.Errorf("unknown event: %d, want 400", code)
	}
	if code := e.anon().do("POST", "/api/v1/usage-counts", map[string]string{"event": "teaser_view", "key": "teams"}, nil); code != 401 {
		t.Errorf("signed out: %d, want 401", code)
	}

	// A plan limit refusal is counted by limit kind.
	setPlanLimits(t, e, store.PlanLimits{NextPlan: "Starter", RuleLimits: map[string]int64{store.LimitAPITokens: 0}})
	if code := s.do("POST", "/api/v1/tokens", map[string]any{"name": "t1", "role": "viewer"}, nil); code != 402 {
		t.Fatalf("token over the plan: %d, want 402", code)
	}

	got := usageCounts(t, e)
	want := map[string]int64{
		"teaser_view/remediation": 2, "teaser_click/remediation": 1, "teaser_view/sso": 1,
		"export/evidence_json": 1, "export/outcomes_print": 1, "limit_refused/api_tokens": 1,
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s = %d, want %d (all: %v)", k, got[k], n, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected counts: %v", got)
	}

	// Kept per organisation and day; purge keeps today's.
	if _, err := e.st.PurgeUsageCounts(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := usageCounts(t, e)["teaser_view/remediation"]; n != 2 {
		t.Errorf("purge removed today's count: %d", n)
	}
}

// TestCountUsageRefusesBadKeys: the store refuses keys outside the table's
// pattern and ignores requests without an organisation.
func TestCountUsageRefusesBadKeys(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.st.CountUsage(ctx, tenant.DefaultWorkspace, store.UsageExport, "Bad Key"); err == nil {
		t.Error("bad key accepted")
	}
	if err := e.st.CountUsage(ctx, 0, store.UsageExport, store.ExportSBOM); err != nil {
		t.Errorf("no organisation: %v", err)
	}
}
