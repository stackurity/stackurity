package api_test

import (
	"context"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// TestPlanHistoryWindow: on a plan with a history window, people's lists
// leave out issues resolved before it (open ones are always shown); the
// data is kept, background work still sees it, and lifting the window
// shows everything again at once.
func TestPlanHistoryWindow(t *testing.T) {
	o := newOrg(t)
	sys := tenant.System(context.Background())
	old, recent := o.id("beta-db-finding"), o.id("shared-finding")
	for id, ago := range map[int64]time.Duration{old: 40 * 24 * time.Hour, recent: 5 * 24 * time.Hour} {
		if _, err := o.e.st.Pool.Exec(sys, `UPDATE findings SET status = 'resolved', resolved_at = $2 WHERE id = $1`, id, time.Now().Add(-ago)); err != nil {
			t.Fatal(err)
		}
	}
	type list struct {
		Items []store.Finding `json:"items"`
	}
	ids := func(path string) map[int64]bool {
		t.Helper()
		var l list
		if code := o.admin.do("GET", path, nil, &l); code != 200 {
			t.Fatalf("%s: %d", path, code)
		}
		out := map[int64]bool{}
		for _, f := range l.Items {
			out[f.ID] = true
		}
		return out
	}
	if got := ids("/api/v1/findings?status=resolved"); !got[old] || !got[recent] {
		t.Fatalf("without a window: %v", got)
	}
	setPlanLimits(t, o.e, store.PlanLimits{NextPlan: "Starter", HistoryDays: 30})
	if got := ids("/api/v1/findings?status=resolved"); got[old] || !got[recent] {
		t.Errorf("30-day window: %v", got)
	}
	if got := ids("/api/v1/findings?status=all"); got[old] || !got[o.id("alpha-finding")] {
		t.Errorf("30-day window, all: open issues must stay, old resolved ones go: %v", got)
	}
	// Background work (no window on its context) still sees everything.
	fs, _, err := o.e.st.ListFindings(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace),
		store.FindingFilter{Status: "resolved", Page: store.Page{Limit: 100}})
	seen := false
	for _, f := range fs {
		seen = seen || f.ID == old
	}
	if err != nil || !seen {
		t.Errorf("background lists lost history: %v", err)
	}
	var usage store.AssetUsage
	if o.admin.do("GET", "/api/v1/usage", nil, &usage); usage.Plan == nil || usage.Plan.HistoryDays != 30 {
		t.Errorf("usage: %+v", usage.Plan)
	}
	setPlanLimits(t, o.e, store.PlanLimits{})
	if got := ids("/api/v1/findings?status=resolved"); !got[old] {
		t.Errorf("window lifted: %v", got)
	}
}
