package api_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// TestDashboardTrend: the SLA split counts active findings by fix-by date,
// and the 30-day trend is worked back from today's open count through the
// matcher's events, with fixes counted per week.
func TestDashboardTrend(t *testing.T) {
	e := newEnv(t)
	e.user("viewer@x.io", auth.RoleViewer)
	viewer := e.login("viewer@x.io")
	ws := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)

	b := model.NewBatch(model.Collector{ID: "t", Method: "test"},
		model.AssetRef{Kind: model.AssetRepository, Name: "web", Identifiers: []model.Identifier{{Scheme: "test", Value: "web"}}})
	for _, p := range []string{"a@1.0.0", "b@1.0.0", "c@1.0.0", "d@1.0.0"} {
		b.Observations = append(b.Observations, model.Observation{Purl: "pkg:npm/" + p, Confidence: model.ConfidenceConfirmed})
	}
	b.Complete = true
	res, err := e.st.Ingest(ws, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := e.st.ListInventory(ws, store.InventoryFilter{AssetID: res.AssetID})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	var in []store.FindingInput
	for _, r := range rows {
		ids = append(ids, r.ID)
		in = append(in, store.FindingInput{Kind: "vulnerability", Key: "GHSA-" + r.Name, InventoryID: r.ID, AssetID: res.AssetID,
			ComponentID: r.ComponentID, Verification: "confirmed", Severity: "high", Sources: []string{"GHSA-" + r.Name}, Evidence: map[string]any{}})
	}
	if _, _, err := e.st.SyncFindings(ws, []string{"vulnerability"}, ids, in); err != nil {
		t.Fatal(err)
	}
	// a is overdue, b due within the minute, c due in three days; all
	// opened 10 days ago. d opened 20 days ago and was fixed 2 days ago.
	for _, q := range []string{
		`UPDATE findings SET state = 'new', first_seen = now() - interval '10 days'`,
		`UPDATE findings SET fix_due = now() - interval '1 day' WHERE key = 'GHSA-a'`,
		`UPDATE findings SET fix_due = now() + interval '1 minute' WHERE key = 'GHSA-b'`,
		`UPDATE findings SET fix_due = now() + interval '3 days' WHERE key = 'GHSA-c'`,
		`UPDATE findings SET status = 'resolved', resolved_at = now() - interval '2 days', resolution_kind = 'remediated',
		   first_seen = now() - interval '20 days' WHERE key = 'GHSA-d'`,
		`INSERT INTO finding_events (workspace_id, finding_id, at, actor_type, actor_name, action, detail)
		   SELECT workspace_id, id, now() - interval '2 days', 'system', 'matcher', 'resolved', '{"resolution_kind": "remediated"}'
		   FROM findings WHERE key = 'GHSA-d'`,
	} {
		if _, err := e.st.Pool.Exec(ws, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	var tr store.DashboardTrend
	if code := viewer.do("GET", "/api/v1/dashboard/trend?tz=UTC", nil, &tr); code != 200 {
		t.Fatalf("trend: %d", code)
	}
	if tr.SLA.Overdue != 1 || tr.SLA.OnTime != 1 || tr.SLA.DueToday+tr.SLA.OnTime != 2 {
		t.Errorf("SLA: %+v", tr.SLA)
	}
	if len(tr.Open) != store.TrendDays+1 {
		t.Fatalf("%d trend points", len(tr.Open))
	}
	open := func(daysAgo int) int64 { return tr.Open[store.TrendDays-daysAgo].Open }
	got := fmt.Sprint(open(0), open(1), open(3), open(15), open(25))
	if got != "3 3 4 1 0" {
		t.Errorf("open 0, 1, 3, 15 and 25 days ago: %s", got)
	}
	if len(tr.Fixed) != store.TrendWeeks || tr.Fixed[store.TrendWeeks-1].Fixed != 1 || tr.Fixed[0].Fixed != 0 {
		t.Errorf("fixed per week: %+v", tr.Fixed)
	}

	// "Due today" deep-links to the findings due by the end of today.
	var list struct{ Total int64 }
	q := "/api/v1/findings?due_before=" + tr.EndOfToday.UTC().Format(time.RFC3339)
	if code := viewer.do("GET", q, nil, &list); code != 200 || list.Total != tr.SLA.Overdue+tr.SLA.DueToday {
		t.Errorf("%s: %d, %d findings", q, code, list.Total)
	}
	q = "/api/v1/findings?due_after=" + tr.CheckedAt.UTC().Add(-time.Second).Format(time.RFC3339) + "&due_before=" + tr.EndOfToday.UTC().Format(time.RFC3339)
	if code := viewer.do("GET", q, nil, &list); code != 200 || list.Total != tr.SLA.DueToday {
		t.Errorf("due today: %d, %d findings", code, list.Total)
	}
	if code := viewer.do("GET", "/api/v1/findings?overdue=false", nil, &list); code != 200 || list.Total != tr.SLA.OnTime+tr.SLA.DueToday {
		t.Errorf("on time: %d, %d findings", code, list.Total)
	}
	for _, bad := range []string{"/api/v1/dashboard/trend?tz=Not/AZone", "/api/v1/dashboard/trend?tz=../../etc/passwd", "/api/v1/findings?due_before=today"} {
		if code := viewer.do("GET", bad, nil, nil); code != 400 {
			t.Errorf("%s: %d", bad, code)
		}
	}
}
