package notify

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// finishFirstScan marks an asset's first collection as evaluated, as the
// evaluate job would.
func (f *fixture) finishFirstScan(name string) {
	f.t.Helper()
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if err := f.st.MarkEvaluated(ctx, f.asset[name], time.Now()); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.st.Pool.Exec(ctx, `UPDATE jobs SET done_at = now() WHERE dedupe_key = $1`, fmt.Sprintf("evaluate:asset:%d", f.asset[name])); err != nil {
		f.t.Fatal(err)
	}
}

// Connecting an asset tells people once, in a "connected" message, and
// nothing else about its backlog: no urgent alert (the fixture's route
// sends to a webhook), no Jira issue, no escalation record, no overdue
// reminder, no "came back" alert and no "new issues" in summaries, even
// when the backlog is long past its deadlines. Issues found afterwards
// alert as usual.
func TestQuietFirstScanEveryPath(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	fj, srv := newFakeJira(t, false)
	jira := f.addJira(ctx, srv.URL, false, nil)
	f.addNewAsset("web-1", "production", true)
	// Known exploited, so urgent for every route, and found 60 days ago by
	// the clock of the deadlines: past every acknowledgement and fix deadline.
	f.findingsOn(map[string][]string{"web-1": {"CVE-2021-23337", "CVE-2020-8203"}})
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET first_seen = now() - interval '60 days'`); err != nil {
		t.Fatal(err)
	}
	f.tick()
	if ev := f.hook.events(); len(ev) != 0 {
		t.Fatalf("messages before the first scan finished: %v", ev)
	}
	f.finishFirstScan("web-1")
	f.tick()
	f.tick()

	if ev := f.hook.events(); len(ev) != 1 || !strings.HasPrefix(ev[0], "connected") {
		t.Fatalf("want one connected message on the webhook: %v", ev)
	}
	if m := f.hook.got[0]; m.Title != "web-1 connected: 1 package checked, 2 issues found, 1 fix needs you" || m.Counts["issues"] != 2 {
		t.Errorf("connected = %q %v", m.Title, m.Counts)
	}
	if ds := jiraDeliveries(t, f.st, ctx, jira.ID); len(ds) != 0 || fj.creates != 0 {
		t.Errorf("Jira for the backlog: %d deliveries, %d issues", len(ds), fj.creates)
	}
	if esc, err := f.st.EscalationCandidates(ctx); err != nil || len(esc) != 0 {
		t.Errorf("escalation candidates for the backlog: %v %v", esc, err)
	}
	if n := f.count(`SELECT count(*) FROM findings WHERE escalated_at IS NOT NULL OR escalation_level > 0`); n != 0 {
		t.Errorf("%d backlog findings escalated", n)
	}
	now := time.Now()
	for _, set := range []store.IssueSet{store.IssuesOverdue, store.IssuesAckOverdue, store.IssuesNew} {
		if c, err := f.st.CountIssues(ctx, set, now.Add(-90*24*time.Hour), now); err != nil || len(c) != 0 {
			t.Errorf("issue set %d counts the backlog: %+v %v", set, c, err)
		}
	}
	if c, err := f.st.CountIssues(ctx, store.IssuesNewlyOverdue, now.Add(-90*24*time.Hour), now); err != nil || len(c) != 0 {
		t.Errorf("newly overdue counts the backlog: %+v %v", c, err)
	}

	// The summary says "connected, N issues found", not "N new issues",
	// and has no overdue section for the backlog.
	routes, _ := f.st.ListRoutes(ctx)
	var main store.Route
	for _, r := range routes {
		if r.Name == "main" {
			main = r
		}
	}
	data := &summaryData{d: f.d, ctx: ctx, cache: map[string][]store.IssueCount{}}
	sm, changed, err := f.d.summaryMessage(main, data, now.Add(-time.Hour), time.Now().Add(time.Minute), true)
	if err != nil || !changed {
		t.Fatalf("summary: %v %v", changed, err)
	}
	if sm.Title != "Daily summary: 1 asset connected, 2 issues found" || sm.Counts["new"] != 0 || sm.Counts["connected_issues"] != 2 ||
		sm.Counts["overdue"] != 0 || sm.Counts["ack_overdue"] != 0 {
		t.Errorf("summary %q %v", sm.Title, sm.Counts)
	}
	for _, s := range sm.Sections {
		if s.Title == "New issues" || s.Title == "Overdue" {
			t.Errorf("summary section %q for the backlog: %+v", s.Title, s.Items)
		}
	}

	// A late part of the backlog (findings first seen before the asset was
	// announced, whose incident appears only afterwards) stays quiet too.
	f.findingsOn(map[string][]string{"web-1": {"CVE-2021-23337", "CVE-2020-8203", "CVE-2019-10744"}})
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET first_seen = now() - interval '60 days' WHERE key = 'CVE-2019-10744'`); err != nil {
		t.Fatal(err)
	}
	f.tick()
	f.tick()
	if ev := f.hook.events(); len(ev) != 1 {
		t.Errorf("late backlog alerted: %v", ev)
	}
	if fj.creates != 0 {
		t.Errorf("late backlog made %d Jira issues", fj.creates)
	}

	// A new issue after the first scan: urgent, and a Jira issue.
	f.findingsOn(map[string][]string{"web-1": {"CVE-2021-23337", "CVE-2020-8203", "CVE-2019-10744", "CVE-2026-0001"}})
	f.tick()
	f.tick()
	ev := f.hook.events()
	if len(ev) != 2 || ev[1] != "urgent:P1" || f.hook.got[1].Title != "web-1: 1 new urgent issue" {
		t.Fatalf("after the first scan: %v", ev)
	}
	if fj.creates != 1 {
		t.Errorf("new issue: %d Jira issues, want 1", fj.creates)
	}
	// Past its deadlines it escalates, unlike the backlog.
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET fix_due = now() - interval '1 day' WHERE key = 'CVE-2026-0001'`); err != nil {
		t.Fatal(err)
	}
	esc, err := f.st.EscalationCandidates(ctx)
	if err != nil || len(esc) != 1 {
		t.Errorf("escalation candidates: %v %v", esc, err)
	}
	if c, _ := f.st.CountIssues(ctx, store.IssuesOverdue, now, time.Now()); len(c) != 1 || c[0].Count != 1 {
		t.Errorf("overdue: %+v", c)
	}
}

// An asset that existed before 0.9 keeps its deadlines: its old findings
// still escalate and show as overdue.
func TestQuietBacklogOnlyForNewAssets(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	f.addAsset("old-1", "production", true)
	if _, err := f.st.Pool.Exec(ctx, `UPDATE assets SET quiet_backlog = false, announced_at = now() WHERE id = $1`, f.asset["old-1"]); err != nil {
		t.Fatal(err)
	}
	f.findingsOn(map[string][]string{"old-1": {"CVE-2021-23337"}})
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET first_seen = now() - interval '60 days', fix_due = now() - interval '1 day'`); err != nil {
		t.Fatal(err)
	}
	if err := f.st.CorrelateIncidents(ctx); err != nil {
		t.Fatal(err)
	}
	if esc, err := f.st.EscalationCandidates(ctx); err != nil || len(esc) != 1 {
		t.Errorf("escalation candidates: %v %v", esc, err)
	}
}

// An issue that comes back on an asset whose first scan is not announced
// yet is part of that scan, and raises no "came back" alert.
func TestRegressedOnNewAssetIsQuiet(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	f.addNewAsset("web-9", "production", true)
	f.findingsOn(map[string][]string{"web-9": {"CVE-2021-23337"}})
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET regressed_at = now()`); err != nil {
		t.Fatal(err)
	}
	counts, _, err := f.st.RegressedToAnnounce(ctx)
	if err != nil || len(counts) != 1 || !counts[0].Backlog {
		t.Fatalf("regressed = %+v %v", counts, err)
	}
	f.tick()
	for _, e := range f.hook.events() {
		if strings.HasPrefix(e, "urgent") {
			t.Errorf("came-back alert for a first scan: %v", f.hook.events())
		}
	}
}
