package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func evalRunsStore(t *testing.T) (*store.Store, context.Context, context.Context) {
	t.Helper()
	s := store.New(testdb.New(t))
	sys := tenant.System(context.Background())
	if _, err := s.Pool.Exec(sys, `INSERT INTO workspaces (id, name, slug) VALUES (2, 'Other', 'other')`); err != nil {
		t.Fatal(err)
	}
	return s, tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), tenant.WithWorkspace(context.Background(), 2)
}

func record(t *testing.T, s *store.Store, ctx context.Context, at time.Time, ok bool, class string) {
	t.Helper()
	recordRun(t, s, ctx, store.RunScheduled, at, ok, class, 3)
}

func recordRun(t *testing.T, s *store.Store, ctx context.Context, trigger string, at time.Time, ok bool, class string, assets int) {
	t.Helper()
	if err := s.RecordEvaluationRun(ctx, store.EvaluationRun{Trigger: trigger, StartedAt: at.Add(-time.Second), FinishedAt: at,
		OK: ok, ErrorClass: class, AssetsEvaluated: assets}); err != nil {
		t.Fatal(err)
	}
}

// Hours are counted only from the first recorded run: before it nothing is
// known either way. One hour without a successful run is a missed hour,
// and a workspace never sees another's runs.
func TestEvaluationCoverage(t *testing.T) {
	s, ctx, other := evalRunsStore(t)
	now := time.Now()
	// Recording starts 10 hours and 20 minutes ago (as if migration 0116
	// shipped then); a run every 30 minutes, except for one hour with only a
	// failed run.
	first := now.Add(-10*time.Hour - 20*time.Minute)
	missed := now.Truncate(time.Hour).Add(-4 * time.Hour)
	for at := first; at.Before(now); at = at.Add(30 * time.Minute) {
		if !at.Before(missed) && at.Before(missed.Add(time.Hour)) {
			record(t, s, ctx, at, false, "feed_stale")
			continue
		}
		record(t, s, ctx, at, true, "")
	}
	// The other workspace's runs fill the missed hour: not counted here.
	record(t, s, other, missed.Add(10*time.Minute), true, "")
	record(t, s, other, missed.Add(-48*time.Hour), true, "")

	c, err := s.EvaluationCoverage(ctx, now.AddDate(0, 0, -30), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if c.RecordedSince == nil || c.RecordedSince.Sub(first).Abs() > time.Millisecond {
		t.Fatalf("recorded since %v, want %v", c.RecordedSince, first)
	}
	// Whole hours from the first full hour after recording started to the
	// start of the current hour.
	wantFrom := first.Truncate(time.Hour).Add(time.Hour)
	wantTo := now.Truncate(time.Hour)
	want := int64(wantTo.Sub(wantFrom) / time.Hour)
	if c.From == nil || !c.From.Equal(wantFrom) || !c.To.Equal(wantTo) || c.HoursExpected != want || c.HoursPassed != want-1 {
		t.Errorf("coverage %+v; want %d hours from %v, %d with a run", c, want, wantFrom, want-1)
	}
	if c.LongestGapHours < 1.4 || c.LongestGapHours > 1.6 || c.ChecksFailed != 2 || c.FailedByClass["feed_stale"] != 2 {
		t.Errorf("gap %.2f, failed %d %v", c.LongestGapHours, c.ChecksFailed, c.FailedByClass)
	}
	runs, err := s.EvaluationRuns(ctx, now.Add(-24*time.Hour), now.Add(time.Minute), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) < 18 {
		t.Errorf("runs listed: %d", len(runs))
	}
	for _, r := range runs {
		if r.FinishedAt.Equal(missed.Add(10*time.Minute)) && r.OK {
			t.Error("the other workspace's run is visible")
		}
	}

	// A period entirely before recording started: nothing is claimed.
	c, err = s.EvaluationCoverage(ctx, now.AddDate(0, 0, -30), first.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if c.HoursExpected != 0 || c.From != nil || c.RecordedSince == nil {
		t.Errorf("before recording: %+v", c)
	}
	// A workspace with no runs at all.
	if _, err := s.Pool.Exec(tenant.System(context.Background()), `DELETE FROM evaluation_runs WHERE workspace_id = 2`); err != nil {
		t.Fatal(err)
	}
	if c, err := s.EvaluationCoverage(other, now.AddDate(0, 0, -30), now); err != nil || c.RecordedSince != nil || c.HoursExpected != 0 {
		t.Errorf("no runs: %+v %v", c, err)
	}
}

// Runs and feed syncs older than 400 days are pruned, in every workspace.
func TestPruneEvaluationRuns(t *testing.T) {
	s, ctx, other := evalRunsStore(t)
	now := time.Now()
	record(t, s, ctx, now.Add(-401*24*time.Hour), true, "")
	record(t, s, other, now.Add(-401*24*time.Hour), true, "")
	record(t, s, ctx, now.Add(-399*24*time.Hour), true, "")
	sys := tenant.System(context.Background())
	if err := s.RecordFeedSyncRun(sys, "osv:npm", now.Add(-2*time.Hour), 3, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(sys, `INSERT INTO feed_sync_runs (feed, started_at, finished_at, ok) VALUES ('osv:npm', now() - interval '402 days', now() - interval '402 days', true)`); err != nil {
		t.Fatal(err)
	}
	n, err := s.PruneEvaluationRuns(sys, 0)
	if err != nil {
		t.Fatal(err)
	}
	var runs, syncs int
	if err := s.Pool.QueryRow(sys, `SELECT (SELECT count(*) FROM evaluation_runs), (SELECT count(*) FROM feed_sync_runs)`).Scan(&runs, &syncs); err != nil {
		t.Fatal(err)
	}
	if n != 3 || runs != 1 || syncs != 1 {
		t.Errorf("pruned %d; left %d runs, %d syncs", n, runs, syncs)
	}
	// The application never changes a run.
	var role string
	if err := s.Pool.QueryRow(ctx, `SELECT current_user`).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "stackurity_app" {
		t.Skipf("connected as %s, not the application role", role)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE evaluation_runs SET ok = false`); err == nil {
		t.Error("the application role may update evaluation runs")
	}
}

// The scheduled check passes when every source the workspace's software
// is checked against was read on schedule and nothing waits for
// re-evaluation, and says why when not.
func TestCheckEvaluation(t *testing.T) {
	s, ctx, _ := evalRunsStore(t)
	sys := tenant.System(context.Background())
	asset := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15")
	if err := s.EnsureFeed(sys, "osv:npm", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(sys, `UPDATE inventory SET coverage_feed = 'osv:npm' WHERE asset_id = $1`, asset); err != nil {
		t.Fatal(err)
	}
	// The ingest queued an evaluation; the worker has not run here.
	if _, err := s.Pool.Exec(sys, `UPDATE jobs SET done_at = now() WHERE kind = 'evaluate'`); err != nil {
		t.Fatal(err)
	}
	check := func(feedAgo time.Duration, lastErr string, want string) {
		t.Helper()
		if _, err := s.Pool.Exec(sys, `UPDATE feeds SET last_success = now() - make_interval(secs => $1), last_error = $2 WHERE name = 'osv:npm'`,
			feedAgo.Seconds(), lastErr); err != nil {
			t.Fatal(err)
		}
		r, err := s.CheckEvaluation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if r.OK != (want == "") || r.ErrorClass != want || len(r.Feeds) != 1 || r.Feeds[0].Name != "osv:npm" || r.AssetsEvaluated != 1 {
			t.Errorf("feed %v ago, error %q: %+v, want %q", feedAgo, lastErr, r, want)
		}
	}
	check(20*time.Minute, "", "")
	check(110*time.Minute, "", "")            // within the hour's refresh and an hour's grace
	check(3*time.Hour, "", "feed_stale")      // overdue
	check(3*time.Hour, "boom", "feed_failed") // overdue after a failed sync
	if _, err := s.Pool.Exec(ctx, `INSERT INTO jobs (kind, payload, run_at) VALUES ('evaluate', '{"all": true}', now() - interval '1 hour')`); err != nil {
		t.Fatal(err)
	}
	check(10*time.Minute, "", "evaluation_backlog")
	// An evaluation that failed for good, in the last day, fails the check.
	if _, err := s.Pool.Exec(ctx, `UPDATE jobs SET failed_at = now() - interval '2 hours' WHERE kind = 'evaluate' AND done_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	check(10*time.Minute, "", "evaluation_failed")
	if _, err := s.Pool.Exec(ctx, `UPDATE jobs SET failed_at = now() - interval '25 hours' WHERE kind = 'evaluate' AND failed_at IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	check(10*time.Minute, "", "")

	var n int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM evaluation_runs WHERE trigger = 'scheduled'`).Scan(&n); err != nil || n != 7 {
		t.Errorf("scheduled runs recorded: %d %v", n, err)
	}
}

// An hour passes only on its scheduled checks: successful evaluations of
// other kinds never mask a failing check, an hour with a failing check
// fails even if another check passed, and checks of a workspace with no
// installed software are not counted at all.
func TestEvaluationCoverageCountsOnlyScheduledChecks(t *testing.T) {
	s, ctx, other := evalRunsStore(t)
	now := time.Now()
	h0 := now.Truncate(time.Hour).Add(-5 * time.Hour)
	for i := 0; i < 5; i++ {
		h := h0.Add(time.Duration(i) * time.Hour)
		// Every scheduled check fails; successful ingests, feed syncs and
		// daily runs in the same hours.
		recordRun(t, s, ctx, store.RunScheduled, h, false, "feed_stale", 3)
		recordRun(t, s, ctx, store.RunScheduled, h.Add(40*time.Minute), false, "feed_stale", 3)
		recordRun(t, s, ctx, store.RunIngest, h.Add(20*time.Minute), true, "", 1)
		recordRun(t, s, ctx, store.RunFeedSync, h.Add(25*time.Minute), true, "", 3)
		recordRun(t, s, ctx, store.RunDaily, h.Add(30*time.Minute), true, "", 3)
	}
	c, err := s.EvaluationCoverage(ctx, h0, now.Truncate(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if c.HoursExpected != 5 || c.HoursPassed != 0 || c.ChecksFailed != 10 || c.FailedByClass["feed_stale"] != 10 {
		t.Errorf("failing checks masked: %+v", c)
	}

	// One passing and one failing check in the same hour: the hour fails.
	h := h0.Add(-time.Hour)
	recordRun(t, s, other, store.RunScheduled, h.Add(-time.Hour), true, "", 2) // recording starts an hour earlier
	recordRun(t, s, other, store.RunScheduled, h.Add(10*time.Minute), true, "", 2)
	recordRun(t, s, other, store.RunScheduled, h.Add(40*time.Minute), false, "evaluation_backlog", 2)
	recordRun(t, s, other, store.RunScheduled, h.Add(70*time.Minute), true, "", 2)
	recordRun(t, s, other, store.RunScheduled, h.Add(100*time.Minute), true, "", 2)
	c, err = s.EvaluationCoverage(other, h, h.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if c.HoursExpected != 2 || c.HoursPassed != 1 {
		t.Errorf("mixed hour: %+v", c)
	}

	// No installed software: checks pass with 0 assets and are not
	// counted, so nothing is claimed.
	if _, err := s.Pool.Exec(tenant.System(context.Background()), `DELETE FROM evaluation_runs`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		recordRun(t, s, ctx, store.RunScheduled, h0.Add(time.Duration(i)*30*time.Minute+time.Minute), true, "", 0)
	}
	c, err = s.EvaluationCoverage(ctx, h0, now.Truncate(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if c.HoursExpected != 0 || c.HoursPassed != 0 || c.From != nil || c.RecordedSince == nil {
		t.Errorf("empty workspace: %+v", c)
	}
}
