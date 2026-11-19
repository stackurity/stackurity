package store

// Evaluation runs (migration 0116, docs/evaluation-runs.md): a record of each
// time a workspace's software was checked against vulnerability data, and of
// each feed sync, kept 400 days so the compliance evidence pack can show how
// often it happened over a period.

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// Evaluation run triggers.
const (
	RunFeedSync  = "feed_sync" // a source changed; the components it affects were evaluated again
	RunIngest    = "ingest"    // an asset reported; its inventory was evaluated
	RunDaily     = "daily"     // the daily full evaluation (end-of-life dates pass without a feed change)
	RunScheduled = "scheduled" // the check every 30 minutes (CheckEvaluation)
)

// EvaluationRunsKeep is how long runs are kept: an audit year and a margin.
const EvaluationRunsKeep = 400 * 24 * time.Hour

// Scheduled check thresholds: a source is on schedule when it was read
// successfully within its refresh interval plus RunFeedGrace; a re-evaluation
// waiting longer than RunBacklogAfter means evaluation is behind.
const (
	RunFeedGrace    = time.Hour
	RunBacklogAfter = 15 * time.Minute
)

// RunFeed is a source a run used, with its last successful sync then.
type RunFeed struct {
	Name        string     `json:"name"`
	LastSuccess *time.Time `json:"last_success"`
}

// EvaluationRun is one evaluation run of a workspace.
type EvaluationRun struct {
	ID              int64     `json:"id"`
	Trigger         string    `json:"trigger"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
	Feeds           []RunFeed `json:"feeds"`
	AssetsEvaluated int       `json:"assets_evaluated"`
	FindingsOpened  int64     `json:"findings_opened"`
	FindingsClosed  int64     `json:"findings_closed"`
	OK              bool      `json:"ok"`
	ErrorClass      string    `json:"error_class,omitempty"`
}

// RunErrorClass is a short, fixed class for an error, never its text (which
// may name URLs or paths): timeout, canceled or error ("" for nil).
func RunErrorClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	return "error"
}

// RecordEvaluationRun stores a run of the context's workspace. FinishedAt
// defaults to now.
func (s *Store) RecordEvaluationRun(ctx context.Context, r EvaluationRun) error {
	if r.Feeds == nil {
		r.Feeds = []RunFeed{}
	}
	var fin any
	if !r.FinishedAt.IsZero() {
		fin = r.FinishedAt
	}
	_, err := s.Pool.Exec(context.WithoutCancel(ctx), `INSERT INTO evaluation_runs
		(trigger, started_at, finished_at, feeds, assets_evaluated, findings_opened, findings_closed, ok, error_class)
		VALUES ($1, $2, COALESCE($3::timestamptz, now()), $4, $5, $6, $7, $8, $9)`,
		r.Trigger, r.StartedAt, fin, r.Feeds, r.AssetsEvaluated, clampInt(r.FindingsOpened), clampInt(r.FindingsClosed), r.OK, r.ErrorClass)
	return err
}

func clampInt(n int64) int64 { return min(n, math.MaxInt32) }

// RecordFeedSyncRun stores one sync of a source.
func (s *Store) RecordFeedSyncRun(ctx context.Context, feed string, started time.Time, changed int, reevaluate bool, runErr error) error {
	_, err := s.Pool.Exec(context.WithoutCancel(ctx), `INSERT INTO feed_sync_runs (feed, started_at, ok, changed, reevaluate, error_class)
		VALUES ($1, $2, $3, $4, $5, $6)`, feed, started, runErr == nil, min(changed, math.MaxInt32), reevaluate, RunErrorClass(runErr))
	return err
}

// RunFeeds are the vulnerability sources the context's workspace's
// installed software is evaluated against (of one asset, or all with 0),
// with their last successful sync.
func (s *Store) RunFeeds(ctx context.Context, assetID int64) ([]RunFeed, error) {
	rows, err := s.Pool.Query(ctx, `SELECT f.name, f.last_success FROM feeds f
		WHERE f.kind = 'vulnerability' AND f.name IN (SELECT DISTINCT i.coverage_feed FROM inventory i
			WHERE i.removed_at IS NULL AND i.coverage_feed <> '' AND ($1 = 0 OR i.asset_id = $1))
		ORDER BY f.name`, assetID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[RunFeed])
	if out == nil {
		out = []RunFeed{}
	}
	return out, err
}

// CheckEvaluation is the scheduled check of the context's workspace, run
// every 30 minutes: every vulnerability source its installed software is
// evaluated against was read successfully within its refresh interval plus
// RunFeedGrace (a source that changed hands its components to re-evaluation,
// and the rest stay valid against the new data), and no re-evaluation has
// been waiting longer than RunBacklogAfter. It records the run and returns it.
// ok is false with error_class feed_failed (a source's last sync failed and
// it is overdue), feed_stale (overdue) or evaluation_backlog.
func (s *Store) CheckEvaluation(ctx context.Context) (EvaluationRun, error) {
	r := EvaluationRun{Trigger: RunScheduled, Feeds: []RunFeed{}}
	if err := s.Pool.QueryRow(ctx, `SELECT now()`).Scan(&r.StartedAt); err != nil {
		return r, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT f.name, f.last_success,
			f.enabled AND f.last_success IS NOT NULL AND f.last_success >= now() - f.refresh - make_interval(secs => $1),
			f.last_error <> ''
		FROM feeds f
		WHERE f.kind = 'vulnerability' AND f.name IN (SELECT DISTINCT i.coverage_feed FROM inventory i
			WHERE i.removed_at IS NULL AND i.coverage_feed <> '')
		ORDER BY f.name`, RunFeedGrace.Seconds())
	if err != nil {
		return r, err
	}
	stale, failed := false, false
	for rows.Next() {
		var f RunFeed
		var onTime, hasErr bool
		if err := rows.Scan(&f.Name, &f.LastSuccess, &onTime, &hasErr); err != nil {
			rows.Close()
			return r, err
		}
		r.Feeds = append(r.Feeds, f)
		if !onTime {
			stale = true
			failed = failed || hasErr
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return r, err
	}
	var backlog bool
	if err := s.Pool.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM jobs WHERE kind = 'evaluate' AND workspace_id = stackurity_ws() AND done_at IS NULL AND failed_at IS NULL
			AND run_at < now() - make_interval(secs => $1)),
		(SELECT count(DISTINCT i.asset_id) FROM inventory i JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL WHERE i.removed_at IS NULL)`,
		RunBacklogAfter.Seconds()).Scan(&backlog, &r.AssetsEvaluated); err != nil {
		return r, err
	}
	switch {
	case failed:
		r.ErrorClass = "feed_failed"
	case stale:
		r.ErrorClass = "feed_stale"
	case backlog:
		r.ErrorClass = "evaluation_backlog"
	}
	r.OK = r.ErrorClass == ""
	return r, s.RecordEvaluationRun(ctx, r)
}

// EvaluationRuns lists the context's workspace's runs finished in
// [from, to), newest first, up to limit.
func (s *Store) EvaluationRuns(ctx context.Context, from, to time.Time, limit int) ([]EvaluationRun, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, trigger, started_at, finished_at, feeds, assets_evaluated, findings_opened, findings_closed, ok, error_class
		FROM evaluation_runs WHERE finished_at >= $1 AND finished_at < $2 ORDER BY finished_at DESC, id DESC LIMIT $3`, from, to, limit)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[EvaluationRun])
	if out == nil {
		out = []EvaluationRun{}
	}
	return out, err
}

// EvaluationCoverage is how regularly a workspace's software was checked
// against vulnerability data over a period.
type EvaluationCoverage struct {
	// RecordedSince is the first recorded run of the workspace (nil: none).
	// Hours before it are not counted: they are not known either way.
	RecordedSince *time.Time `json:"recorded_since"`
	// From and To bound the hours counted: whole clock hours from the later
	// of the period's start and RecordedSince to the earlier of its end and
	// now.
	From *time.Time `json:"from"`
	To   *time.Time `json:"to"`
	// HoursExpected whole clock hours in [From, To); HoursWithRun of them had
	// a run that finished successfully.
	HoursExpected int64 `json:"hours_expected"`
	HoursWithRun  int64 `json:"hours_with_run"`
	// LongestGapHours is the longest time without a successful run in
	// [From, To), the edges included.
	LongestGapHours float64 `json:"longest_gap_hours"`
	// RunsOK and RunsFailed count the runs in [From, To); FailedByClass
	// splits the failures.
	RunsOK        int64            `json:"runs_ok"`
	RunsFailed    int64            `json:"runs_failed"`
	FailedByClass map[string]int64 `json:"failed_by_class"`
}

// EvaluationCoverage measures the context's workspace's runs over
// [from, to).
func (s *Store) EvaluationCoverage(ctx context.Context, from, to time.Time) (EvaluationCoverage, error) {
	c := EvaluationCoverage{FailedByClass: map[string]int64{}}
	var now time.Time
	if err := s.Pool.QueryRow(ctx, `SELECT now(), (SELECT min(finished_at) FROM evaluation_runs)`).Scan(&now, &c.RecordedSince); err != nil {
		return c, err
	}
	if c.RecordedSince == nil {
		return c, nil
	}
	// Whole clock hours only (UTC, as the query counts them): a partial
	// hour at either end is not counted.
	lo := maxTime(from, *c.RecordedSince)
	start := lo.Truncate(time.Hour)
	if start.Before(lo) {
		start = start.Add(time.Hour)
	}
	stop := to
	if now.Before(stop) {
		stop = now
	}
	stop = stop.Truncate(time.Hour)
	if !stop.After(start) {
		return c, nil
	}
	c.From, c.To = &start, &stop
	c.HoursExpected = int64(stop.Sub(start) / time.Hour)
	err := s.Pool.QueryRow(ctx, `WITH r AS (SELECT finished_at, ok, error_class FROM evaluation_runs WHERE finished_at >= $1 AND finished_at < $2),
		pts AS (SELECT finished_at AS t FROM r WHERE ok UNION ALL SELECT $1::timestamptz UNION ALL SELECT $2::timestamptz)
		SELECT (SELECT count(DISTINCT date_trunc('hour', finished_at, 'UTC')) FROM r WHERE ok),
			COALESCE((SELECT max(extract(epoch FROM t - prev)) FROM (SELECT t, lag(t) OVER (ORDER BY t) AS prev FROM pts) x), 0) / 3600,
			(SELECT count(*) FROM r WHERE ok), (SELECT count(*) FROM r WHERE NOT ok)`, start, stop).
		Scan(&c.HoursWithRun, &c.LongestGapHours, &c.RunsOK, &c.RunsFailed)
	if err != nil {
		return c, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT error_class, count(*) FROM evaluation_runs WHERE finished_at >= $1 AND finished_at < $2 AND NOT ok GROUP BY 1`, start, stop)
	if err != nil {
		return c, err
	}
	var class string
	var n int64
	_, err = pgx.ForEachRow(rows, []any{&class, &n}, func() error { c.FailedByClass[class] = n; return nil })
	return c, err
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// PruneEvaluationRuns deletes evaluation and feed sync runs older than
// keep (EvaluationRunsKeep when 0), in every workspace (system scope).
func (s *Store) PruneEvaluationRuns(ctx context.Context, keep time.Duration) (int64, error) {
	if keep <= 0 {
		keep = EvaluationRunsKeep
	}
	a, err := s.Pool.Exec(ctx, `DELETE FROM evaluation_runs WHERE finished_at < now() - make_interval(secs => $1)`, keep.Seconds())
	if err != nil {
		return 0, err
	}
	b, err := s.Pool.Exec(ctx, `DELETE FROM feed_sync_runs WHERE finished_at < now() - make_interval(secs => $1)`, keep.Seconds())
	if err != nil {
		return 0, err
	}
	return a.RowsAffected() + b.RowsAffected(), nil
}
