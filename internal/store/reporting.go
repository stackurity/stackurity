package store

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/model"
)

// Reporting sources: how an asset's reports reach Stackurity (migration
// 0064). What is expected of an asset follows from its source.
const (
	SourceAgent       = "agent"       // the Stackurity agent on a server (and the applications it reads)
	SourceScan        = "scan"        // a scan uploaded with an API token: the CLI, a CI job, a scheduled scan
	SourceIntegration = "integration" // a Git, image or plugin integration the server runs on its schedule
	SourceManual      = "manual"      // an upload in the dashboard
)

// Reporting overrides a person may set on an asset.
const (
	ReportAuto   = "auto"
	ReportDaily  = "daily"
	ReportWeekly = "weekly"
	ReportOneOff = "one_off"
)

const (
	// DefaultStaleAfter is how long an agent may stay silent
	// (STACKURITY_STALE_AFTER), and the shortest time any asset may.
	DefaultStaleAfter = 48 * time.Hour
	// runGap: reports closer together than this are one run (the agent's
	// OS and software batches, a scan's several lockfiles).
	runGap = time.Hour
	// cadenceRuns is how many recent runs a learned cadence looks at.
	cadenceRuns = 6
	// A cadence is learned only from at least learnRuns runs over at least
	// learnSpan from the asset's first report. Fewer, or all within a day
	// (a scan re-run by hand a few times on the day it was set up), is a
	// one-off scan.
	learnRuns = 3
	learnSpan = 24 * time.Hour
	// OneOffAging is when a one-off scan's note says how old its results are.
	OneOffAging = 90 * 24 * time.Hour
)

// ValidReportOverride reports whether v is a reporting override.
func ValidReportOverride(v string) bool {
	switch v {
	case ReportAuto, ReportDaily, ReportWeekly, ReportOneOff:
		return true
	}
	return false
}

// Reporting is how an asset reports and what is expected of it.
type Reporting struct {
	Source   string `json:"source"`
	Override string `json:"override"`
	// Mode is what the dashboard shows: agent, scheduled (a learned or set
	// cadence), one_off (no further report expected), integration, or
	// unknown (no report yet).
	Mode string `json:"mode"`
	// Runs counts the reports seen an hour apart or more, up to 6.
	Runs int `json:"runs"`
	// UsualSeconds is the median gap between them (2 runs or more).
	UsualSeconds *int64 `json:"usual_seconds"`
	// DueAfterSeconds is how long after the last report the asset is
	// overdue; null when nothing is expected.
	DueAfterSeconds *int64 `json:"due_after_seconds"`
	// AsOf is the date its results are from when no further report is
	// expected (one-off).
	AsOf *time.Time `json:"as_of,omitempty"`
}

// reportSourceKey carries the reporting source of the batches ingested
// with a context (WithReportSource).
type reportSourceKey struct{}

// ReportSource says how a batch reached the server.
type ReportSource struct {
	Source        string
	IntegrationID int64
}

// WithReportSource marks the batches ingested with ctx as coming from src:
// the API for uploads in the dashboard, the integration jobs for theirs.
func WithReportSource(ctx context.Context, src ReportSource) context.Context {
	return context.WithValue(ctx, reportSourceKey{}, src)
}

// reportSourceOf is the source of a batch: the one ctx names, else what the
// collector and the token say (a token uploads scans; the server's own
// collection without one is an integration's).
func reportSourceOf(ctx context.Context, b *model.ObservationBatch, tokenID int64) ReportSource {
	if src, ok := ctx.Value(reportSourceKey{}).(ReportSource); ok && src.Source != "" {
		if src.Source == SourceManual && b.Collector.Method == "agent" && tokenID > 0 {
			return ReportSource{Source: SourceAgent}
		}
		return src
	}
	switch {
	case b.Collector.Method == "agent":
		return ReportSource{Source: SourceAgent}
	case b.Collector.Method == "plugin" || b.Collector.Method == "repository":
		return ReportSource{Source: SourceIntegration}
	case tokenID > 0:
		return ReportSource{Source: SourceScan}
	case b.Collector.Method == "scanner":
		return ReportSource{Source: SourceIntegration}
	}
	return ReportSource{Source: SourceManual}
}

// Cadence works out an asset's reporting runs from its latest report times:
// reports less than an hour apart are one run. It returns the number of
// runs among the latest 6 and the median gap between their starts (0 for
// fewer than 2 runs).
func Cadence(times []time.Time) (runs int, usual time.Duration) {
	ts := append([]time.Time(nil), times...)
	sort.Slice(ts, func(i, j int) bool { return ts[i].After(ts[j]) })
	// Walk from the newest; a run starts at its oldest report.
	var starts []time.Time
	for i := 0; i < len(ts); i++ {
		start := ts[i]
		for i+1 < len(ts) && start.Sub(ts[i+1]) < runGap {
			i++
			start = ts[i]
		}
		starts = append(starts, start)
		if len(starts) == cadenceRuns {
			break
		}
	}
	runs = len(starts)
	if runs < 2 {
		return runs, 0
	}
	gaps := make([]time.Duration, runs-1)
	for i := range gaps {
		gaps[i] = starts[i].Sub(starts[i+1])
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	n := len(gaps)
	if n%2 == 1 {
		return runs, gaps[n/2]
	}
	return runs, (gaps[n/2-1] + gaps[n/2]) / 2
}

// Learned reports whether runs reports, the first span before the latest,
// show a cadence: at least 3 runs over at least a day.
func Learned(runs int, span time.Duration) bool {
	return runs >= learnRuns && span >= learnSpan
}

// DueAfter is how long after its last report an asset is overdue, and false
// when no further report is expected.
//
//   - A person's override: daily, overdue after 48 hours; weekly, after 8
//     days (a week and a day's grace); one-off, never.
//   - The agent: staleAfter (48 hours by default).
//   - A scan or manual upload with a learned cadence (usual > 0: at least
//     3 runs over at least a day, Learned): twice its usual gap, and at
//     least 48 hours. Otherwise never (one-off).
//   - An integration: twice its schedule, and at least staleAfter. Its
//     assets never open an incident; a failing integration has its own.
func DueAfter(source, override string, runs int, usual, staleAfter, schedule time.Duration) (time.Duration, bool) {
	if staleAfter <= 0 {
		staleAfter = DefaultStaleAfter
	}
	// A server the agent reports is never one-off: it would never say if
	// the agent stopped.
	if source == SourceAgent && override == ReportOneOff {
		override = ReportAuto
	}
	switch override {
	case ReportDaily:
		return 48 * time.Hour, true
	case ReportWeekly:
		return 8 * 24 * time.Hour, true
	case ReportOneOff:
		return 0, false
	}
	switch source {
	case SourceAgent:
		return staleAfter, true
	case SourceIntegration:
		return max(staleAfter, 2*schedule), true
	case SourceScan, SourceManual:
		if runs < learnRuns || usual <= 0 {
			return 0, false
		}
		return max(DefaultStaleAfter, 2*usual), true
	}
	return 0, false
}

func (s *Store) staleAfter() time.Duration {
	if s.StaleAfter > 0 {
		return s.StaleAfter
	}
	return DefaultStaleAfter
}

// RefreshReporting works out report_runs, report_usual and report_due_after
// for the given assets, or, with ids nil, for every asset not worked out
// yet (after migration 0064).
func (s *Store) RefreshReporting(ctx context.Context, ids []int64) error {
	for {
		n, err := refreshReporting(ctx, s.Pool, ids, s.staleAfter())
		if err != nil || ids != nil || n < refreshBatch {
			return err
		}
	}
}

const refreshBatch = 2000

func refreshReporting(ctx context.Context, db q, ids []int64, staleAfter time.Duration) (int, error) {
	cond, args := `a.report_runs IS NULL`, []any{}
	if ids != nil {
		cond, args = `a.id = ANY($1)`, []any{ids}
	}
	rows, err := db.Query(ctx, `SELECT a.id, a.report_source, a.report_override, COALESCE(EXTRACT(epoch FROM i.schedule)::bigint, 0),
		  ARRAY(SELECT c.received_at FROM collections c WHERE c.asset_id = a.id ORDER BY c.received_at DESC LIMIT 60),
		  (SELECT min(c.received_at) FROM collections c WHERE c.asset_id = a.id)
		FROM assets a LEFT JOIN integrations i ON i.id = a.report_integration_id
		WHERE a.merged_into IS NULL AND `+cond+fmt.Sprintf(` ORDER BY a.id LIMIT %d`, refreshBatch), args...)
	if err != nil {
		return 0, err
	}
	var (
		upd              []int64
		runsCol          []int32
		usualCol, dueCol []*int64
		id, schedule     int64
		source, override string
		times            []time.Time
		first            *time.Time
	)
	_, err = pgx.ForEachRow(rows, []any{&id, &source, &override, &schedule, &times, &first}, func() error {
		runs, usual := Cadence(times)
		if first == nil || len(times) == 0 || !Learned(runs, times[0].Sub(*first)) {
			usual = 0 // no cadence to learn from yet
		}
		var u, d *int64
		if usual > 0 {
			v := int64(usual / time.Second)
			u = &v
		}
		if due, ok := DueAfter(source, override, runs, usual, staleAfter, time.Duration(schedule)*time.Second); ok {
			v := int64(due / time.Second)
			d = &v
		}
		upd, runsCol, usualCol, dueCol = append(upd, id), append(runsCol, int32(runs)), append(usualCol, u), append(dueCol, d)
		return nil
	})
	if err != nil || len(upd) == 0 {
		return len(upd), err
	}
	_, err = db.Exec(ctx, `UPDATE assets a SET report_runs = v.runs,
		  report_usual = make_interval(secs => v.usual), report_due_after = make_interval(secs => v.due)
		FROM unnest($1::bigint[], $2::int[], $3::bigint[], $4::bigint[]) AS v(id, runs, usual, due)
		WHERE a.id = v.id`, upd, runsCol, usualCol, dueCol)
	return len(upd), err
}

// dueSQL is an asset's overdue interval ($1: the agent's stale period in
// seconds): the agent's follows STACKURITY_STALE_AFTER as it is now.
// A server the agent reports is always expected to report: its own period,
// or a daily or weekly override; never one-off, whatever the override says.
const dueSQL = `CASE WHEN a.report_source = 'agent' AND a.report_override NOT IN ('daily', 'weekly')
	THEN make_interval(secs => $1) ELSE a.report_due_after END`

// MarkStaleAssets flags assets whose next report is overdue (FR-03: stale
// data is visible, never healthy) and clears the flag on those no longer
// expected to report (scanned once, or set to one-off). Returns the number
// newly marked. maxAge is the agent's stale period (STACKURITY_STALE_AFTER).
func (s *Store) MarkStaleAssets(ctx context.Context, maxAge time.Duration) (int64, error) {
	if maxAge <= 0 {
		maxAge = s.staleAfter()
	}
	if err := s.RefreshReporting(ctx, nil); err != nil {
		return 0, err
	}
	return s.markStale(ctx, 0, maxAge)
}

// markStale applies the overdue rule to one asset, or to all with id 0, and
// queues re-evaluation of the assets that changed, so their findings'
// verification follows.
func (s *Store) markStale(ctx context.Context, id int64, staleAfter time.Duration) (int64, error) {
	var marked int64
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE assets a SET collection_status = 'stale'
			WHERE a.merged_into IS NULL AND a.collection_status NOT IN ('stale', 'removed') AND ($2 = 0 OR a.id = $2)
			  AND `+dueSQL+` IS NOT NULL AND a.last_seen < now() - `+dueSQL+` RETURNING a.id`, staleAfter.Seconds(), id)
		if err != nil {
			return err
		}
		stale, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			return err
		}
		marked = int64(len(stale))
		rows, err = tx.Query(ctx, `UPDATE assets a SET collection_status = CASE WHEN COALESCE((SELECT c.complete FROM collections c
			    WHERE c.asset_id = a.id ORDER BY c.received_at DESC, c.id DESC LIMIT 1), true) THEN 'ok' ELSE 'partial' END
			WHERE a.merged_into IS NULL AND a.collection_status = 'stale' AND ($2 = 0 OR a.id = $2)
			  AND (`+dueSQL+` IS NULL OR a.last_seen >= now() - `+dueSQL+`) RETURNING a.id`, staleAfter.Seconds(), id)
		if err != nil {
			return err
		}
		fresh, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			return err
		}
		changed := append(stale, fresh...)
		if len(changed) == 0 {
			return nil
		}
		_, err = tx.Exec(ctx, `INSERT INTO jobs (kind, payload, dedupe_key, run_at)
			SELECT 'evaluate', jsonb_build_object('asset_id', v), 'evaluate:asset:' || v, now() + interval '5 seconds'
			FROM unnest($1::bigint[]) AS v
			ON CONFLICT (COALESCE(workspace_id, 0), dedupe_key) WHERE dedupe_key IS NOT NULL AND done_at IS NULL AND failed_at IS NULL
			DO UPDATE SET requeue = true WHERE jobs.locked_at IS NOT NULL`, changed)
		return err
	})
	return marked, err
}

// recordReport stores a batch's reporting source on its asset and works out
// its cadence again; part of Ingest.
func recordReport(ctx context.Context, tx pgx.Tx, assetID int64, src ReportSource, staleAfter time.Duration) error {
	var integ *int64
	if src.IntegrationID > 0 {
		integ = &src.IntegrationID
	}
	// An asset set to one-off that the agent now reports goes back to
	// automatic: a server is never one-off (SetReportOverride).
	if _, err := tx.Exec(ctx, `UPDATE assets SET report_source = $2,
		report_integration_id = CASE WHEN $2 = 'integration' THEN COALESCE($3, CASE WHEN report_source = 'integration' THEN report_integration_id END) END,
		report_override = CASE WHEN $2 = 'agent' AND report_override = 'one_off' THEN 'auto' ELSE report_override END
		WHERE id = $1`, assetID, src.Source, integ); err != nil {
		return err
	}
	_, err := refreshReporting(ctx, tx, []int64{assetID}, staleAfter)
	return err
}

// SetReportOverride sets how often an asset is expected to report, works its
// expectation out again and applies it at once.
func (s *Store) SetReportOverride(ctx context.Context, id int64, override string) error {
	if !ValidReportOverride(override) {
		return fmt.Errorf("reporting must be auto, daily, weekly or one_off: %w", ErrInvalid)
	}
	var source string
	if err := s.Pool.QueryRow(ctx, `SELECT report_source FROM assets WHERE id = $1 AND merged_into IS NULL`, id).Scan(&source); err != nil {
		return notFound(err)
	}
	// One-off would hide a server whose agent stopped, for good.
	if override == ReportOneOff && source == SourceAgent {
		return fmt.Errorf("a server the agent reports cannot be one-off: it would never say if the agent stopped; delete the server if it is gone: %w", ErrInvalid)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE assets SET report_override = $2 WHERE id = $1`, id, override); err != nil {
		return err
	}
	if err := s.RefreshReporting(ctx, []int64{id}); err != nil {
		return err
	}
	_, err := s.markStale(ctx, id, s.staleAfter())
	return err
}

// reportingFrom builds an asset's Reporting from its columns (seconds).
func reportingFrom(source, override string, runs *int32, usual, due *int64, lastSeen time.Time) Reporting {
	r := Reporting{Source: source, Override: override, UsualSeconds: usual, DueAfterSeconds: due}
	if runs != nil {
		r.Runs = int(*runs)
	}
	switch {
	case override == ReportOneOff && source != SourceAgent || due == nil && runs != nil && (source == SourceScan || source == SourceManual):
		r.Mode = "one_off"
		t := lastSeen
		r.AsOf = &t
	case source == "":
		r.Mode = "unknown"
	case source == SourceAgent:
		r.Mode = "agent"
	case source == SourceIntegration:
		r.Mode = "integration"
	default:
		r.Mode = "scheduled"
	}
	return r
}

// oneOffSQL selects assets no further report is expected of: reported once
// by a scan or upload, or set to one-off.
const oneOffSQL = `a.merged_into IS NULL AND a.collection_status <> 'removed' AND (a.report_override = 'one_off' AND a.report_source <> 'agent'
	OR a.report_override = 'auto' AND a.report_source IN ('scan', 'manual') AND a.report_runs IS NOT NULL AND a.report_due_after IS NULL)`

// OneOffGroup counts the assets of one kind scanned once.
type OneOffGroup struct {
	Kind   string    `json:"kind"`
	Count  int       `json:"count"`
	Oldest time.Time `json:"oldest"`
	Newest time.Time `json:"newest"`
}

// OneOffAssets counts the assets scanned once, per kind, with the dates
// their results are from.
func (s *Store) OneOffAssets(ctx context.Context) ([]OneOffGroup, error) {
	rows, err := s.Pool.Query(ctx, `SELECT a.kind, count(*), min(a.last_seen), max(a.last_seen) FROM assets a
		WHERE `+oneOffSQL+` GROUP BY a.kind ORDER BY count(*) DESC, a.kind`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[OneOffGroup])
}

// AsOf is "26 Oct", or "12 Oct – 26 Oct" for results from several days.
func AsOf(oldest, newest, now time.Time) string {
	a, b := ReportDate(oldest, now), ReportDate(newest, now)
	if a == b {
		return a
	}
	return a + " – " + b
}
