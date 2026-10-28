package store

import (
	"context"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// OutcomesReport measures remediation over a window: how long findings stay
// open, how they were resolved, whether they come back, SLA compliance and,
// where automatic remediation ran, how it went. Every rate comes with the
// counts it is made of, and is absent when there is nothing to divide by.
type OutcomesReport struct {
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	GeneratedAt time.Time `json:"generated_at"`
	// EventsSince is when the matcher started recording resolutions and
	// reopenings; reopen counts before it are unknown.
	EventsSince *time.Time `json:"events_since"`

	// Resolved counts findings remediated in the window and still resolved:
	// Remediated (the installed version changed) plus Removed (the
	// component is gone). Time to remedy and SLA count the same findings.
	Resolved   int64 `json:"resolved"`
	Remediated int64 `json:"remediated"`
	Removed    int64 `json:"removed"`
	// NotRemediation counts findings that closed in the window with nothing
	// changed on the asset (advisory withdrawn or changed, still affected
	// after an upgrade, no longer evaluated). They are not in Resolved,
	// time to remedy or SLA.
	NotRemediation OutcomeNotRemediation `json:"closed_not_remediation"`
	TimeToRemedy   []OutcomeTiming       `json:"time_to_remedy"` // by priority and kind, plus totals
	Causes         []OutcomeCause        `json:"causes"`
	SLA            []OutcomeSLA          `json:"sla"`
	Reopened       OutcomeReopened       `json:"reopened"`
	Open           OutcomeOpen           `json:"open"`
	Remediation    *OutcomeRemedies      `json:"remediation"` // nil when no plan or action falls in the window
}

// OutcomeTiming is the time from detection (or the last reopening) to
// resolution. Priority or Kind "all" are totals.
type OutcomeTiming struct {
	Priority   string   `json:"priority"`
	Kind       string   `json:"kind"`
	Resolved   int64    `json:"resolved"`
	MeanDays   *float64 `json:"mean_days"`
	MedianDays *float64 `json:"median_days"`
}

// OutcomeNotRemediation counts closures that are not remediation, by
// resolution kind (advisory_withdrawn, advisory_changed, superseded,
// not_evaluated, other).
type OutcomeNotRemediation struct {
	Total  int64            `json:"total"`
	ByKind map[string]int64 `json:"by_kind"`
}

// OutcomeCause groups closures by what closed them. Evidence is
// "fresh_collection" when a newer complete inventory showed the change,
// "intelligence" when advisory or lifecycle data changed instead, and
// "coverage" when the row could no longer be evaluated. Remediation is true
// for the causes counted as remediation (upgraded, remediation, removed).
type OutcomeCause struct {
	// upgraded, remediation, removed, superseded, advisory_withdrawn,
	// advisory_changed, not_evaluated, other
	Cause       string `json:"cause"`
	Kind        string `json:"resolution_kind"`
	Evidence    string `json:"evidence"`
	Count       int64  `json:"count"`
	Remediation bool   `json:"counts_as_remediation"`
}

// OutcomeSLA compares findings with the risk policy's fix deadline for
// their priority, counted from first detection.
type OutcomeSLA struct {
	Priority      string   `json:"priority"`
	FixDays       int      `json:"fix_days"`
	Resolved      int64    `json:"resolved"`
	ResolvedInSLA int64    `json:"resolved_within_sla"`
	Rate          *float64 `json:"rate"`
	OpenActive    int64    `json:"open_active"`  // open now, not suppressed or accepted
	OpenOverdue   int64    `json:"open_overdue"` // of those, past the deadline
}

type OutcomeReopened struct {
	Events   int64 `json:"events"`   // reopenings in the window
	Findings int64 `json:"findings"` // distinct findings reopened in the window
	// Of the resolutions recorded in the window, how many were reopened later.
	ResolutionEvents  int64           `json:"resolution_events"`
	LaterReopened     int64           `json:"later_reopened"`
	Rate              *float64        `json:"rate"`
	Recent            []OutcomeReopen `json:"recent"`
	RecentTruncatedAt int             `json:"recent_limit"`
}

type OutcomeReopen struct {
	FindingID          int64     `json:"finding_id"`
	Key                string    `json:"key"`
	Component          string    `json:"component"`
	Version            string    `json:"version"`
	AssetID            int64     `json:"asset_id"`
	AssetName          string    `json:"asset_name"`
	ReopenedAt         time.Time `json:"reopened_at"`
	PreviousResolution string    `json:"previous_resolution"`
}

// OutcomeOpen describes what is open now, for context.
type OutcomeOpen struct {
	Active     int64 `json:"active"`
	Overdue    int64 `json:"overdue"`
	Excepted   int64 `json:"excepted"`    // suppressed or risk accepted
	StaleAsset int64 `json:"stale_asset"` // evidence is old: the asset stopped reporting
	// ByEvidence counts open findings by evidence state (evidenceState):
	// confirmed, needs_validation, stale, stale_intelligence, unknown.
	ByEvidence map[string]int64 `json:"by_evidence"`
}

// evidenceState is a finding's evidence state for reports: its verification,
// except that confirmed findings evaluated against a stale feed are
// stale_intelligence (the version is confirmed, the advisory data was not
// fresh).
const evidenceState = `CASE WHEN f.verification = 'confirmed' AND COALESCE((f.evidence->>'feed_stale')::boolean, false)
	THEN 'stale_intelligence' ELSE f.verification END`

// openByEvidence counts open findings on current assets by evidence state.
func (s *Store) openByEvidence(ctx context.Context) (map[string]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+evidenceState+`, count(*) FROM findings f
		JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL WHERE f.status = 'open' GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

type OutcomeRemedies struct {
	Plans       map[string]int64 `json:"plans"`   // by status, created in the window
	Actions     map[string]int64 `json:"actions"` // upgrades and pull requests by status
	Finished    int64            `json:"finished"`
	Verified    int64            `json:"verified"`
	Failed      int64            `json:"failed"`
	RolledBack  int64            `json:"rolled_back"`
	SuccessRate *float64         `json:"success_rate"` // verified / (verified + failed + rolled back)
	Rollbacks   map[string]int64 `json:"rollback_actions"`
	Failures    []OutcomeFailure `json:"recent_failures"`
}

type OutcomeFailure struct {
	ActionID    int64     `json:"action_id"`
	PlanID      int64     `json:"plan_id"`
	AssetID     int64     `json:"asset_id"`
	AssetName   string    `json:"asset_name"`
	Package     string    `json:"package"`
	FromVersion string    `json:"from_version"`
	ToVersion   string    `json:"to_version"`
	Status      string    `json:"status"`
	Error       string    `json:"error"`
	At          time.Time `json:"at"`
}

const outcomeRecent = 20

// closedInWindow selects findings resolved in [$1, $2), whatever closed
// them, with their cause (resolutionCause) and whether that is remediation.
var closedInWindow = `WITH res AS (
	SELECT f.id, f.kind, f.priority, f.resolution_kind, ` + resolutionCause("f") + ` AS cause, ` + remedied("f") + ` AS counted
	FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
	WHERE f.status = 'resolved' AND f.resolved_at >= $1 AND f.resolved_at < $2)
`

// resolvedInWindow selects findings remediated in [$1, $2) (see remedied)
// with the start of their last open episode. Findings closed with nothing
// changed on the asset are not remediation and are left out.
var resolvedInWindow = `WITH res AS (
	SELECT f.id, f.kind, f.priority, f.resolution, f.first_seen, f.resolved_at,
	  COALESCE((SELECT max(e.at) FROM finding_events e WHERE e.finding_id = f.id AND e.action = 'reopened'
	    AND e.at <= f.resolved_at), f.first_seen) AS opened_at
	FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
	WHERE f.status = 'resolved' AND f.resolved_at >= $1 AND f.resolved_at < $2 AND ` + remedied("f") + `)
`

// OutcomesReport builds the report for [from, to). fixDays is the risk
// policy's fix deadline per priority.
func (s *Store) OutcomesReport(ctx context.Context, from, to time.Time, fixDays map[string]int) (*OutcomesReport, error) {
	r := &OutcomesReport{From: from, To: to, GeneratedAt: time.Now().UTC(), TimeToRemedy: []OutcomeTiming{}, Causes: []OutcomeCause{},
		NotRemediation: OutcomeNotRemediation{ByKind: map[string]int64{}},
		SLA:            []OutcomeSLA{}, Reopened: OutcomeReopened{Recent: []OutcomeReopen{}, RecentTruncatedAt: outcomeRecent}}
	var since time.Time
	if err := s.Pool.QueryRow(ctx, `SELECT applied_at FROM schema_migrations WHERE name = '0019_upgrade_outcomes'`).Scan(&since); err == nil {
		r.EventsSince = &since
	}

	// Time to remedy, with totals per priority, per kind and overall.
	rows, err := s.Pool.Query(ctx, resolvedInWindow+`SELECT COALESCE(priority, 'all'), COALESCE(kind, 'all'), count(*),
		avg(extract(epoch FROM resolved_at - opened_at) / 86400),
		percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM resolved_at - opened_at) / 86400)
		FROM res GROUP BY GROUPING SETS ((priority, kind), (priority), (kind), ()) ORDER BY 1, 2`, from, to)
	if err != nil {
		return nil, err
	}
	r.TimeToRemedy, err = pgx.CollectRows(rows, pgx.RowToStructByPos[OutcomeTiming])
	if err != nil {
		return nil, err
	}
	for _, t := range r.TimeToRemedy {
		if t.Priority == "all" && t.Kind == "all" {
			r.Resolved = t.Resolved
		}
	}

	// Causes, from the resolution kind the matcher recorded: remediation
	// first, then what closed findings without it.
	rows, err = s.Pool.Query(ctx, closedInWindow+`SELECT cause, resolution_kind,
		  CASE WHEN resolution_kind IN ('advisory_withdrawn', 'advisory_changed') THEN 'intelligence'
		    WHEN resolution_kind = 'not_evaluated' THEN 'coverage'
		    WHEN resolution_kind IN ('remediated', 'removed', 'superseded') THEN 'fresh_collection' ELSE 'unknown' END,
		  count(*), counted
		FROM res GROUP BY 1, 2, 5 ORDER BY 5 DESC, 4 DESC, 1`, from, to)
	if err != nil {
		return nil, err
	}
	if r.Causes, err = pgx.CollectRows(rows, pgx.RowToStructByPos[OutcomeCause]); err != nil {
		return nil, err
	}
	for _, c := range r.Causes {
		switch {
		case c.Kind == ResolutionRemediated:
			r.Remediated += c.Count
		case c.Kind == ResolutionRemoved:
			r.Removed += c.Count
		default:
			k := c.Kind
			if k == "" {
				k = ResolutionOther
			}
			r.NotRemediation.ByKind[k] += c.Count
			r.NotRemediation.Total += c.Count
		}
	}

	// SLA, against the current policy's fix deadline per priority.
	prios := make([]string, 0, len(fixDays))
	for p := range fixDays {
		prios = append(prios, p)
	}
	sort.Strings(prios)
	days := make([]int32, len(prios))
	for i, p := range prios {
		days[i] = int32(fixDays[p])
	}
	sla := map[string]*OutcomeSLA{}
	for _, p := range prios {
		sla[p] = &OutcomeSLA{Priority: p, FixDays: fixDays[p]}
	}
	rows, err = s.Pool.Query(ctx, resolvedInWindow+`SELECT res.priority, count(*),
		count(*) FILTER (WHERE res.resolved_at <= res.first_seen + make_interval(days => d.days))
		FROM res JOIN unnest($3::text[], $4::int[]) AS d(priority, days) ON d.priority = res.priority GROUP BY 1`, from, to, prios, days)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p string
		var n, in int64
		if err := rows.Scan(&p, &n, &in); err != nil {
			rows.Close()
			return nil, err
		}
		sla[p].Resolved, sla[p].ResolvedInSLA = n, in
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	const active = `f.state IN ('new', 'acknowledged', 'in_progress')`
	rows, err = s.Pool.Query(ctx, `SELECT f.priority, count(*) FILTER (WHERE `+active+`),
		count(*) FILTER (WHERE `+active+` AND d.days IS NOT NULL AND now() > f.first_seen + make_interval(days => d.days)),
		count(*) FILTER (WHERE f.state IN ('suppressed', 'risk_accepted')), count(*) FILTER (WHERE f.verification = 'stale')
		FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		LEFT JOIN unnest($1::text[], $2::int[]) AS d(priority, days) ON d.priority = f.priority
		WHERE f.status = 'open' GROUP BY 1`, prios, days)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p string
		var act, over, exc, stale int64
		if err := rows.Scan(&p, &act, &over, &exc, &stale); err != nil {
			rows.Close()
			return nil, err
		}
		if x := sla[p]; x != nil {
			x.OpenActive, x.OpenOverdue = act, over
		}
		r.Open.Active += act
		r.Open.Overdue += over
		r.Open.Excepted += exc
		r.Open.StaleAsset += stale
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if r.Open.ByEvidence, err = s.openByEvidence(ctx); err != nil {
		return nil, err
	}
	for _, p := range prios {
		x := sla[p]
		x.Rate = ratio(x.ResolvedInSLA, x.Resolved)
		r.SLA = append(r.SLA, *x)
	}

	// Reopened findings.
	const scoped = ` JOIN findings f ON f.id = e.finding_id JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL`
	if err := s.Pool.QueryRow(ctx, `SELECT count(*), count(DISTINCT e.finding_id) FROM finding_events e`+scoped+`
		WHERE e.action = 'reopened' AND e.at >= $1 AND e.at < $2`, from, to).Scan(&r.Reopened.Events, &r.Reopened.Findings); err != nil {
		return nil, err
	}
	if err := s.Pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE EXISTS (SELECT 1 FROM finding_events o
		  WHERE o.finding_id = e.finding_id AND o.action = 'reopened' AND o.at >= e.at AND o.id > e.id))
		FROM finding_events e`+scoped+` WHERE e.action = 'resolved' AND e.at >= $1 AND e.at < $2`, from, to).
		Scan(&r.Reopened.ResolutionEvents, &r.Reopened.LaterReopened); err != nil {
		return nil, err
	}
	r.Reopened.Rate = ratio(r.Reopened.LaterReopened, r.Reopened.ResolutionEvents)
	rows, err = s.Pool.Query(ctx, `SELECT f.id, f.key, CASE WHEN c.namespace = '' THEN c.name ELSE c.namespace || '/' || c.name END,
		i.version, f.asset_id, a.name, e.at, COALESCE(e.detail->>'resolution', '')
		FROM finding_events e`+scoped+` JOIN components c ON c.id = f.component_id JOIN inventory i ON i.id = f.inventory_id
		WHERE e.action = 'reopened' AND e.at >= $1 AND e.at < $2 ORDER BY e.at DESC, e.id DESC LIMIT $3`, from, to, outcomeRecent)
	if err != nil {
		return nil, err
	}
	if r.Reopened.Recent, err = pgx.CollectRows(rows, pgx.RowToStructByPos[OutcomeReopen]); err != nil {
		return nil, err
	}

	rem, err := s.outcomeRemedies(ctx, from, to)
	if err != nil {
		return nil, err
	}
	r.Remediation = rem
	return r, nil
}

// outcomeRemedies summarises remediation plans and actions created in the
// window (the paid edition creates them; the tables are in the core schema).
func (s *Store) outcomeRemedies(ctx context.Context, from, to time.Time) (*OutcomeRemedies, error) {
	m := &OutcomeRemedies{Plans: map[string]int64{}, Actions: map[string]int64{}, Rollbacks: map[string]int64{}, Failures: []OutcomeFailure{}}
	rows, err := s.Pool.Query(ctx, `SELECT status, count(*) FROM remediation_plans WHERE created_at >= $1 AND created_at < $2 GROUP BY 1`, from, to)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var st string
		var n int64
		if err := rows.Scan(&st, &n); err != nil {
			rows.Close()
			return nil, err
		}
		m.Plans[st] = n
	}
	rows.Close()
	rows, err = s.Pool.Query(ctx, `SELECT kind, status, count(*) FROM remediation_actions WHERE created_at >= $1 AND created_at < $2 GROUP BY 1, 2`, from, to)
	if err != nil {
		return nil, err
	}
	found := len(m.Plans) > 0
	for rows.Next() {
		var kind, st string
		var n int64
		if err := rows.Scan(&kind, &st, &n); err != nil {
			rows.Close()
			return nil, err
		}
		found = true
		if kind == "package_rollback" {
			m.Rollbacks[st] += n
			continue
		}
		m.Actions[st] += n
		switch st {
		case "verified":
			m.Verified += n
		case "failed":
			m.Failed += n
		case "rolled_back":
			m.RolledBack += n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	m.Finished = m.Verified + m.Failed + m.RolledBack
	m.SuccessRate = ratio(m.Verified, m.Finished)
	rows, err = s.Pool.Query(ctx, `SELECT ra.id, ra.plan_id, ra.asset_id, a.name, ra.package, ra.from_version, ra.to_version, ra.status,
		ra.error, COALESCE(ra.applied_at, ra.dispatched_at, ra.created_at)
		FROM remediation_actions ra JOIN assets a ON a.id = ra.asset_id
		WHERE ra.status IN ('failed', 'rolled_back') AND ra.created_at >= $1 AND ra.created_at < $2
		ORDER BY ra.created_at DESC, ra.id DESC LIMIT 10`, from, to)
	if err != nil {
		return nil, err
	}
	if m.Failures, err = pgx.CollectRows(rows, pgx.RowToStructByPos[OutcomeFailure]); err != nil {
		return nil, err
	}
	return m, nil
}

// ratio is n/d, or nil when d is zero.
func ratio(n, d int64) *float64 {
	if d == 0 {
		return nil
	}
	v := float64(n) / float64(d)
	return &v
}
