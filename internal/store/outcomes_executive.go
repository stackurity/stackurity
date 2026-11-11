package store

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// OutcomeExecutive is what the executive view of Outcomes adds to the
// report: the trend of issues opened against issues fixed, the most overdue
// issues with their owner, open and overdue issues per owner, what is urgent
// on production and internet-facing assets, and exceptions. It counts with
// the report's own rules: fixed is remediated or removed and still resolved
// (the report's resolved), open is active (not snoozed or accepted) and
// overdue is past the issue's fix-by date, so the two views always agree.
type OutcomeExecutive struct {
	// Trend covers the report's window in periods of PeriodDays, oldest
	// first; the first may be shorter when the window does not divide.
	PeriodDays int             `json:"period_days"`
	Trend      []OutcomePeriod `json:"trend"`
	// Overdue lists the most overdue active issues: P1 first, then the
	// oldest fix-by date. The total is the report's open.overdue.
	Overdue      []OutcomeOverdue `json:"overdue_top"`
	OverdueLimit int              `json:"overdue_limit"`
	// Owners counts active and overdue issues per assignee, most overdue
	// first. An issue assigned to a person and a team counts under the
	// person. OwnersTotal is the number of owners before any trim.
	Owners      []OutcomeOwner    `json:"by_owner"`
	OwnersTotal int               `json:"owners_total"`
	Impact      OutcomeImpact     `json:"impact"`
	Exceptions  OutcomeExceptions `json:"exceptions"`
}

// OutcomePeriod is one period of the trend. Fixed counts findings
// remediated or removed in it and still resolved, as the report's resolved
// does, so the periods add up to it. Opened counts findings first seen or
// reopened in it, each once.
type OutcomePeriod struct {
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Opened int64     `json:"opened"`
	Fixed  int64     `json:"fixed"`
}

// OutcomeOverdue is one active issue past its fix-by date.
type OutcomeOverdue struct {
	FindingID      int64     `json:"finding_id"`
	Key            string    `json:"key"`
	Title          string    `json:"title"`
	Priority       string    `json:"priority"`
	KnownExploited bool      `json:"known_exploited"`
	AssetID        int64     `json:"asset_id"`
	AssetName      string    `json:"asset_name"`
	OwnerKind      string    `json:"owner_kind"` // user, team, or empty when unassigned
	OwnerID        int64     `json:"owner_id"`
	OwnerName      string    `json:"owner_name"`
	FirstSeen      time.Time `json:"first_seen"`
	FixDue         time.Time `json:"fix_due"`
}

// OutcomeOwner is one assignee's active issues now.
type OutcomeOwner struct {
	Kind    string `json:"kind"` // user, team, or empty for unassigned
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Open    int64  `json:"open"`
	Overdue int64  `json:"overdue"`
	Urgent  int64  `json:"urgent"` // P1 or P2
}

// OutcomeImpact counts the assets with an active P1 or P2 issue now, and of
// those how many are production (environment in the risk policy's
// production list) and internet-facing (the exposure risk scoring uses).
// EnvironmentKnown and ExposureKnown say for how many that was recorded:
// an asset with no record is not counted as either, and not as safe.
type OutcomeImpact struct {
	UrgentAssets      int64 `json:"urgent_assets"`
	EnvironmentKnown  int64 `json:"environment_known"`
	Production        int64 `json:"production"`
	ExposureKnown     int64 `json:"exposure_known"`
	Exposed           int64 `json:"exposed"`
	ExposedProduction int64 `json:"exposed_production"`
}

// OutcomeExceptions: requests to ignore waiting for a decision now, and
// snoozes or acceptances that ran out in the window (the issue went back to
// new for review), with how many of those are still open and active.
type OutcomeExceptions struct {
	Pending          int64      `json:"pending"`
	PendingSince     *time.Time `json:"pending_since"`
	Expired          int64      `json:"expired"`
	ExpiredStillOpen int64      `json:"expired_still_open"`
}

const (
	execOverdueLimit = 10
	execOwnersLimit  = 15
)

// activeOpen is an open finding nobody snoozed or accepted: the findings
// the SLA, the overdue counts and the dashboard count.
const activeOpen = `f.status = 'open' AND f.state IN ('new', 'acknowledged', 'in_progress')`

// execPeriods splits [from, to) into periods of step days, ending at to.
func execPeriods(from, to time.Time, step int) (starts, ends []time.Time) {
	for end := to; end.After(from); end = end.AddDate(0, 0, -step) {
		start := end.AddDate(0, 0, -step)
		if start.Before(from) {
			start = from
		}
		starts = append(starts, start)
		ends = append(ends, end)
	}
	for i, j := 0, len(starts)-1; i < j; i, j = i+1, j-1 {
		starts[i], starts[j] = starts[j], starts[i]
		ends[i], ends[j] = ends[j], ends[i]
	}
	return starts, ends
}

// OutcomesExecutive builds the executive figures for [from, to); from is the
// report's own From (OutcomesReport may start it later). production is the
// risk policy's production environments.
func (s *Store) OutcomesExecutive(ctx context.Context, from, to time.Time, production []string) (*OutcomeExecutive, error) {
	step := 7
	if to.Sub(from) > 91*24*time.Hour {
		step = 28
	}
	x := &OutcomeExecutive{PeriodDays: step, Trend: []OutcomePeriod{}, Overdue: []OutcomeOverdue{}, OverdueLimit: execOverdueLimit,
		Owners: []OutcomeOwner{}}

	starts, ends := execPeriods(from, to, step)
	// One pass over the window's findings and events, then counted per
	// period (a CTE used twice is computed once).
	rows, err := s.Pool.Query(ctx, `WITH o AS (
		    SELECT f.id, f.first_seen AS at FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		    WHERE f.first_seen >= $3 AND f.first_seen < $4
		    UNION ALL
		    SELECT e.finding_id, e.at FROM finding_events e JOIN findings f ON f.id = e.finding_id
		      JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		    WHERE e.action = 'reopened' AND e.at >= $3 AND e.at < $4),
		  fx AS (
		    SELECT f.resolved_at AS at FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		    WHERE f.status = 'resolved' AND f.resolved_at >= $3 AND f.resolved_at < $4 AND `+remedied("f")+`)
		SELECT p.s, p.e,
		  (SELECT count(DISTINCT o.id) FROM o WHERE o.at >= p.s AND o.at < p.e),
		  (SELECT count(*) FROM fx WHERE fx.at >= p.s AND fx.at < p.e)
		FROM unnest($1::timestamptz[], $2::timestamptz[]) AS p(s, e) ORDER BY p.s`, starts, ends, from, to)
	if err != nil {
		return nil, err
	}
	if x.Trend, err = pgx.CollectRows(rows, pgx.RowToStructByPos[OutcomePeriod]); err != nil {
		return nil, err
	}
	// Postgres keeps microseconds; report the exact bounds the caller gave
	// so the first start is the report's From and the last end its To.
	for i := range x.Trend {
		x.Trend[i].Start, x.Trend[i].End = starts[i], ends[i]
	}

	rows, err = s.Pool.Query(ctx, `SELECT f.id, f.key, f.title, f.priority, COALESCE((f.evidence->>'known_exploited')::boolean, false),
		f.asset_id, a.name,
		CASE WHEN f.assignee_user_id IS NOT NULL THEN 'user' WHEN f.assignee_team_id IS NOT NULL THEN 'team' ELSE '' END,
		COALESCE(f.assignee_user_id, f.assignee_team_id, 0), COALESCE(au.email, t.name, ''), f.first_seen, f.fix_due
		FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		LEFT JOIN users au ON au.id = f.assignee_user_id LEFT JOIN teams t ON t.id = f.assignee_team_id
		WHERE `+activeOpen+` AND f.fix_due < now()
		ORDER BY f.priority, f.fix_due, f.id LIMIT $1`, execOverdueLimit)
	if err != nil {
		return nil, err
	}
	if x.Overdue, err = pgx.CollectRows(rows, pgx.RowToStructByPos[OutcomeOverdue]); err != nil {
		return nil, err
	}

	rows, err = s.Pool.Query(ctx, `SELECT
		CASE WHEN f.assignee_user_id IS NOT NULL THEN 'user' WHEN f.assignee_team_id IS NOT NULL THEN 'team' ELSE '' END,
		COALESCE(f.assignee_user_id, f.assignee_team_id, 0), COALESCE(max(au.email), max(t.name), ''),
		count(*), count(*) FILTER (WHERE f.fix_due < now()), count(*) FILTER (WHERE f.priority IN ('P1', 'P2'))
		FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		LEFT JOIN users au ON au.id = f.assignee_user_id LEFT JOIN teams t ON t.id = f.assignee_team_id
		WHERE `+activeOpen+` GROUP BY 1, 2`)
	if err != nil {
		return nil, err
	}
	if x.Owners, err = pgx.CollectRows(rows, pgx.RowToStructByPos[OutcomeOwner]); err != nil {
		return nil, err
	}
	sort.Slice(x.Owners, func(i, j int) bool {
		a, b := x.Owners[i], x.Owners[j]
		if a.Overdue != b.Overdue {
			return a.Overdue > b.Overdue
		}
		if a.Open != b.Open {
			return a.Open > b.Open
		}
		return a.Name < b.Name
	})
	x.OwnersTotal = len(x.Owners)
	if len(x.Owners) > execOwnersLimit {
		x.Owners = x.Owners[:execOwnersLimit]
	}

	prod := make([]string, 0, len(production))
	for _, e := range production {
		prod = append(prod, strings.ToLower(e))
	}
	if err := s.Pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE env <> ''), count(*) FILTER (WHERE lower(env) = ANY($1)),
		count(*) FILTER (WHERE exposed IS NOT NULL), count(*) FILTER (WHERE exposed),
		count(*) FILTER (WHERE exposed AND lower(env) = ANY($1))
		FROM (SELECT a.environment AS env, `+effectiveExposure+` AS exposed FROM assets a WHERE a.merged_into IS NULL
		  AND EXISTS (SELECT 1 FROM findings f WHERE f.asset_id = a.id AND `+activeOpen+` AND f.priority IN ('P1', 'P2'))) x`, prod).
		Scan(&x.Impact.UrgentAssets, &x.Impact.EnvironmentKnown, &x.Impact.Production, &x.Impact.ExposureKnown, &x.Impact.Exposed,
			&x.Impact.ExposedProduction); err != nil {
		return nil, err
	}

	// A request counts when every issue it is about is on an asset the
	// caller can see, as the approval inbox decides who may decide it.
	if err := s.Pool.QueryRow(ctx, `SELECT count(*), min(r.requested_at) FROM ignore_requests r WHERE r.status = 'pending'
		AND NOT EXISTS (SELECT 1 FROM unnest(r.finding_ids) x(id) LEFT JOIN findings f ON f.id = x.id
		  LEFT JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL WHERE a.id IS NULL)`).
		Scan(&x.Exceptions.Pending, &x.Exceptions.PendingSince); err != nil {
		return nil, err
	}
	if err := s.Pool.QueryRow(ctx, `SELECT count(DISTINCT e.finding_id), count(DISTINCT e.finding_id) FILTER (WHERE `+activeOpen+`)
		FROM finding_events e JOIN findings f ON f.id = e.finding_id JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		WHERE e.action = 'expired' AND e.at >= $1 AND e.at < $2`, from, to).
		Scan(&x.Exceptions.Expired, &x.Exceptions.ExpiredStillOpen); err != nil {
		return nil, err
	}
	return x, nil
}
