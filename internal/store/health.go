package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/risk"
)

// JobCount is the number of jobs of one kind in one state: queued (due and
// waiting for a worker), scheduled (waiting for its time, e.g. a retry
// backoff), running, or failed (gave up within the last 24 hours).
type JobCount struct {
	Kind  string `json:"kind"`
	State string `json:"state"`
	Count int64  `json:"count"`
}

// JobStats summarises the queue across workspaces (system scope), with the
// age in seconds of the oldest job that is due but not running.
func (s *Store) JobStats(ctx context.Context) ([]JobCount, float64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT kind,
		  CASE WHEN failed_at IS NOT NULL THEN 'failed'
		       WHEN locked_at IS NOT NULL AND locked_at >= now() - make_interval(secs => $1) THEN 'running'
		       WHEN run_at <= now() THEN 'queued'
		       ELSE 'scheduled' END AS state,
		  count(*)
		FROM jobs
		WHERE done_at IS NULL AND (failed_at IS NULL OR failed_at >= now() - interval '24 hours')
		GROUP BY 1, 2 ORDER BY 1, 2`, s.lockTimeout().Seconds())
	if err != nil {
		return nil, 0, err
	}
	counts, err := pgx.CollectRows(rows, pgx.RowToStructByPos[JobCount])
	if err != nil {
		return nil, 0, err
	}
	var oldest float64
	err = s.Pool.QueryRow(ctx, `SELECT COALESCE(extract(epoch FROM now() - min(run_at)), 0)::float8 FROM jobs
		WHERE done_at IS NULL AND failed_at IS NULL AND run_at <= now()
		  AND (locked_at IS NULL OR locked_at < now() - make_interval(secs => $1))`, s.lockTimeout().Seconds()).Scan(&oldest)
	return counts, oldest, err
}

// CountStaleAssets counts assets that stopped reporting, across workspaces
// in system scope.
func (s *Store) CountStaleAssets(ctx context.Context) (int64, error) {
	var n int64
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM assets WHERE merged_into IS NULL AND collection_status = 'stale'`).Scan(&n)
	return n, err
}

// DeliveryCount is the number of notification deliveries to one kind of
// channel in one state: pending (waiting for its first attempt, its time or
// quiet hours to end), retrying (a send failed and another attempt is
// scheduled), held (kept for the next digest by a rate limit) or failed (ran
// out of attempts within the last 24 hours). Deliveries to disabled
// channels are left out unless they failed.
type DeliveryCount struct {
	Kind  string `json:"kind"`
	State string `json:"state"`
	Count int64  `json:"count"`
}

// ChannelCount is the number of enabled channels of one kind.
type ChannelCount struct {
	Kind  string `json:"kind"`
	Count int64  `json:"count"`
}

// DeliveryStats summarises notification deliveries across workspaces
// (system scope), with the age in seconds of the oldest delivery that is due
// but has not been claimed for sending, and the enabled channels whose last
// send failed.
func (s *Store) DeliveryStats(ctx context.Context) ([]DeliveryCount, float64, []ChannelCount, error) {
	rows, err := s.Pool.Query(ctx, `SELECT c.kind,
		  CASE WHEN d.status = 'failed' THEN 'failed'
		       WHEN d.status = 'held' THEN 'held'
		       WHEN d.attempts > 0 AND d.last_error <> '' THEN 'retrying'
		       ELSE 'pending' END AS state,
		  count(*)
		FROM deliveries d JOIN channels c ON c.id = d.channel_id
		WHERE (d.status IN ('pending', 'held') AND c.enabled)
		   OR (d.status = 'failed' AND d.failed_at >= now() - interval '24 hours')
		GROUP BY 1, 2 ORDER BY 1, 2`)
	if err != nil {
		return nil, 0, nil, err
	}
	counts, err := pgx.CollectRows(rows, pgx.RowToStructByPos[DeliveryCount])
	if err != nil {
		return nil, 0, nil, err
	}
	var oldest float64
	if err := s.Pool.QueryRow(ctx, `SELECT COALESCE(extract(epoch FROM now() - min(d.next_attempt)), 0)::float8
		FROM deliveries d JOIN channels c ON c.id = d.channel_id
		WHERE d.status = 'pending' AND c.enabled AND d.next_attempt <= now()`).Scan(&oldest); err != nil {
		return nil, 0, nil, err
	}
	rows, err = s.Pool.Query(ctx, `SELECT kind, count(*) FROM channels WHERE enabled AND last_error <> '' GROUP BY 1 ORDER BY 1`)
	if err != nil {
		return nil, 0, nil, err
	}
	failing, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ChannelCount])
	return counts, oldest, failing, err
}

// The queries below feed the platform health check. They run in system
// scope and return aggregates over every workspace, plus named items for one
// workspace only (viewerWS, the instance administrator's active workspace;
// 0 for none), so a report never names another workspace's assets,
// integrations or channels.

// HealthGroup is a set of affected objects of one kind across workspaces.
type HealthGroup struct {
	Count int64 // affected objects in every workspace
	// Severe counts the more serious ones: production assets (silent
	// collectors), integrations failing for two schedules or more, channels
	// with deliveries that were given up.
	Severe     int64
	Workspaces int64 // workspaces with at least one
	// LastSuccess is the most recent success among them (the newest report,
	// sync or delivery); nil when none ever succeeded.
	LastSuccess *time.Time
	Items       []HealthItem // in viewerWS only, at most the limit asked for
}

// HealthItem is one affected object in the viewer's workspace.
type HealthItem struct {
	ID          int64
	Name        string
	Detail      string
	LastSuccess *time.Time
	LastError   string
	Severe      bool
}

// JobKindHealth summarises the jobs of one kind that failed in the last 24
// hours or are being retried.
type JobKindHealth struct {
	Kind         string
	Failed       int64 // ran out of retries in the last 24 hours
	Retrying     int64 // pending after at least one failed attempt
	RetriedOften int64 // pending after three or more attempts
	Workspaces   int64 // workspaces with failed or retrying jobs (platform jobs have none)
	Platform     bool  // some of them are platform jobs (no workspace)
	LastSuccess  *time.Time
	LastError    string
}

// JobKindHealth returns, per job kind with failed or retrying jobs, the
// counts, the last completed job and the latest error.
func (s *Store) JobKindHealth(ctx context.Context) ([]JobKindHealth, error) {
	rows, err := s.Pool.Query(ctx, `WITH bad AS (
		  SELECT * FROM jobs WHERE (failed_at >= now() - interval '24 hours')
		     OR (done_at IS NULL AND failed_at IS NULL AND attempts > 0 AND last_error <> ''))
		SELECT b.kind,
		  count(*) FILTER (WHERE b.failed_at IS NOT NULL),
		  count(*) FILTER (WHERE b.failed_at IS NULL),
		  count(*) FILTER (WHERE b.failed_at IS NULL AND b.attempts >= 3),
		  count(DISTINCT b.workspace_id), bool_or(b.workspace_id IS NULL),
		  (SELECT max(done_at) FROM jobs d WHERE d.kind = b.kind AND d.done_at IS NOT NULL),
		  (SELECT l.last_error FROM bad l WHERE l.kind = b.kind ORDER BY COALESCE(l.failed_at, l.run_at) DESC, l.id DESC LIMIT 1)
		FROM bad b GROUP BY b.kind ORDER BY b.kind`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[JobKindHealth])
}

// productionAsset is true when a's environment is one its workspace's risk
// policy treats as production ($1, the default list, when the workspace never
// saved a policy).
const productionAsset = `lower(a.environment) IN (SELECT lower(e) FROM jsonb_array_elements_text(COALESCE(
	  (SELECT CASE WHEN jsonb_typeof(st.value->'production_environments') = 'array' THEN st.value->'production_environments' ELSE '[]'::jsonb END
	   FROM settings st WHERE st.workspace_id = a.workspace_id AND st.key = 'risk_policy' AND st.value ? 'production_environments'),
	  $1::jsonb)) e)`

func defaultProductionEnvs() []byte {
	b, _ := json.Marshal(risk.DefaultPolicy().ProductionEnvironments)
	return b
}

// healthGroup runs an aggregate query (count, severe, workspaces, last
// success) and an item query for viewerWS returning id, name, detail, last
// success, last error, severe. With prod, both take $1 (the default
// production environments) and the item query $2 (workspace) and $3 (limit);
// without, the item query takes $1 (workspace) and $2 (limit).
func (s *Store) healthGroup(ctx context.Context, prod bool, agg, items string, viewerWS int64, limit int) (*HealthGroup, error) {
	g := &HealthGroup{}
	var pre []any
	if prod {
		pre = []any{defaultProductionEnvs()}
	}
	if err := s.Pool.QueryRow(ctx, agg, pre...).Scan(&g.Count, &g.Severe, &g.Workspaces, &g.LastSuccess); err != nil {
		return nil, err
	}
	if g.Count == 0 || viewerWS == 0 || limit <= 0 {
		return g, nil
	}
	rows, err := s.Pool.Query(ctx, items, append(pre, viewerWS, limit)...)
	if err != nil {
		return nil, err
	}
	g.Items, err = pgx.CollectRows(rows, pgx.RowToStructByPos[HealthItem])
	return g, err
}

// SilentCollectors are assets that stopped reporting (collection status
// stale): their collector, agent or integration sends nothing any more.
func (s *Store) SilentCollectors(ctx context.Context, viewerWS int64, limit int) (*HealthGroup, error) {
	return s.healthGroup(ctx, true, `SELECT count(*), count(*) FILTER (WHERE `+productionAsset+`), count(DISTINCT a.workspace_id), max(a.last_seen)
		FROM assets a WHERE a.merged_into IS NULL AND a.collection_status = 'stale'`,
		`SELECT a.id, a.name, a.kind || COALESCE(' via ' || (SELECT c.collector_id FROM collections c WHERE c.asset_id = a.id
		   ORDER BY c.received_at DESC LIMIT 1), ''), a.last_seen, '', `+productionAsset+`
		FROM assets a WHERE a.merged_into IS NULL AND a.collection_status = 'stale' AND a.workspace_id = $2
		ORDER BY 6 DESC, a.last_seen DESC, a.id LIMIT $3`, viewerWS, limit)
}

// ProductionCoverageGaps are production assets with a collection scope that
// failed or was only partly checked, so findings on them may be missing.
func (s *Store) ProductionCoverageGaps(ctx context.Context, viewerWS int64, limit int) (*HealthGroup, error) {
	const gap = `EXISTS (SELECT 1 FROM coverage c WHERE c.asset_id = a.id AND c.status IN ('failed', 'partial'))`
	return s.healthGroup(ctx, true, `SELECT count(*), count(*), count(DISTINCT a.workspace_id),
		  (SELECT max(c.last_success) FROM coverage c JOIN assets a ON a.id = c.asset_id
		   WHERE c.status IN ('failed', 'partial') AND a.merged_into IS NULL AND `+productionAsset+`)
		FROM assets a WHERE a.merged_into IS NULL AND `+productionAsset+` AND `+gap,
		`SELECT a.id, a.name,
		   (SELECT string_agg(c.scope || ' ' || c.status, ', ' ORDER BY c.scope) FROM coverage c WHERE c.asset_id = a.id AND c.status IN ('failed', 'partial')),
		   (SELECT min(c.last_success) FROM coverage c WHERE c.asset_id = a.id AND c.status IN ('failed', 'partial')),
		   COALESCE((SELECT c.reason FROM coverage c WHERE c.asset_id = a.id AND c.status IN ('failed', 'partial') AND c.reason <> ''
		     ORDER BY c.last_attempt DESC LIMIT 1), ''), true
		FROM assets a WHERE a.merged_into IS NULL AND a.workspace_id = $2 AND `+productionAsset+` AND `+gap+`
		ORDER BY a.name, a.id LIMIT $3`, viewerWS, limit)
}

// ProductionEvaluationGaps are production assets running components that no
// vulnerability source covers or that could not be evaluated (unsupported or
// not_evaluated inventory rows), so "no findings" there means "not checked".
func (s *Store) ProductionEvaluationGaps(ctx context.Context, viewerWS int64, limit int) (*HealthGroup, error) {
	const gapRows = `FROM inventory i WHERE i.asset_id = a.id AND i.removed_at IS NULL AND i.coverage IN ('unsupported', 'not_evaluated')`
	return s.healthGroup(ctx, true, `SELECT count(*), count(*), count(DISTINCT a.workspace_id), NULL::timestamptz
		FROM assets a WHERE a.merged_into IS NULL AND `+productionAsset+` AND EXISTS (SELECT 1 `+gapRows+`)`,
		`SELECT a.id, a.name, (SELECT count(DISTINCT i.component_id)::text || ' component(s) not evaluated' `+gapRows+`),
		   (SELECT max(i.evaluated_at) `+gapRows+`),
		   COALESCE((SELECT i.coverage_reason `+gapRows+` AND i.coverage_reason <> '' ORDER BY i.evaluated_at DESC NULLS LAST LIMIT 1), ''), true
		FROM assets a WHERE a.merged_into IS NULL AND a.workspace_id = $2 AND `+productionAsset+` AND EXISTS (SELECT 1 `+gapRows+`)
		ORDER BY a.name, a.id LIMIT $3`, viewerWS, limit)
}

// FailingIntegrations are enabled integrations whose latest run failed.
// Production counts those that have not succeeded for two schedules or more
// (repeatedly failing); the item detail says which.
func (s *Store) FailingIntegrations(ctx context.Context, viewerWS int64, limit int) (*HealthGroup, error) {
	const failing = `a.enabled AND a.last_error <> '' AND a.last_attempt IS NOT NULL AND (a.last_success IS NULL OR a.last_success < a.last_attempt)`
	const repeated = `now() - COALESCE(a.last_success, a.created_at) > 2 * a.schedule`
	return s.healthGroup(ctx, false, `SELECT count(*), count(*) FILTER (WHERE `+repeated+`), count(DISTINCT a.workspace_id), max(a.last_success)
		FROM integrations a WHERE `+failing+``,
		`SELECT a.id, a.name, a.kind || CASE WHEN `+repeated+` THEN ', failing for more than two scheduled runs' ELSE ', latest run failed' END,
		   a.last_success, a.last_error, `+repeated+`
		FROM integrations a WHERE `+failing+` AND a.workspace_id = $1
		ORDER BY 6 DESC, a.name LIMIT $2`, viewerWS, limit)
}

// FailingChannels are notification channels with deliveries that failed in
// the last seven days or are being retried. Production counts channels with
// failed (given up) deliveries.
func (s *Store) FailingChannels(ctx context.Context, viewerWS int64, limit int) (*HealthGroup, error) {
	const bad = `(d.status = 'failed' AND d.created_at >= now() - interval '7 days') OR (d.status = 'pending' AND d.attempts >= 2 AND d.last_error <> '')`
	return s.healthGroup(ctx, false, `SELECT count(*), count(*) FILTER (WHERE x.failed > 0), count(DISTINCT x.workspace_id), max(x.last_ok_at)
		FROM (SELECT a.id, a.workspace_id, a.last_ok_at, count(*) FILTER (WHERE d.status = 'failed') AS failed
		      FROM channels a JOIN deliveries d ON d.channel_id = a.id WHERE (`+bad+`) GROUP BY a.id) x`,
		`SELECT a.id, a.name,
		   a.kind || ': ' || count(*) FILTER (WHERE d.status = 'failed') || ' failed, ' || count(*) FILTER (WHERE d.status = 'pending') || ' retrying'
		   || COALESCE('; routes ' || (SELECT string_agg(DISTINCT r.name, ', ') FROM routes r JOIN deliveries d2 ON d2.route_id = r.id
		        WHERE d2.channel_id = a.id AND (`+strings.ReplaceAll(bad, "d.", "d2.")+`)), ''),
		   a.last_ok_at,
		   COALESCE((SELECT d3.last_error FROM deliveries d3 WHERE d3.channel_id = a.id AND d3.last_error <> ''
		     ORDER BY d3.created_at DESC, d3.id DESC LIMIT 1), a.last_error),
		   count(*) FILTER (WHERE d.status = 'failed') > 0
		FROM channels a JOIN deliveries d ON d.channel_id = a.id
		WHERE (`+bad+`) AND a.workspace_id = $1
		GROUP BY a.id ORDER BY 6 DESC, a.name LIMIT $2`, viewerWS, limit)
}

// WorkspaceNames maps workspace ids to names (system scope).
func (s *Store) WorkspaceNames(ctx context.Context) (map[int64]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, name FROM workspaces`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		var n string
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}
