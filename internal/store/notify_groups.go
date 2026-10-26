package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// This file holds what grouped notifications (urgent alerts, summaries,
// overdue alerts, "connected" messages) read: counts of findings by asset,
// priority and fix, rather than one row per incident.

// ClaimSummary records that a route's summary covering up to `to` has been
// planned. It succeeds only if the route still has the last summary time
// the caller read, so two replicas never plan the same summary twice.
func (s *Store) ClaimSummary(ctx context.Context, routeID int64, prev, to time.Time) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE routes SET last_summary_at = $3 WHERE id = $1 AND last_summary_at = $2`, routeID, prev, to)
	return err == nil && tag.RowsAffected() == 1, err
}

// HeldForRoute returns the ids of a route's deliveries held by its hourly
// limit, which its next summary takes in.
func (s *Store) HeldForRoute(ctx context.Context, routeID int64) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id FROM deliveries WHERE route_id = $1 AND status = 'held' ORDER BY id`, routeID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// NewAsset is an asset notifications have not described yet.
type NewAsset struct {
	ID          int64
	Name        string
	Environment string
	OwnerTeamID *int64
	Packages    int
	// Ready: its first complete collection has been evaluated (or it has
	// waited six hours, so a collector that never sends a complete batch
	// does not silence the asset for ever).
	Ready bool
}

// UnannouncedAssets returns the assets whose first scan has not been
// announced.
func (s *Store) UnannouncedAssets(ctx context.Context) ([]NewAsset, error) {
	rows, err := s.Pool.Query(ctx, `SELECT a.id, a.name, a.environment, a.owner_team_id,
		  (SELECT count(*) FROM inventory i WHERE i.asset_id = a.id AND i.removed_at IS NULL)::int,
		  (a.evaluated_at IS NOT NULL
		    AND EXISTS (SELECT 1 FROM collections c WHERE c.asset_id = a.id AND c.complete AND c.received_at <= a.evaluated_at)
		    AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.dedupe_key = 'evaluate:asset:' || a.id AND j.done_at IS NULL AND j.failed_at IS NULL))
		  OR a.created_at < now() - interval '6 hours'
		FROM assets a WHERE a.announced_at IS NULL AND a.merged_into IS NULL ORDER BY a.name LIMIT 5000`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[NewAsset])
}

// MarkAssetsAnnounced records that notifications have described the assets.
func (s *Store) MarkAssetsAnnounced(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.Pool.Exec(ctx, `UPDATE assets SET announced_at = now() WHERE id = ANY($1) AND announced_at IS NULL`, ids)
	return err
}

// IssueCount is a number of findings that share an asset, kind, priority,
// SOS and known-exploited flags and fix (action plan group).
type IssueCount struct {
	IncidentID  int64 // only for IncidentIssues
	AssetID     int64
	AssetName   string
	Environment string
	OwnerTeamID *int64
	Kind        string
	Priority    string
	SOS         bool
	KEV         bool
	FixGroup    string
	FixTitle    string // for fixed issues: the fix they were closed by
	Count       int
}

// IssueSet selects the findings CountIssues counts.
type IssueSet int

const (
	// IssuesNew: active findings first seen in [from, to) on assets that
	// were already announced (an asset's first scan is not "new issues").
	IssuesNew IssueSet = iota
	// IssuesFixed: findings resolved in [from, to).
	IssuesFixed
	// IssuesOverdue: active findings past their fix deadline now.
	IssuesOverdue
	// IssuesNewlyOverdue: active findings whose fix deadline fell in [from, to).
	IssuesNewlyOverdue
	// IssuesAckOverdue: new findings past their acknowledgement deadline.
	IssuesAckOverdue
)

const activeFinding = `f.status = 'open' AND f.state IN ('new', 'acknowledged', 'in_progress')`

// CountIssues counts findings in a set, grouped for summaries.
func (s *Store) CountIssues(ctx context.Context, set IssueSet, from, to time.Time) ([]IssueCount, error) {
	cond, fix, title := "", "f.fix_group", "''"
	switch set {
	case IssuesNew:
		cond = activeFinding + ` AND f.first_seen >= $1 AND f.first_seen < $2 AND a.announced_at IS NOT NULL AND f.first_seen > a.announced_at`
	case IssuesFixed:
		cond = `f.status = 'resolved' AND f.resolved_at >= $1 AND f.resolved_at < $2`
		fix, title = "f.resolved_fix_group", "f.resolved_fix_title"
	case IssuesOverdue:
		cond = activeFinding + ` AND f.fix_due < $2 AND $1::timestamptz IS NOT NULL`
	case IssuesNewlyOverdue:
		cond = activeFinding + ` AND f.fix_due >= $1 AND f.fix_due < $2`
	case IssuesAckOverdue:
		cond = `f.status = 'open' AND f.state = 'new' AND f.ack_due < $2 AND $1::timestamptz IS NOT NULL`
	default:
		return nil, fmt.Errorf("unknown issue set %d", set)
	}
	rows, err := s.Pool.Query(ctx, `SELECT 0::bigint, a.id, a.name, a.environment, a.owner_team_id, f.kind, f.priority, f.sos,
		  COALESCE((f.evidence->>'known_exploited')::boolean, false), `+fix+`, `+title+`, count(*)::int
		FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		WHERE `+cond+`
		GROUP BY 2, 3, 4, 5, 6, 7, 8, 9, 10, 11`, from, to)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[IssueCount])
}

// IncidentIssues counts the active findings of incidents, per incident,
// for urgent alerts.
func (s *Store) IncidentIssues(ctx context.Context, incidentIDs []int64) ([]IssueCount, error) {
	rows, err := s.Pool.Query(ctx, `SELECT f.incident_id, a.id, a.name, a.environment, a.owner_team_id, f.kind, f.priority, f.sos,
		  COALESCE((f.evidence->>'known_exploited')::boolean, false), f.fix_group, '', count(*)::int
		FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		WHERE f.incident_id = ANY($1) AND `+activeFinding+`
		GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10`, incidentIDs)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[IssueCount])
}

// FixInfo is what notifications say about an action plan group.
type FixInfo struct {
	ID           string
	AssetID      int64
	AssetName    string
	Environment  string
	OwnerTeamID  *int64
	Kind         string
	Title        string
	FindingCount int
	SOS          bool
	TopPriority  string
	SortOrder    int
}

const fixInfoCols = `g.id, g.asset_id, a.name, a.environment, a.owner_team_id, g.kind, COALESCE(g.data->>'title', ''),
	COALESCE((g.data->>'finding_count')::int, 0), COALESCE((g.data->>'sos')::boolean, false),
	COALESCE(g.data->>'top_priority', 'P4'), g.sort_order`

// FixInfos returns the action plan groups with the given ids.
func (s *Store) FixInfos(ctx context.Context, ids []string) (map[string]FixInfo, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+fixInfoCols+` FROM fix_groups g JOIN assets a ON a.id = g.asset_id WHERE g.id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[FixInfo])
	if err != nil {
		return nil, err
	}
	out := make(map[string]FixInfo, len(list))
	for _, f := range list {
		out[f.ID] = f
	}
	return out, nil
}

// OpenFixes returns the action plan's groups that are something to do (not
// "no fix yet"), most urgent first; assetIDs limits them to some assets.
func (s *Store) OpenFixes(ctx context.Context, assetIDs []int64) ([]FixInfo, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+fixInfoCols+` FROM fix_groups g JOIN assets a ON a.id = g.asset_id
		WHERE g.kind <> 'no_fix' AND ($1::bigint[] IS NULL OR g.asset_id = ANY($1)) ORDER BY g.sort_order LIMIT 20000`, assetIDs)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[FixInfo])
}

// OpenSystemIncidents returns open problems with collection, feeds,
// coverage and the platform, for summaries.
func (s *Store) OpenSystemIncidents(ctx context.Context) ([]Incident, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+incidentCols+` FROM incidents i LEFT JOIN teams t ON t.id = i.owner_team_id
		WHERE i.status = 'open' AND i.kind IN ('feed', 'collection', 'coverage', 'platform') ORDER BY i.priority, i.created_at LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Incident])
}

// SetIncidentEscalations records escalation levels in bulk, on the
// incidents and their open findings.
func (s *Store) SetIncidentEscalations(ctx context.Context, levels map[int64]int) error {
	if len(levels) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(levels))
	lv := make([]int32, 0, len(levels))
	for id, l := range levels {
		ids, lv = append(ids, id), append(lv, int32(l))
	}
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE incidents i SET escalation_level = x.level
			FROM unnest($1::bigint[], $2::int[]) AS x(id, level) WHERE i.id = x.id`, ids, lv); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE findings f SET escalation_level = GREATEST(f.escalation_level, x.level), escalated_at = now()
			FROM unnest($1::bigint[], $2::int[]) AS x(id, level) WHERE f.incident_id = x.id AND f.status = 'open'`, ids, lv)
		return err
	})
}

// IncidentsByID returns incidents by id, in no particular order.
func (s *Store) IncidentsByID(ctx context.Context, ids []int64) ([]Incident, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+incidentCols+` FROM incidents i LEFT JOIN teams t ON t.id = i.owner_team_id WHERE i.id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Incident])
}

// AssetsAnnounced returns the assets first described in [from, to), for
// summaries; Ready is always true.
func (s *Store) AssetsAnnounced(ctx context.Context, from, to time.Time) ([]NewAsset, error) {
	rows, err := s.Pool.Query(ctx, `SELECT a.id, a.name, a.environment, a.owner_team_id,
		  (SELECT count(*) FROM inventory i WHERE i.asset_id = a.id AND i.removed_at IS NULL)::int, true
		FROM assets a WHERE a.announced_at >= $1 AND a.announced_at < $2 AND a.merged_into IS NULL ORDER BY a.name LIMIT 5000`, from, to)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[NewAsset])
}

// MarkIncidentsNotified is MarkIncidentNotified for many incidents, each
// at its current priority.
func (s *Store) MarkIncidentsNotified(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.Pool.Exec(ctx, `UPDATE incidents SET notified_priority = priority, notified_at = now() WHERE id = ANY($1)`, ids)
	return err
}

// MarkResolvedNotifiedAll is MarkResolvedNotified for many incidents.
func (s *Store) MarkResolvedNotifiedAll(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.Pool.Exec(ctx, `UPDATE incidents SET resolved_notified = true WHERE id = ANY($1)`, ids)
	return err
}
