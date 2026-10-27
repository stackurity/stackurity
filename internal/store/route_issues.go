package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Jira routes limited to a project (migration 0037) keep their own issue
// per incident in route_issues, describing only that project's part of the
// incident. Rows are keyed by route, project, channel and incident, so a
// route moved to another project or channel starts new issues instead of
// telling an old one about other assets. Like incident_issues, the table is
// hidden from connections narrowed to projects: the dispatcher keeps it with
// its workspace-wide connection and reads the issue's content with a
// connection narrowed to the project.

// RouteIssueKey names the issue a project-scoped route keeps for an
// incident.
type RouteIssueKey struct {
	RouteID    int64
	ProjectID  int64
	ChannelID  int64
	IncidentID int64
}

// RouteIssue is a project-scoped route's issue for an incident, with what
// the issue was last told and when (UpdatedAt, part of update dedupe keys).
type RouteIssue struct {
	IssueLink
	UpdatedAt time.Time
}

const routeIssueCols = `id, incident_id, channel_id, issue_key, issue_url, synced_priority, synced_findings, synced_assets, resolved_synced, updated_at`

func scanRouteIssue(row pgx.CollectableRow) (RouteIssue, error) {
	var r RouteIssue
	err := row.Scan(&r.ID, &r.IncidentID, &r.ChannelID, &r.IssueKey, &r.IssueURL, &r.SyncedPriority, &r.SyncedFindings,
		&r.SyncedAssets, &r.ResolvedSynced, &r.UpdatedAt)
	return r, err
}

// errNarrowedIssues: route issues are kept workspace-wide; a narrowed
// connection would see none and could write none.
var errNarrowedIssues = errors.New("route issues are not available to a connection narrowed to projects")

// RouteIssueFor returns the route's issue for an incident, or ErrNotFound
// when it has none (or it is still being created).
func (s *Store) RouteIssueFor(ctx context.Context, k RouteIssueKey) (*RouteIssue, error) {
	if tenant.Narrowed(ctx) {
		return nil, errNarrowedIssues
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+routeIssueCols+` FROM route_issues
		WHERE route_id = $1 AND project_id = $2 AND channel_id = $3 AND incident_id = $4 AND issue_key <> ''`,
		k.RouteID, k.ProjectID, k.ChannelID, k.IncidentID)
	if err != nil {
		return nil, err
	}
	l, err := pgx.CollectExactlyOneRow(rows, scanRouteIssue)
	if err != nil {
		return nil, notFound(err)
	}
	return &l, nil
}

// ClaimRouteIssue reserves the right to create the route's issue for an
// incident for lease, as ClaimIssueCreation does for whole-incident issues.
func (s *Store) ClaimRouteIssue(ctx context.Context, k RouteIssueKey, lease time.Duration) (existing *RouteIssue, err error) {
	if tenant.Narrowed(ctx) {
		return nil, errNarrowedIssues
	}
	// Selecting the referenced rows applies row-level security to them.
	tag, err := s.Pool.Exec(ctx, `INSERT INTO route_issues (route_id, project_id, channel_id, incident_id, creating_until)
		SELECT r.id, p.id, c.id, i.id, now() + $5::interval FROM routes r, projects p, channels c, incidents i
		WHERE r.id = $1 AND p.id = $2 AND c.id = $3 AND i.id = $4
		ON CONFLICT (route_id, project_id, channel_id, incident_id) DO UPDATE SET creating_until = EXCLUDED.creating_until, updated_at = now()
		WHERE route_issues.issue_key = '' AND (route_issues.creating_until IS NULL OR route_issues.creating_until < now())`,
		k.RouteID, k.ProjectID, k.ChannelID, k.IncidentID, lease)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 1 {
		return nil, nil
	}
	l, err := s.RouteIssueFor(ctx, k)
	if errors.Is(err, ErrNotFound) {
		var claimed bool
		if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM route_issues
			WHERE route_id = $1 AND project_id = $2 AND channel_id = $3 AND incident_id = $4)`,
			k.RouteID, k.ProjectID, k.ChannelID, k.IncidentID).Scan(&claimed); err != nil {
			return nil, err
		}
		if !claimed {
			return nil, ErrNotFound
		}
		return nil, ErrIssueBeingCreated
	}
	return l, err
}

// ReleaseRouteIssue gives up a creation claim after a failed attempt.
func (s *Store) ReleaseRouteIssue(ctx context.Context, k RouteIssueKey) error {
	_, err := s.Pool.Exec(ctx, `UPDATE route_issues SET creating_until = NULL
		WHERE route_id = $1 AND project_id = $2 AND channel_id = $3 AND incident_id = $4 AND issue_key = ''`,
		k.RouteID, k.ProjectID, k.ChannelID, k.IncidentID)
	return err
}

// RecordRouteIssue stores the issue created (or found) for the route and
// incident, with the state of the project's part it describes.
func (s *Store) RecordRouteIssue(ctx context.Context, k RouteIssueKey, key, url, priority string, findings, assets int) error {
	if tenant.Narrowed(ctx) {
		return errNarrowedIssues
	}
	tag, err := s.Pool.Exec(ctx, `INSERT INTO route_issues (route_id, project_id, channel_id, incident_id, issue_key, issue_url,
		  synced_priority, synced_findings, synced_assets)
		SELECT r.id, p.id, c.id, i.id, $5, $6, $7, $8, $9 FROM routes r, projects p, channels c, incidents i
		WHERE r.id = $1 AND p.id = $2 AND c.id = $3 AND i.id = $4
		ON CONFLICT (route_id, project_id, channel_id, incident_id) DO UPDATE SET issue_key = EXCLUDED.issue_key,
		  issue_url = EXCLUDED.issue_url, synced_priority = EXCLUDED.synced_priority, synced_findings = EXCLUDED.synced_findings,
		  synced_assets = EXCLUDED.synced_assets, resolved_synced = false, creating_until = NULL, updated_at = now()`,
		k.RouteID, k.ProjectID, k.ChannelID, k.IncidentID, key, url, priority, findings, assets)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// RouteIssueSynced records what the issue has now been told. resolved is
// the state it now shows: an issue whose project part opened again after
// it was resolved is told so, and can be resolved again later.
func (s *Store) RouteIssueSynced(ctx context.Context, id int64, priority string, findings, assets int, resolved bool) error {
	_, err := s.Pool.Exec(ctx, `UPDATE route_issues SET synced_priority = $2, synced_findings = $3, synced_assets = $4,
		resolved_synced = $5, updated_at = now() WHERE id = $1`, id, priority, findings, assets, resolved)
	return err
}

// RouteIssues returns the issues a route keeps in one project and channel
// that may need an update: those not told of a resolution, and those of
// incidents still open (a resolved part can open again). At most 1000, the
// least recently updated first.
func (s *Store) RouteIssues(ctx context.Context, routeID, projectID, channelID int64) ([]RouteIssue, error) {
	if tenant.Narrowed(ctx) {
		return nil, errNarrowedIssues
	}
	rows, err := s.Pool.Query(ctx, `SELECT l.id, l.incident_id, l.channel_id, l.issue_key, l.issue_url, l.synced_priority, l.synced_findings,
		  l.synced_assets, l.resolved_synced, l.updated_at FROM route_issues l JOIN incidents i ON i.id = l.incident_id
		WHERE l.route_id = $1 AND l.project_id = $2 AND l.channel_id = $3 AND l.issue_key <> ''
		  AND (NOT l.resolved_synced OR i.status = 'open')
		ORDER BY l.updated_at, l.id LIMIT 1000`, routeID, projectID, channelID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanRouteIssue)
}

// RouteIssued returns which of the incidents already have an issue (or a
// claim to create one) for the route in the project and channel.
func (s *Store) RouteIssued(ctx context.Context, routeID, projectID, channelID int64, incidentIDs []int64) (map[int64]bool, error) {
	out := map[int64]bool{}
	if len(incidentIDs) == 0 {
		return out, nil
	}
	if tenant.Narrowed(ctx) {
		return nil, errNarrowedIssues
	}
	rows, err := s.Pool.Query(ctx, `SELECT incident_id FROM route_issues
		WHERE route_id = $1 AND project_id = $2 AND channel_id = $3 AND incident_id = ANY($4)`, routeID, projectID, channelID, incidentIDs)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	for _, id := range ids {
		out[id] = true
	}
	return out, err
}

// ProjectIssueCandidates returns open finding incidents that, seen from
// ctx (narrowed to a project, so row-level security limits it to that
// project's findings), have an active finding outside a first-scan backlog
// at minPriority or above (SOS only when sosOnly), and that were announced,
// or gained or regained such a finding, after since. At most 2000, most
// urgent first.
func (s *Store) ProjectIssueCandidates(ctx context.Context, since time.Time, minPriority string, sosOnly bool) ([]int64, error) {
	if !tenant.Narrowed(ctx) {
		return nil, errors.New("project issue candidates need a connection narrowed to the project")
	}
	rows, err := s.Pool.Query(ctx, `SELECT f.incident_id FROM findings f
		JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		JOIN incidents i ON i.id = f.incident_id
		WHERE `+activeFinding+` AND i.status = 'open' AND f.kind IN ('vulnerability', 'end_of_life')
		  AND NOT `+BacklogFinding+`
		  AND f.priority <= $2 AND (NOT $3 OR f.sos)
		  AND (i.notified_at > $1 OR f.first_seen > $1 OR f.regressed_at > $1)
		GROUP BY f.incident_id ORDER BY min(f.priority), f.incident_id LIMIT 2000`, since, minPriority, sosOnly)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// IncidentsSeen returns incidents by id as ctx sees them: for a narrowed
// connection, only those it can see, with their counts, names, priority
// and title recomputed from its findings (as GetIncident does).
func (s *Store) IncidentsSeen(ctx context.Context, ids []int64) (map[int64]Incident, error) {
	out := map[int64]Incident{}
	if len(ids) == 0 {
		return out, nil
	}
	list, err := s.IncidentsByID(ctx, ids)
	if err != nil {
		return nil, err
	}
	if err := s.narrowIncidents(ctx, list); err != nil {
		return nil, err
	}
	for _, in := range list {
		out[in.ID] = in
	}
	return out, nil
}
