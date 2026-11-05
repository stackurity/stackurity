package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Notifications of projects and assets (migration 0096): the organisation
// setting that lets projects connect their own Slack or Teams workspace,
// and what the API needs to decide who manages a project's or an asset's
// rules.

const projectChatAppsKey = "notify_project_chat_apps"

// ProjectChatApps reports whether project admins may connect their own
// Slack or Teams workspace to their project. Off unless an organisation
// admin turned it on.
func (s *Store) ProjectChatApps(ctx context.Context) (bool, error) {
	var on bool
	err := s.Pool.QueryRow(tenant.WithoutProject(ctx), `SELECT value = 'true'::jsonb FROM settings WHERE key = $1`, projectChatAppsKey).Scan(&on)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return on, err
}

// SetProjectChatApps stores the setting.
func (s *Store) SetProjectChatApps(ctx context.Context, on bool) error {
	raw, _ := json.Marshal(on)
	_, err := s.Pool.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
		ON CONFLICT (workspace_id, key) DO UPDATE SET value = EXCLUDED.value`, projectChatAppsKey, raw)
	return err
}

// ProjectGrantRole returns the highest role userID holds on the project
// itself through grants (their own or their teams'), or "" (also for an
// archived project). Organisation-wide roles are checked by the caller.
func (s *Store) ProjectGrantRole(ctx context.Context, userID, projectID int64) (auth.Role, error) {
	var rank int
	err := s.Pool.QueryRow(tenant.WithoutProject(ctx), `SELECT COALESCE(max(`+roleRank("g.role")+`), 0)
		FROM access_grants g JOIN projects p ON p.id = g.project_id
		WHERE g.project_id = $2 AND p.archived_at IS NULL
		  AND (g.user_id = $1 OR g.team_id IN (SELECT tm.team_id FROM team_members tm WHERE tm.user_id = $1))`, userID, projectID).Scan(&rank)
	if err != nil {
		return "", err
	}
	return [...]auth.Role{"", auth.RoleViewer, auth.RoleEngineer, auth.RoleSecurity, auth.RoleAdmin}[rank], nil
}

// AssetProjects returns the active projects an asset is in.
func (s *Store) AssetProjects(ctx context.Context, assetID int64) ([]int64, error) {
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `SELECT pa.project_id FROM project_assets pa JOIN projects p ON p.id = pa.project_id
		WHERE pa.asset_id = $1 AND p.archived_at IS NULL ORDER BY pa.project_id`, assetID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// ListOwnedChannels lists the channels of the owners given (the
// organisation's for an empty Owner).
func (s *Store) ListOwnedChannels(ctx context.Context, owners ...Owner) ([]Channel, error) {
	var out []Channel
	for _, o := range owners {
		rows, err := s.Pool.Query(ctx, `SELECT `+channelCols+` FROM channels
			WHERE owner_project_id IS NOT DISTINCT FROM $1 AND owner_asset_id IS NOT DISTINCT FROM $2 ORDER BY name`, o.ProjectID, o.AssetID)
		if err != nil {
			return nil, err
		}
		cs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Channel])
		if err != nil {
			return nil, err
		}
		out = append(out, cs...)
	}
	return out, nil
}

// OrgAdmins returns the names (or emails) of the organisation's admins, to
// tell project admins whom to ask.
func (s *Store) OrgAdmins(ctx context.Context) ([]string, error) {
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `SELECT COALESCE(NULLIF(u.name, ''), u.email) FROM workspace_members m
		JOIN users u ON u.id = m.user_id WHERE m.workspace_id = stackurity_ws() AND m.role = 'admin' ORDER BY 1 LIMIT 5`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
