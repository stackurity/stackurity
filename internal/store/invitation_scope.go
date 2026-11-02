package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Invitations say what the person will see, like Add user: an
// organisation-wide role, or grants on chosen projects and assets
// (invitation_grants, migration 0079). The grants are checked when the
// invitation is made and again when it is accepted.

// InvitationGrant is one project or asset an invitation gives access to.
type InvitationGrant struct {
	// Kind: "project" (its assets, including ones added later) or "asset".
	Kind      string    `json:"kind"`
	ProjectID *int64    `json:"project_id"`
	AssetID   *int64    `json:"asset_id"`
	Role      auth.Role `json:"role"`
	// Name is the project's or asset's name; as it was when the person
	// was invited if it has been deleted since.
	Name string `json:"name"`
	// Available: accepting now would give it. Unavailable says why not:
	// "archived" or "deleted" (a project), "merged" or "deleted" (an asset),
	// or "changed" (one of those happened while the link was being used).
	Available   bool   `json:"available"`
	Unavailable string `json:"unavailable,omitempty"`
}

// ErrInvitationStale: every project and asset the invitation named was
// archived, merged or deleted after it was sent, so accepting would give
// nothing. Nothing is written; the invitation stays open for an admin to
// revoke or replace.
var ErrInvitationStale = errors.New("everything this invitation gave access to has been archived, merged or deleted since it was sent; ask the person who invited you for a new invitation")

// InvitationInput is an invitation to make: Role for all projects and
// assets, or Grants (Role empty or RoleNone) on chosen ones.
type InvitationInput struct {
	Email  string
	Name   string
	Role   auth.Role
	Grants []ScopeGrant
}

// Invite stores an invitation and returns it with its link token, shown
// once. One person has one open invitation in a workspace: the ones they
// already have are replaced (revoked), and their ids returned. Grants must
// name active projects and unmerged assets of this workspace.
func (s *Store) Invite(ctx context.Context, in InvitationInput, by int64) (*Invitation, string, []int64, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	name := strings.TrimSpace(in.Name)
	if !validEmail(email) {
		return nil, "", nil, fmt.Errorf("a valid email is required: %w", ErrInvalid)
	}
	if len(name) > 200 {
		return nil, "", nil, fmt.Errorf("name is limited to 200 characters: %w", ErrInvalid)
	}
	role, err := CheckScope(in.Role, in.Grants)
	if err != nil {
		return nil, "", nil, err
	}
	var orgRole *auth.Role
	if role != RoleNone {
		orgRole = &role
	}
	secret, prefix, err := auth.NewToken("inv")
	if err != nil {
		return nil, "", nil, err
	}
	var byID *int64
	if by > 0 {
		byID = &by
	}
	ctx = tenant.WithoutProject(ctx)
	var id int64
	var replaced []int64
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		names, err := grantTargets(ctx, tx, in.Grants)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `UPDATE invitations SET revoked_at = now()
			WHERE email = $1 AND accepted_at IS NULL AND revoked_at IS NULL RETURNING id`, email)
		if err != nil {
			return err
		}
		if replaced, err = pgx.CollectRows(rows, pgx.RowTo[int64]); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO invitations (email, name, project_id, role, prefix, token_hash, created_by, expires_at)
			VALUES ($1, $2, NULL, $3, $4, $5, $6, now() + make_interval(secs => $7)) RETURNING id`,
			email, name, orgRole, prefix, auth.HashToken(secret), byID, InvitationTTL.Seconds()).Scan(&id); err != nil {
			return err
		}
		for i, g := range in.Grants {
			kind := "project"
			if g.AssetID != nil {
				kind = "asset"
			}
			label := names[i]
			if len(label) > 300 {
				label = label[:300]
			}
			_, err := tx.Exec(ctx, `INSERT INTO invitation_grants (invitation_id, kind, project_id, asset_id, role, label)
				VALUES ($1, $2, $3, $4, $5, $6)`, id, kind, g.ProjectID, g.AssetID, g.Role, label)
			if isForeignKey(err) {
				return fmt.Errorf("grant %d: no such %s in this organisation: %w", i+1, kind, ErrInvalid)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, "", nil, err
	}
	inv, err := s.GetInvitation(ctx, id)
	return inv, secret, replaced, err
}

// loadGrants fills in Grants for each invitation in list: its stored
// grants with whether each can still be given, or the single project of an
// invitation made before grants existed.
func loadGrants(ctx context.Context, db q, list []Invitation) error {
	at := map[int64]int{}
	var ids []int64
	for i := range list {
		list[i].Grants = []InvitationGrant{}
		if list[i].Scope == "project" && list[i].ProjectID != nil {
			list[i].Grants = append(list[i].Grants, InvitationGrant{Kind: "project", ProjectID: list[i].ProjectID, Role: list[i].Role,
				Name: list[i].ProjectName, Available: true})
		}
		if list[i].Scope == "specific" {
			at[list[i].ID] = i
			ids = append(ids, list[i].ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	const sql = `SELECT g.invitation_id, g.kind, g.project_id, g.asset_id, g.role, COALESCE(p.name, a.name, g.label),
		  CASE WHEN g.kind = 'project' THEN CASE WHEN p.id IS NULL THEN 'deleted' WHEN p.archived_at IS NOT NULL THEN 'archived' ELSE '' END
		       ELSE CASE WHEN a.id IS NULL THEN 'deleted' WHEN a.merged_into IS NOT NULL THEN 'merged' ELSE '' END END
		FROM invitation_grants g LEFT JOIN projects p ON p.id = g.project_id LEFT JOIN assets a ON a.id = g.asset_id
		WHERE g.invitation_id = ANY($1) ORDER BY g.invitation_id, g.kind DESC, COALESCE(p.name, a.name, g.label), g.id`
	rows, err := db.Query(ctx, sql, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var invID int64
		var g InvitationGrant
		if err := rows.Scan(&invID, &g.Kind, &g.ProjectID, &g.AssetID, &g.Role, &g.Name, &g.Unavailable); err != nil {
			return err
		}
		g.Available = g.Unavailable == ""
		i := at[invID]
		list[i].Grants = append(list[i].Grants, g)
	}
	return rows.Err()
}

// availableGrants returns the grants that can still be given.
func availableGrants(gs []InvitationGrant) []InvitationGrant {
	var out []InvitationGrant
	for _, g := range gs {
		if g.Available {
			out = append(out, g)
		}
	}
	return out
}

// acceptGrants gives uid the invitation's grants, in tx (system scope). An
// existing grant keeps the higher of its role and the invitation's. The
// project or asset is checked once more in the same statement, so one
// archived or merged in between is skipped (and returned) rather than given.
func acceptGrants(ctx context.Context, tx pgx.Tx, inv *Invitation, uid int64, give []InvitationGrant) (ids []int64, skipped []InvitationGrant, err error) {
	keepHigher := `DO UPDATE SET role = CASE WHEN ` + roleRank("EXCLUDED.role") + ` > ` + roleRank("access_grants.role") + `
		THEN EXCLUDED.role ELSE access_grants.role END RETURNING id`
	for _, g := range give {
		var id int64
		var err error
		if g.ProjectID != nil {
			err = tx.QueryRow(ctx, `INSERT INTO access_grants (workspace_id, project_id, user_id, role, created_by)
				SELECT $1, p.id, $3, $4, i.created_by FROM projects p, invitations i
				WHERE p.id = $2 AND p.workspace_id = $1 AND p.archived_at IS NULL AND i.id = $5
				ON CONFLICT (project_id, user_id) WHERE project_id IS NOT NULL AND user_id IS NOT NULL `+keepHigher,
				inv.WorkspaceID, *g.ProjectID, uid, g.Role, inv.ID).Scan(&id)
		} else {
			err = tx.QueryRow(ctx, `INSERT INTO access_grants (workspace_id, asset_id, user_id, role, created_by)
				SELECT $1, a.id, $3, $4, i.created_by FROM assets a, invitations i
				WHERE a.id = $2 AND a.workspace_id = $1 AND a.merged_into IS NULL AND i.id = $5
				ON CONFLICT (asset_id, user_id) WHERE asset_id IS NOT NULL AND user_id IS NOT NULL `+keepHigher,
				inv.WorkspaceID, *g.AssetID, uid, g.Role, inv.ID).Scan(&id)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			g.Available, g.Unavailable = false, "changed"
			skipped = append(skipped, g)
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, nil, ErrInvitationStale
	}
	return ids, skipped, nil
}

// GrantMember gives an existing member of the context's workspace the
// grants, in one transaction: all of them or none. An existing grant on
// the same project or asset takes the new role (as SaveGrant does).
func (s *Store) GrantMember(ctx context.Context, uid int64, grants []ScopeGrant, by int64) ([]int64, error) {
	if _, err := CheckScope(RoleNone, grants); err != nil {
		return nil, err
	}
	var byID *int64
	if by > 0 {
		byID = &by
	}
	ctx = tenant.WithoutProject(ctx)
	var ids []int64
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := grantTargets(ctx, tx, grants); err != nil {
			return err
		}
		for i, g := range grants {
			var id int64
			var err error
			if g.ProjectID != nil {
				err = tx.QueryRow(ctx, `INSERT INTO access_grants (project_id, user_id, role, created_by) VALUES ($1, $2, $3, $4)
					ON CONFLICT (project_id, user_id) WHERE project_id IS NOT NULL AND user_id IS NOT NULL
					DO UPDATE SET role = EXCLUDED.role RETURNING id`, *g.ProjectID, uid, g.Role, byID).Scan(&id)
			} else {
				err = tx.QueryRow(ctx, `INSERT INTO access_grants (asset_id, user_id, role, created_by) VALUES ($1, $2, $3, $4)
					ON CONFLICT (asset_id, user_id) WHERE asset_id IS NOT NULL AND user_id IS NOT NULL
					DO UPDATE SET role = EXCLUDED.role RETURNING id`, *g.AssetID, uid, g.Role, byID).Scan(&id)
			}
			if isForeignKey(err) {
				return fmt.Errorf("grant %d: no such project, asset or member in this organisation: %w", i+1, ErrInvalid)
			}
			if err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return nil
	})
	return ids, err
}
