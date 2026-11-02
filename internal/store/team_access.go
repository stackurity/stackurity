package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Team membership gives access: a member sees what the team's grants
// (access_grants with team_id) give, as long as they are in the team. The
// team an asset belongs to (assets.owner_team_id) only routes that asset's
// alerts and incidents; it gives no access.

// MaxMemberTeams caps the teams one request may add someone to.
const MaxMemberTeams = 50

// checkTeamIDs refuses duplicates and non-ids.
func checkTeamIDs(teams []int64) error {
	if len(teams) > MaxMemberTeams {
		return fmt.Errorf("at most %d teams at a time: %w", MaxMemberTeams, ErrInvalid)
	}
	seen := map[int64]bool{}
	for i, id := range teams {
		if id <= 0 || seen[id] {
			return fmt.Errorf("team %d: a team may be named once: %w", i+1, ErrInvalid)
		}
		seen[id] = true
	}
	return nil
}

// CheckAccess is CheckScope with teams: with no organisation-wide role,
// teams may stand in for grants (the check that one of them can see
// something is made in the transaction, teamTargets).
func CheckAccess(role auth.Role, grants []ScopeGrant, teams []int64) (auth.Role, error) {
	if err := checkTeamIDs(teams); err != nil {
		return role, err
	}
	if len(grants) == 0 && len(teams) > 0 && (role == "" || role == RoleNone) {
		return RoleNone, nil
	}
	return CheckScope(role, grants)
}

// teamTargets checks, inside tx under the workspace's row-level security,
// that every team is this workspace's, and returns their names and whether
// any of them can see something (has a grant on an active project or an
// unmerged asset).
func teamTargets(ctx context.Context, tx pgx.Tx, teams []int64) ([]string, bool, error) {
	names := make([]string, len(teams))
	seesSomething := false
	for i, id := range teams {
		var sees bool
		err := tx.QueryRow(ctx, `SELECT t.name, EXISTS (SELECT 1 FROM access_grants g LEFT JOIN projects p ON p.id = g.project_id
			LEFT JOIN assets a ON a.id = g.asset_id
			WHERE g.team_id = t.id AND (p.archived_at IS NULL AND g.project_id IS NOT NULL OR a.merged_into IS NULL AND g.asset_id IS NOT NULL))
			FROM teams t WHERE t.id = $1`, id).Scan(&names[i], &sees)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, fmt.Errorf("team %d: no such team in this organisation: %w", i+1, ErrInvalid)
		}
		if err != nil {
			return nil, false, err
		}
		seesSomething = seesSomething || sees
	}
	return names, seesSomething, nil
}

// errTeamsSeeNothing: specific access given through teams alone, none of
// which can see anything yet.
var errTeamsSeeNothing = fmt.Errorf("the teams chosen cannot see any project or asset yet; give a team access under Settings, Teams, or choose projects or assets for this person: %w", ErrInvalid)

// joinTeams adds uid to the teams in workspace ws, inside tx.
func joinTeams(ctx context.Context, tx pgx.Tx, ws, uid int64, teams []int64) error {
	for _, id := range teams {
		if _, err := tx.Exec(ctx, `INSERT INTO team_members (workspace_id, team_id, user_id) VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING`, ws, id, uid); err != nil {
			if isForeignKey(err) {
				return fmt.Errorf("no such team in this organisation: %w", ErrInvalid)
			}
			return err
		}
	}
	return nil
}

// TeamChange is what UpdateTeam's Access changed, for the audit log.
type TeamChange struct {
	Granted []int64 // new grant ids
	Changed []int64 // grant ids whose role changed
	Revoked []Grant // grants removed (as they were)
	// OwnsAdded and OwnsRemoved count assets the team now owns, or no
	// longer does.
	OwnsAdded, OwnsRemoved int64
}

// setTeamAccess makes the team's grants exactly grants, inside tx.
func setTeamAccess(ctx context.Context, tx pgx.Tx, teamID int64, grants []ScopeGrant, by *int64, ch *TeamChange) error {
	if _, err := grantTargets(ctx, tx, grants); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT `+grantCols+grantFrom+` WHERE g.team_id = $1 FOR UPDATE OF g`, teamID)
	if err != nil {
		return err
	}
	old, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Grant])
	if err != nil {
		return err
	}
	key := func(p, a *int64) string {
		if p != nil {
			return fmt.Sprintf("p%d", *p)
		}
		return fmt.Sprintf("a%d", *a)
	}
	have := map[string]Grant{}
	for _, g := range old {
		have[key(g.ProjectID, g.AssetID)] = g
	}
	want := map[string]bool{}
	for _, g := range grants {
		k := key(g.ProjectID, g.AssetID)
		want[k] = true
		if o, ok := have[k]; ok {
			if o.Role != g.Role {
				if _, err := tx.Exec(ctx, `UPDATE access_grants SET role = $2 WHERE id = $1`, o.ID, g.Role); err != nil {
					return err
				}
				ch.Changed = append(ch.Changed, o.ID)
			}
			continue
		}
		var id int64
		if err := tx.QueryRow(ctx, `INSERT INTO access_grants (project_id, asset_id, team_id, role, created_by)
			VALUES ($1, $2, $3, $4, $5) RETURNING id`, g.ProjectID, g.AssetID, teamID, g.Role, by).Scan(&id); err != nil {
			return err
		}
		ch.Granted = append(ch.Granted, id)
	}
	for k, o := range have {
		if want[k] {
			continue
		}
		if _, err := tx.Exec(ctx, `DELETE FROM access_grants WHERE id = $1`, o.ID); err != nil {
			return err
		}
		ch.Revoked = append(ch.Revoked, o)
	}
	return nil
}

// setTeamOwns makes the team the owner of exactly assets (they must be
// this workspace's and not merged); assets it owned and not listed are
// left without an owner team.
func setTeamOwns(ctx context.Context, tx pgx.Tx, teamID int64, assets []int64, ch *TeamChange) error {
	seen := map[int64]bool{}
	for _, id := range assets {
		if id <= 0 || seen[id] {
			return fmt.Errorf("an asset may be named once: %w", ErrInvalid)
		}
		seen[id] = true
	}
	var n int64
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM assets WHERE id = ANY($1) AND merged_into IS NULL`, assets).Scan(&n); err != nil {
		return err
	}
	if n != int64(len(assets)) {
		return fmt.Errorf("no such asset in this organisation: %w", ErrInvalid)
	}
	tag, err := tx.Exec(ctx, `UPDATE assets SET owner_team_id = NULL WHERE owner_team_id = $1 AND NOT (id = ANY($2))`, teamID, assets)
	if err != nil {
		return err
	}
	ch.OwnsRemoved = tag.RowsAffected()
	tag, err = tx.Exec(ctx, `UPDATE assets SET owner_team_id = $1 WHERE id = ANY($2) AND owner_team_id IS DISTINCT FROM $1`, teamID, assets)
	if err != nil {
		return err
	}
	ch.OwnsAdded = tag.RowsAffected()
	return nil
}

// TeamUpdate changes a team; nil fields are left as they are.
type TeamUpdate struct {
	Name, Email *string
	Members     *[]int64
	// Access replaces the team's grants ("Can see"); Owns replaces the
	// assets it owns.
	Access *[]ScopeGrant
	Owns   *[]int64
}

// UpdateTeamAccess changes the team, its members, what it can see and
// what it owns, all in one transaction.
func (s *Store) UpdateTeamAccess(ctx context.Context, id int64, u TeamUpdate, by int64) (*TeamChange, error) {
	if u.Access != nil {
		if len(*u.Access) > MaxMemberGrants {
			return nil, fmt.Errorf("at most %d grants at a time: %w", MaxMemberGrants, ErrInvalid)
		}
		// The same rules as a person's grants (one target each, named
		// once, a valid role); an empty list takes all access away.
		if len(*u.Access) > 0 {
			if _, err := CheckScope(RoleNone, *u.Access); err != nil {
				return nil, err
			}
		}
	}
	var byID *int64
	if by > 0 {
		byID = &by
	}
	ctx = tenant.WithoutProject(ctx)
	ch := &TeamChange{}
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if err := updateTeam(ctx, tx, id, u.Name, u.Email, u.Members); err != nil {
			return err
		}
		if u.Access != nil {
			if err := setTeamAccess(ctx, tx, id, *u.Access, byID, ch); err != nil {
				return err
			}
		}
		if u.Owns != nil {
			if err := setTeamOwns(ctx, tx, id, *u.Owns, ch); err != nil {
				return err
			}
		}
		return nil
	})
	return ch, err
}
