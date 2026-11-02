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

// Adding someone to a workspace always says what they can see: an
// organisation-wide role (every project and asset), or roles on chosen
// projects and assets. There is no default; NewMember with neither is
// refused, so a forgotten choice never turns into access to everything.

// MaxMemberGrants caps the grants one request may create.
const MaxMemberGrants = 500

// ScopeGrant is one grant created with a new member: a role on a project
// (which also covers assets added to it later) or on one asset.
type ScopeGrant struct {
	ProjectID *int64    `json:"project_id,omitempty"`
	AssetID   *int64    `json:"asset_id,omitempty"`
	Role      auth.Role `json:"role"`
}

// NewMember is a person to add to the context's workspace.
type NewMember struct {
	Email    string
	Name     string
	Phone    string
	Password string
	// Role is the organisation-wide role, or RoleNone with Grants.
	Role   auth.Role
	Grants []ScopeGrant
	// Teams to add them to, in the same transaction. Membership gives
	// the team's access, so with RoleNone teams may stand in for Grants
	// when at least one of them can see something.
	Teams []int64
}

// NormalizePhone trims a phone number and checks it loosely: digits with an
// optional leading +, and spaces, dots, dashes or brackets between them;
// 6 to 15 digits (E.164 allows at most 15). Empty is allowed.
func NormalizePhone(p string) (string, error) {
	p = strings.Join(strings.Fields(p), " ")
	if p == "" {
		return "", nil
	}
	if len(p) > 32 {
		return "", fmt.Errorf("phone is limited to 32 characters: %w", ErrInvalid)
	}
	digits := 0
	for i, c := range p {
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c == '+' && i == 0:
		case c == ' ' || c == '-' || c == '.' || c == '(' || c == ')':
		default:
			return "", fmt.Errorf("phone may contain digits, a leading +, spaces, dots, dashes and brackets only: %w", ErrInvalid)
		}
	}
	if digits < 6 || digits > 15 {
		return "", fmt.Errorf("phone must have 6 to 15 digits: %w", ErrInvalid)
	}
	return p, nil
}

// checkScope validates what a new member may see, before anything is written.
func (m *NewMember) checkScope() error {
	role, err := CheckAccess(m.Role, m.Grants, m.Teams)
	m.Role = role
	return err
}

// CheckScope validates "what can they see?" for a new member or an
// invitation: an organisation-wide role, or (role empty or RoleNone)
// grants on chosen projects and assets. Neither is refused, so a
// forgotten choice never turns into access to everything. It returns the
// role to store: the organisation-wide one, or RoleNone.
func CheckScope(role auth.Role, grants []ScopeGrant) (auth.Role, error) {
	if role != RoleNone && !role.ValidUser() {
		if role == "" && len(grants) == 0 {
			return role, fmt.Errorf("choose what they can see: an organisation-wide role (all projects and assets), or grants on specific projects or assets: %w", ErrInvalid)
		}
		if role != "" {
			return role, fmt.Errorf("role must be viewer, engineer, security, admin, or none with grants: %w", ErrInvalid)
		}
		role = RoleNone
	}
	if role != RoleNone {
		if len(grants) > 0 {
			return role, fmt.Errorf("an organisation-wide role already covers every project and asset; send grants with role none: %w", ErrInvalid)
		}
		return role, nil
	}
	if len(grants) == 0 {
		return role, fmt.Errorf("with no organisation-wide role, choose at least one project or asset they can see: %w", ErrInvalid)
	}
	if len(grants) > MaxMemberGrants {
		return role, fmt.Errorf("at most %d grants at a time: %w", MaxMemberGrants, ErrInvalid)
	}
	seenProject, seenAsset := map[int64]bool{}, map[int64]bool{}
	for i, g := range grants {
		if !g.Role.ValidUser() {
			return role, fmt.Errorf("grant %d: role must be viewer, engineer, security or admin: %w", i+1, ErrInvalid)
		}
		switch {
		case (g.ProjectID == nil) == (g.AssetID == nil):
			return role, fmt.Errorf("grant %d: name either a project or an asset: %w", i+1, ErrInvalid)
		case g.ProjectID != nil:
			if *g.ProjectID <= 0 || seenProject[*g.ProjectID] {
				return role, fmt.Errorf("grant %d: a project may be named once: %w", i+1, ErrInvalid)
			}
			seenProject[*g.ProjectID] = true
		default:
			if *g.AssetID <= 0 || seenAsset[*g.AssetID] {
				return role, fmt.Errorf("grant %d: an asset may be named once: %w", i+1, ErrInvalid)
			}
			seenAsset[*g.AssetID] = true
		}
	}
	return role, nil
}

// grantTargets checks, inside tx and under the workspace's row-level
// security, that every grant names an active project or an unmerged asset
// of this workspace, and returns their names in order. A project or asset
// of another workspace is "no such" here, as it is invisible.
func grantTargets(ctx context.Context, tx pgx.Tx, grants []ScopeGrant) ([]string, error) {
	names := make([]string, len(grants))
	for i, g := range grants {
		var err error
		if g.ProjectID != nil {
			err = tx.QueryRow(ctx, `SELECT name FROM projects WHERE id = $1 AND archived_at IS NULL`, *g.ProjectID).Scan(&names[i])
		} else {
			err = tx.QueryRow(ctx, `SELECT name FROM assets WHERE id = $1 AND merged_into IS NULL`, *g.AssetID).Scan(&names[i])
		}
		if errors.Is(err, pgx.ErrNoRows) {
			what := "project"
			if g.AssetID != nil {
				what = "asset"
			}
			return nil, fmt.Errorf("grant %d: no such %s in this organisation: %w", i+1, what, ErrInvalid)
		}
		if err != nil {
			return nil, err
		}
	}
	return names, nil
}

// CreateMember adds m to the context's workspace with what they may see,
// in one transaction: the account (when new), the membership and every
// grant are written together, or nothing is. Projects and assets must be
// the workspace's own (archived projects and merged assets are refused).
// It returns the user and the ids of the grants created.
func (s *Store) CreateMember(ctx context.Context, m NewMember, by int64) (*User, []int64, error) {
	if err := m.checkScope(); err != nil {
		return nil, nil, err
	}
	phone, err := NormalizePhone(m.Phone)
	if err != nil {
		return nil, nil, err
	}
	name := strings.TrimSpace(m.Name)
	if len(name) > 200 {
		return nil, nil, fmt.Errorf("name is limited to 200 characters: %w", ErrInvalid)
	}
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil, nil, errNoWorkspace
	}
	// The project chosen in the switcher must not hide the workspace's
	// other projects from the checks below.
	ctx = tenant.WithoutProject(ctx)
	var orgRole *auth.Role
	if m.Role != RoleNone {
		orgRole = &m.Role
	}
	var byID *int64
	if by > 0 {
		byID = &by
	}
	var uid int64
	var grantIDs []int64
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var err error
		if uid, err = ensureUser(ctx, tx, m.Email, name, m.Password); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO workspace_members (workspace_id, user_id, role, phone) VALUES ($1, $2, $3, $4)
			ON CONFLICT (workspace_id, user_id) DO NOTHING`, ws, uid, orgRole, phone)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("a user with that email is already a member: %w", ErrConflict)
		}
		if _, err := grantTargets(ctx, tx, m.Grants); err != nil {
			return err
		}
		_, teamsSee, err := teamTargets(ctx, tx, m.Teams)
		if err != nil {
			return err
		}
		if m.Role == RoleNone && len(m.Grants) == 0 && !teamsSee {
			return errTeamsSeeNothing
		}
		if err := joinTeams(ctx, tx, ws, uid, m.Teams); err != nil {
			return err
		}
		for i, g := range m.Grants {
			var id int64
			err = tx.QueryRow(ctx, `INSERT INTO access_grants (project_id, asset_id, user_id, role, created_by)
				VALUES ($1, $2, $3, $4, $5) RETURNING id`, g.ProjectID, g.AssetID, uid, g.Role, byID).Scan(&id)
			if isForeignKey(err) {
				return fmt.Errorf("grant %d: no such project or asset in this organisation: %w", i+1, ErrInvalid)
			}
			if err != nil {
				return err
			}
			grantIDs = append(grantIDs, id)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	u, err := s.GetUser(ctx, uid)
	return u, grantIDs, err
}
