package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Onboarding (0.9): the first-run flow an organisation's admins see while it
// has no assets, and the checklist on Home until it is done.

// Onboarding states (workspaces.onboarding_state).
const (
	OnboardingNew     = "new"     // the flow shows while there are no assets
	OnboardingSkipped = "skipped" // Home shows the checklist instead
	OnboardingDone    = "done"    // nothing shows
)

// Onboarding is where an organisation is in its first ten minutes.
type Onboarding struct {
	State string `json:"state"`
	// ShowFlow: open the first-run flow (state new and no assets yet).
	ShowFlow  bool            `json:"show_flow"`
	HasAssets bool            `json:"has_assets"`
	ProjectID int64           `json:"project_id"`
	Project   *Project        `json:"project"`
	Steps     OnboardingSteps `json:"steps"`
}

// OnboardingSteps says which steps of the checklist are done. Each is read
// from what exists, so doing it outside the flow counts too.
type OnboardingSteps struct {
	Project       bool `json:"project"`       // a project exists
	Asset         bool `json:"asset"`         // an asset (in the chosen project) has reported
	Notifications bool `json:"notifications"` // a notification route is on
	Invite        bool `json:"invite"`        // someone was invited, or the organisation has other members
}

func (s OnboardingSteps) all() bool { return s.Project && s.Asset && s.Notifications && s.Invite }

// GetOnboarding returns the workspace's onboarding state. When every step
// is done the state becomes done, and the checklist stops showing.
func (s *Store) GetOnboarding(ctx context.Context) (*Onboarding, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil, errNoWorkspace
	}
	ctx = tenant.WithoutProject(ctx)
	o := &Onboarding{}
	var project *int64
	if err := s.Pool.QueryRow(ctx, `SELECT onboarding_state, onboarding_project_id FROM workspaces WHERE id = $1`, ws).Scan(&o.State, &project); err != nil {
		return nil, notFound(err)
	}
	if project != nil {
		p, err := s.GetProject(ctx, *project)
		switch {
		case err == nil && p.ArchivedAt == nil:
			o.ProjectID, o.Project = p.ID, p
		case err != nil && !errors.Is(err, ErrNotFound):
			return nil, err
		}
	}
	err := s.Pool.QueryRow(ctx, `SELECT
		  EXISTS (SELECT 1 FROM assets WHERE merged_into IS NULL),
		  EXISTS (SELECT 1 FROM projects WHERE archived_at IS NULL),
		  CASE WHEN $1::bigint = 0 THEN EXISTS (SELECT 1 FROM assets WHERE merged_into IS NULL)
		       ELSE EXISTS (SELECT 1 FROM project_assets WHERE project_id = $1) END,
		  EXISTS (SELECT 1 FROM routes r WHERE r.enabled AND (cardinality(r.project_ids) = 0 OR $1 = ANY(r.project_ids) OR $1::bigint = 0)),
		  EXISTS (SELECT 1 FROM invitations WHERE revoked_at IS NULL)
		    OR (SELECT count(*) FROM workspace_members WHERE workspace_id = $2) > 1`, o.ProjectID, ws).
		Scan(&o.HasAssets, &o.Steps.Project, &o.Steps.Asset, &o.Steps.Notifications, &o.Steps.Invite)
	if err != nil {
		return nil, err
	}
	if o.State != OnboardingDone && o.Steps.all() {
		if _, err := s.Pool.Exec(ctx, `UPDATE workspaces SET onboarding_state = 'done' WHERE id = $1`, ws); err != nil {
			return nil, err
		}
		o.State = OnboardingDone
	}
	o.ShowFlow = o.State == OnboardingNew && !o.HasAssets
	return o, nil
}

// OnboardingUpdate changes the state or the project chosen in the flow.
type OnboardingUpdate struct {
	State     *string `json:"state"`
	ProjectID *int64  `json:"project_id"`
}

func (s *Store) UpdateOnboarding(ctx context.Context, u OnboardingUpdate) error {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return errNoWorkspace
	}
	ctx = tenant.WithoutProject(ctx)
	if u.State != nil {
		switch *u.State {
		case OnboardingNew, OnboardingSkipped, OnboardingDone:
		default:
			return fmt.Errorf("state must be new, skipped or done: %w", ErrInvalid)
		}
	}
	var project *int64
	if u.ProjectID != nil && *u.ProjectID > 0 {
		var ok bool
		if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM projects WHERE id = $1 AND archived_at IS NULL)`, *u.ProjectID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no such project: %w", ErrInvalid)
		}
		project = u.ProjectID
	}
	_, err := s.Pool.Exec(ctx, `UPDATE workspaces SET onboarding_state = COALESCE($2, onboarding_state),
		onboarding_project_id = CASE WHEN $3::boolean THEN $4 ELSE onboarding_project_id END WHERE id = $1`,
		ws, u.State, u.ProjectID != nil, project)
	return err
}

// --- the waiting screen

// FirstResult is an asset the waiting screen reports on: when it reported,
// whether its first check is done, and what it found.
type FirstResult struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Environment string     `json:"environment"`
	CreatedAt   time.Time  `json:"created_at"`
	LastSeen    *time.Time `json:"last_seen"`
	// Checked: its first complete report has been compared with the
	// intelligence, so the counts below are final.
	Checked  bool `json:"checked"`
	Packages int  `json:"packages"`
	Issues   int  `json:"issues"`
	// FixesNow is how many fixes matter now (Home's focus); the handler
	// fills it.
	FixesNow int `json:"fixes_now"`
}

// FirstResults returns the assets created since `since` that the caller
// can see (row-level security applies the project), newest first.
func (s *Store) FirstResults(ctx context.Context, since time.Time) ([]FirstResult, error) {
	rows, err := s.Pool.Query(ctx, `SELECT a.id, a.name, a.kind, a.environment, a.created_at, a.last_seen,
		  (a.evaluated_at IS NOT NULL
		    AND EXISTS (SELECT 1 FROM collections c WHERE c.asset_id = a.id AND c.complete AND c.received_at <= a.evaluated_at)
		    AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.dedupe_key = 'evaluate:asset:' || a.id AND j.done_at IS NULL AND j.failed_at IS NULL)),
		  (SELECT count(*) FROM inventory i WHERE i.asset_id = a.id AND i.removed_at IS NULL)::int,
		  (SELECT count(*) FROM findings f WHERE f.asset_id = a.id AND `+activeFinding+`)::int,
		  0
		FROM assets a WHERE a.merged_into IS NULL AND a.created_at >= $1 ORDER BY a.created_at DESC, a.id DESC LIMIT 20`, since)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[FirstResult])
}

// --- assets added for a project

// SetTokenProject makes the assets a collector token creates land in a
// project (an active one of the token's workspace).
func (s *Store) SetTokenProject(ctx context.Context, tokenID, projectID int64) error {
	tag, err := s.Pool.Exec(tenant.WithoutProject(ctx), `UPDATE api_tokens SET project_id = $2
		WHERE id = $1 AND EXISTS (SELECT 1 FROM projects WHERE id = $2 AND archived_at IS NULL)`, tokenID, projectID)
	if err == nil && tag.RowsAffected() == 0 {
		return fmt.Errorf("no such project: %w", ErrInvalid)
	}
	return err
}

// ActiveProject reports whether id is an active project of the workspace.
func (s *Store) ActiveProject(ctx context.Context, id int64) (bool, error) {
	var ok bool
	err := s.Pool.QueryRow(tenant.WithoutProject(ctx), `SELECT EXISTS (SELECT 1 FROM projects WHERE id = $1 AND archived_at IS NULL)`, id).Scan(&ok)
	return ok, err
}

// --- invitations

// Invitation is a single-use link to join the organisation, with a role on
// a project (or organisation-wide when ProjectID is nil).
type Invitation struct {
	ID          int64      `json:"id"`
	WorkspaceID int64      `json:"workspace_id"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	ProjectID   *int64     `json:"project_id"`
	ProjectName string     `json:"project_name"`
	Role        auth.Role  `json:"role"`
	Prefix      string     `json:"prefix"`
	CreatedBy   *int64     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	EmailedAt   *time.Time `json:"emailed_at"`
	AcceptedAt  *time.Time `json:"accepted_at"`
	AcceptedBy  *int64     `json:"accepted_by"`
	RevokedAt   *time.Time `json:"revoked_at"`
	// Status: pending, accepted, revoked or expired.
	Status string `json:"status"`
}

// InvitationTTL is how long an invitation link works.
const InvitationTTL = 7 * 24 * time.Hour

const invitationCols = `i.id, i.workspace_id, i.email, i.name, i.project_id, COALESCE(p.name, ''), i.role, i.prefix, i.created_by,
	i.created_at, i.expires_at, i.emailed_at, i.accepted_at, i.accepted_by, i.revoked_at,
	CASE WHEN i.accepted_at IS NOT NULL THEN 'accepted' WHEN i.revoked_at IS NOT NULL THEN 'revoked'
	     WHEN i.expires_at <= now() THEN 'expired' ELSE 'pending' END`

const invitationFrom = ` FROM invitations i LEFT JOIN projects p ON p.id = i.project_id`

// ErrInvitationInvalid hides whether a link is unknown, used, expired or
// revoked: the public endpoints reveal nothing about invitations.
var ErrInvitationInvalid = errors.New("this invitation link is not valid any more; ask for a new one")

// ErrSignInRequired: an account with the invitation's email exists, and
// the caller is not signed in to it.
var ErrSignInRequired = errors.New("an account with this email exists; sign in to it, then open the link again")

// ErrWrongAccount: the caller is signed in to an account other than the
// one the invitation is for.
var ErrWrongAccount = errors.New("this invitation is for another email address; sign out, then open the link again")

// CreateInvitation stores an invitation and returns its link token, shown
// once. An open invitation for the same person and project is replaced.
func (s *Store) CreateInvitation(ctx context.Context, email, name string, projectID *int64, role auth.Role, by int64) (*Invitation, string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	name = strings.TrimSpace(name)
	if !validEmail(email) {
		return nil, "", fmt.Errorf("a valid email is required: %w", ErrInvalid)
	}
	if len(name) > 200 {
		return nil, "", fmt.Errorf("name is limited to 200 characters: %w", ErrInvalid)
	}
	if !role.ValidUser() {
		return nil, "", fmt.Errorf("role must be viewer, engineer, security or admin: %w", ErrInvalid)
	}
	secret, prefix, err := auth.NewToken("inv")
	if err != nil {
		return nil, "", err
	}
	var byID *int64
	if by > 0 {
		byID = &by
	}
	ctx = tenant.WithoutProject(ctx)
	var id int64
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if projectID != nil {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM projects WHERE id = $1 AND archived_at IS NULL)`, *projectID).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("no such project: %w", ErrInvalid)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE invitations SET revoked_at = now()
			WHERE email = $1 AND project_id IS NOT DISTINCT FROM $2 AND accepted_at IS NULL AND revoked_at IS NULL`, email, projectID); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `INSERT INTO invitations (email, name, project_id, role, prefix, token_hash, created_by, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8)) RETURNING id`,
			email, name, projectID, role, prefix, auth.HashToken(secret), byID, InvitationTTL.Seconds()).Scan(&id)
		if isForeignKey(err) {
			return fmt.Errorf("no such project: %w", ErrInvalid)
		}
		return err
	})
	if err != nil {
		return nil, "", err
	}
	inv, err := s.GetInvitation(ctx, id)
	return inv, secret, err
}

func validEmail(e string) bool {
	at := strings.LastIndexByte(e, '@')
	return at > 0 && at < len(e)-1 && len(e) <= 254 && !strings.ContainsAny(e, " \t\r\n<>,;\"")
}

func (s *Store) GetInvitation(ctx context.Context, id int64) (*Invitation, error) {
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `SELECT `+invitationCols+invitationFrom+` WHERE i.id = $1`, id)
	if err != nil {
		return nil, err
	}
	inv, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Invitation])
	return inv, notFound(err)
}

// ListInvitations returns the workspace's invitations, newest first:
// pending ones, and the others of the last 30 days.
func (s *Store) ListInvitations(ctx context.Context, projectID int64) ([]Invitation, error) {
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `SELECT `+invitationCols+invitationFrom+`
		WHERE ($1::bigint = 0 OR i.project_id = $1)
		  AND ((i.accepted_at IS NULL AND i.revoked_at IS NULL) OR i.created_at > now() - interval '30 days')
		ORDER BY i.created_at DESC, i.id DESC LIMIT 200`, projectID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Invitation])
}

// MarkInvitationEmailed records that the link was sent by email.
func (s *Store) MarkInvitationEmailed(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(tenant.WithoutProject(ctx), `UPDATE invitations SET emailed_at = now() WHERE id = $1`, id)
	return err
}

// RevokeInvitation ends a pending invitation; its link stops working.
func (s *Store) RevokeInvitation(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(tenant.WithoutProject(ctx), `UPDATE invitations SET revoked_at = now()
		WHERE id = $1 AND accepted_at IS NULL AND revoked_at IS NULL`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// InvitationPreview is what the person following a link sees before
// accepting: who invited them, to what, with which role.
type InvitationPreview struct {
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	Workspace     string    `json:"workspace"`
	Project       string    `json:"project"`
	Role          auth.Role `json:"role"`
	InvitedBy     string    `json:"invited_by"`
	ExpiresAt     time.Time `json:"expires_at"`
	AccountExists bool      `json:"account_exists"`
}

// pendingByToken finds a usable invitation by its link token, in system
// scope (the caller is not a member of its workspace yet).
func pendingByToken(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, token string, lock bool) (*Invitation, error) {
	if !strings.HasPrefix(token, "inv_") || len(token) > 200 {
		return nil, ErrInvitationInvalid
	}
	sql := `SELECT i.id, i.workspace_id, i.email, i.name, i.project_id, i.role FROM invitations i
		JOIN workspaces w ON w.id = i.workspace_id AND w.disabled_at IS NULL
		LEFT JOIN projects p ON p.id = i.project_id
		WHERE i.token_hash = $1 AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > now()
		  AND (i.project_id IS NULL OR p.archived_at IS NULL)`
	if lock {
		sql += ` FOR UPDATE OF i`
	}
	var inv Invitation
	err := q.QueryRow(ctx, sql, auth.HashToken(token)).Scan(&inv.ID, &inv.WorkspaceID, &inv.Email, &inv.Name, &inv.ProjectID, &inv.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvitationInvalid
	}
	return &inv, err
}

// PreviewInvitation describes a usable invitation by its link token.
func (s *Store) PreviewInvitation(ctx context.Context, token string) (*InvitationPreview, error) {
	sys := tenant.System(ctx)
	inv, err := pendingByToken(sys, s.Pool, token, false)
	if err != nil {
		return nil, err
	}
	out := &InvitationPreview{Email: inv.Email, Name: inv.Name, Role: inv.Role}
	err = s.Pool.QueryRow(sys, `SELECT w.name, COALESCE(p.name, ''), COALESCE(NULLIF(u.name, ''), u.email, ''), i.expires_at,
		  EXISTS (SELECT 1 FROM users x WHERE x.email = i.email)
		FROM invitations i JOIN workspaces w ON w.id = i.workspace_id
		LEFT JOIN projects p ON p.id = i.project_id LEFT JOIN users u ON u.id = i.created_by
		WHERE i.id = $1`, inv.ID).Scan(&out.Workspace, &out.Project, &out.InvitedBy, &out.ExpiresAt, &out.AccountExists)
	return out, err
}

// Accepted is what accepting an invitation did.
type Accepted struct {
	Invitation  *Invitation
	UserID      int64
	WorkspaceID int64
	// AccountCreated: a new account was made with the password given.
	AccountCreated bool
	// Joined: the person became a member of the organisation; false when
	// they already were one.
	Joined bool
	// Grant is the project grant made or kept (nil for an
	// organisation-wide invitation).
	Grant *Grant
}

// AcceptInvitation uses up an invitation. Everything it grants comes from
// the stored invitation, never from the caller: the workspace, the project
// and the role. signedIn is the account the caller is signed in to (0:
// none). When an account with the invitation's email exists, the caller
// must be signed in to it; otherwise a new account is created with name
// and password. It never lowers or raises an existing member's
// organisation-wide role, and keeps a higher existing project grant.
func (s *Store) AcceptInvitation(ctx context.Context, token string, signedIn int64, name, password string) (*Accepted, error) {
	sys := tenant.System(ctx)
	out := &Accepted{}
	var invID int64
	err := pgx.BeginFunc(sys, s.Pool, func(tx pgx.Tx) error {
		inv, err := pendingByToken(sys, tx, token, true)
		if err != nil {
			return err
		}
		invID, out.WorkspaceID = inv.ID, inv.WorkspaceID
		var uid int64
		var disabled bool
		err = tx.QueryRow(sys, `SELECT id, disabled FROM users WHERE email = $1`, inv.Email).Scan(&uid, &disabled)
		switch {
		case err == nil:
			if signedIn != uid {
				if signedIn != 0 {
					return ErrWrongAccount
				}
				return ErrSignInRequired
			}
			if disabled {
				return ErrInvitationInvalid
			}
		case errors.Is(err, pgx.ErrNoRows):
			if signedIn != 0 {
				// Signed in as someone else: the link is for another person.
				return ErrWrongAccount
			}
			if name = strings.TrimSpace(name); name == "" {
				name = inv.Name
			}
			if len(name) > 200 {
				return fmt.Errorf("name is limited to 200 characters: %w", ErrInvalid)
			}
			if err := auth.ValidPassword(password); err != nil {
				return err
			}
			hash, err := auth.HashPassword(password)
			if err != nil {
				return err
			}
			if err := tx.QueryRow(sys, `INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3) RETURNING id`,
				inv.Email, name, hash).Scan(&uid); err != nil {
				return err
			}
			out.AccountCreated = true
		default:
			return err
		}
		out.UserID = uid
		// An organisation-wide invitation gives its role to someone who is
		// not a member yet; a project invitation adds them with project
		// access only. An existing membership is left as it is.
		var orgRole *auth.Role
		if inv.ProjectID == nil {
			orgRole = &inv.Role
		}
		tag, err := tx.Exec(sys, `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, $3)
			ON CONFLICT (workspace_id, user_id) DO NOTHING`, inv.WorkspaceID, uid, orgRole)
		if err != nil {
			return err
		}
		out.Joined = tag.RowsAffected() == 1
		if inv.ProjectID != nil {
			var gid int64
			err := tx.QueryRow(sys, `INSERT INTO access_grants (workspace_id, project_id, user_id, role, created_by)
				SELECT $1, $2, $3, $4, created_by FROM invitations WHERE id = $5
				ON CONFLICT (project_id, user_id) WHERE project_id IS NOT NULL AND user_id IS NOT NULL
				DO UPDATE SET role = CASE WHEN `+roleRank("EXCLUDED.role")+` > `+roleRank("access_grants.role")+`
				  THEN EXCLUDED.role ELSE access_grants.role END
				RETURNING id`, inv.WorkspaceID, *inv.ProjectID, uid, inv.Role, inv.ID).Scan(&gid)
			if err != nil {
				return err
			}
			out.Grant = &Grant{ID: gid}
		}
		_, err = tx.Exec(sys, `UPDATE invitations SET accepted_at = now(), accepted_by = $2 WHERE id = $1`, inv.ID, uid)
		return err
	})
	if err != nil {
		return nil, err
	}
	wctx := tenant.WithWorkspace(ctx, out.WorkspaceID)
	var err2 error
	if out.Invitation, err2 = s.GetInvitation(wctx, invID); err2 != nil {
		return nil, err2
	}
	if out.Grant != nil {
		if out.Grant, err2 = s.GetGrant(wctx, out.Grant.ID); err2 != nil {
			return nil, err
		}
	}
	return out, nil
}

// MemberByEmail returns the id of the account with email and whether it is
// a member of the context's workspace (0, false: no such account).
func (s *Store) MemberByEmail(ctx context.Context, email string) (int64, bool, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return 0, false, errNoWorkspace
	}
	var id int64
	var member bool
	err := s.Pool.QueryRow(ctx, `SELECT u.id, EXISTS (SELECT 1 FROM workspace_members m WHERE m.user_id = u.id AND m.workspace_id = $2)
		FROM users u WHERE u.email = lower($1)`, strings.TrimSpace(email), ws).Scan(&id, &member)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	return id, member, err
}

// FirstEmailChannel returns the workspace's first enabled email channel,
// whose SMTP server sends invitations (nil: none).
func (s *Store) FirstEmailChannel(ctx context.Context) (*Channel, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+channelCols+` FROM channels WHERE kind = 'email' AND enabled ORDER BY id LIMIT 1`)
	if err != nil {
		return nil, err
	}
	ch, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Channel])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return ch, err
}
