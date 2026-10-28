package store

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

type Workspace struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Slug        string     `json:"slug"`
	CreatedAt   time.Time  `json:"created_at"`
	DisabledAt  *time.Time `json:"disabled_at"`
	MemberCount int64      `json:"member_count"`
	AssetCount  int64      `json:"asset_count"`
	Plan        string     `json:"plan"`
	// Monitored counts the assets the limit applies to; AssetLimit is nil
	// when the workspace has no limit (docs/asset-limits.md).
	Monitored  int64  `json:"monitored"`
	AssetLimit *int64 `json:"asset_limit"`
	// Projects counts active projects; ProjectLimit is nil when there is
	// no project limit.
	Projects     int64  `json:"projects"`
	ProjectLimit *int64 `json:"project_limit"`
	// ReadOnlyAt is when the workspace became read-only; nil when it is
	// not.
	ReadOnlyAt     *time.Time `json:"read_only_at"`
	ReadOnlyReason string     `json:"read_only_reason"`
	ReportMode     string     `json:"report_mode"`
}

// Membership is one workspace a user belongs to, with their role there.
type Membership struct {
	WorkspaceID int64     `json:"workspace_id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Role        auth.Role `json:"role"`
	// Access is "organisation" or "projects" (project access only; Role
	// is then empty).
	Access string `json:"access"`
}

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Slugify turns a workspace name into a URL-safe slug.
func Slugify(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.TrimRight(b.String(), "-")
	if len(s) > 63 {
		s = strings.TrimRight(s[:63], "-")
	}
	return s
}

// Memberships lists the enabled workspaces a user belongs to, oldest first.
func (s *Store) Memberships(ctx context.Context, userID int64) ([]Membership, error) {
	rows, err := s.Pool.Query(ctx, `SELECT w.id, w.name, w.slug, COALESCE(m.role, ''),
		CASE WHEN m.role IS NULL THEN 'projects' ELSE 'organisation' END FROM workspace_members m
		JOIN workspaces w ON w.id = m.workspace_id
		WHERE m.user_id = $1 AND w.disabled_at IS NULL ORDER BY w.id`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Membership])
}

// MemberRole returns the user's organisation-wide role in an enabled
// workspace, or "" when they are not a member or have project access only.
func (s *Store) MemberRole(ctx context.Context, workspaceID, userID int64) (auth.Role, error) {
	var role auth.Role
	err := s.Pool.QueryRow(ctx, `SELECT COALESCE(m.role, '') FROM workspace_members m JOIN workspaces w ON w.id = m.workspace_id
		WHERE m.workspace_id = $1 AND m.user_id = $2 AND w.disabled_at IS NULL`, workspaceID, userID).Scan(&role)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	return role, err
}

// IsMember reports whether the user belongs to an enabled workspace, with
// an organisation-wide role or with project access only.
func (s *Store) IsMember(ctx context.Context, workspaceID, userID int64) (bool, error) {
	var ok bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM workspace_members m JOIN workspaces w ON w.id = m.workspace_id
		WHERE m.workspace_id = $1 AND m.user_id = $2 AND w.disabled_at IS NULL)`, workspaceID, userID).Scan(&ok)
	return ok, err
}

// WorkspaceEnabled reports whether a workspace exists and is not disabled.
func (s *Store) WorkspaceEnabled(ctx context.Context, id int64) (bool, error) {
	var ok bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM workspaces WHERE id = $1 AND disabled_at IS NULL)`, id).Scan(&ok)
	return ok, err
}

// ActiveWorkspaceIDs lists enabled workspaces, for per-workspace background work.
func (s *Store) ActiveWorkspaceIDs(ctx context.Context) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id FROM workspaces WHERE disabled_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

func (s *Store) GetWorkspace(ctx context.Context, id int64) (*Workspace, error) {
	rows, err := s.Pool.Query(ctx, workspaceSelect+` WHERE w.id = $1`, id)
	if err != nil {
		return nil, err
	}
	w, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Workspace])
	return w, notFound(err)
}

// WorkspaceByRef finds a workspace by id or slug, for configuration such as
// STACKURITY_PLATFORM_WORKSPACE, and reports whether it is disabled.
func (s *Store) WorkspaceByRef(ctx context.Context, ref string) (id int64, disabled bool, err error) {
	ref = strings.ToLower(strings.TrimSpace(ref))
	byID, convErr := strconv.ParseInt(ref, 10, 64)
	if convErr != nil {
		byID = 0
	}
	err = s.Pool.QueryRow(tenant.System(ctx), `SELECT id, disabled_at IS NOT NULL FROM workspaces
		WHERE id = $1 OR slug = $2 ORDER BY id = $1 DESC LIMIT 1`, byID, ref).Scan(&id, &disabled)
	return id, disabled, notFound(err)
}

// Counts read tenant tables, so listing all workspaces needs system scope.
const workspaceSelect = `SELECT w.id, w.name, w.slug, w.created_at, w.disabled_at,
	(SELECT count(*) FROM workspace_members m WHERE m.workspace_id = w.id),
	(SELECT count(*) FROM assets a WHERE a.workspace_id = w.id AND a.merged_into IS NULL),
	w.plan,
	(SELECT count(*) FROM assets a WHERE a.workspace_id = w.id AND a.merged_into IS NULL AND a.kind <> 'workload'),
	w.asset_limit,
	(SELECT count(*) FROM projects p WHERE p.workspace_id = w.id AND p.archived_at IS NULL),
	w.project_limit, w.read_only_at, w.read_only_reason, w.report_mode
	FROM workspaces w`

// ListWorkspaces lists every workspace. Instance administration only.
func (s *Store) ListWorkspaces(ctx context.Context) ([]Workspace, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), workspaceSelect+` ORDER BY w.id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Workspace])
}

// CreateWorkspace creates a workspace whose first admin is the user with
// adminEmail; a new account is created (with password) if none exists.
func (s *Store) CreateWorkspace(ctx context.Context, name, slug, adminEmail, adminName, password string) (*Workspace, *User, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return nil, nil, fmt.Errorf("name is required (max 100 characters): %w", ErrInvalid)
	}
	if slug == "" {
		slug = Slugify(name)
	}
	if !slugRE.MatchString(slug) {
		return nil, nil, fmt.Errorf("slug must be lowercase letters, digits and dashes: %w", ErrInvalid)
	}
	var wsID, userID int64
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `INSERT INTO workspaces (name, slug) VALUES ($1, $2) RETURNING id`, name, slug).Scan(&wsID)
		if isUniqueViolation(err) {
			return fmt.Errorf("a workspace with slug %q already exists: %w", slug, ErrConflict)
		}
		if err != nil {
			return err
		}
		userID, err = ensureUser(ctx, tx, adminEmail, adminName, password)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, 'admin')`, wsID, userID)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	w, err := s.GetWorkspace(tenant.System(ctx), wsID)
	if err != nil {
		return nil, nil, err
	}
	u, err := s.GetUser(tenant.WithWorkspace(ctx, wsID), userID)
	return w, u, err
}

type WorkspaceUpdate struct {
	Name     *string `json:"name"`
	Disabled *bool   `json:"disabled"`
	// Plan is "inherit", "community", "pro" or "enterprise".
	Plan *string `json:"plan"`
	// AssetLimit sets the monitored-asset limit; -1 removes it.
	AssetLimit *int64 `json:"asset_limit"`
	// ProjectLimit sets the project limit; -1 removes it.
	ProjectLimit *int64 `json:"project_limit"`
	// ReadOnly makes the workspace read-only (keeping an earlier time when
	// it already is) or writable again; ReadOnlyReason is shown to its
	// members.
	ReadOnly       *bool   `json:"read_only"`
	ReadOnlyReason *string `json:"read_only_reason"`
	// ReportMode is full or trial.
	ReportMode *string `json:"report_mode"`
}

func (s *Store) UpdateWorkspace(ctx context.Context, id int64, u WorkspaceUpdate) error {
	if u.Name != nil {
		n := strings.TrimSpace(*u.Name)
		if n == "" || len(n) > 100 {
			return fmt.Errorf("name is required (max 100 characters): %w", ErrInvalid)
		}
		u.Name = &n
	}
	if u.Plan != nil {
		switch *u.Plan {
		case "inherit", "community", "pro", "enterprise":
		default:
			return fmt.Errorf("plan must be inherit, community, pro or enterprise: %w", ErrInvalid)
		}
	}
	if u.AssetLimit != nil && (*u.AssetLimit < -1 || *u.AssetLimit > 1_000_000_000) {
		return fmt.Errorf("asset_limit must be between 0 and 1000000000, or -1 for no limit: %w", ErrInvalid)
	}
	if u.ProjectLimit != nil && (*u.ProjectLimit < -1 || *u.ProjectLimit > 1_000_000) {
		return fmt.Errorf("project_limit must be between 0 and 1000000, or -1 for no limit: %w", ErrInvalid)
	}
	if u.ReportMode != nil && *u.ReportMode != ReportFull && *u.ReportMode != ReportTrial {
		return fmt.Errorf("report_mode must be full or trial: %w", ErrInvalid)
	}
	if u.ReadOnlyReason != nil {
		r := strings.TrimSpace(*u.ReadOnlyReason)
		if len(r) > 500 {
			return fmt.Errorf("read_only_reason is limited to 500 characters: %w", ErrInvalid)
		}
		u.ReadOnlyReason = &r
	}
	if u.Disabled != nil && *u.Disabled && id == tenant.DefaultWorkspace {
		return fmt.Errorf("the default workspace cannot be disabled: %w", ErrConflict)
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE workspaces SET name = COALESCE($2, name),
		disabled_at = CASE WHEN $3::boolean IS NULL THEN disabled_at WHEN $3 THEN COALESCE(disabled_at, now()) ELSE NULL END,
		plan = COALESCE($4, plan),
		asset_limit = CASE WHEN $5::bigint IS NULL THEN asset_limit WHEN $5 < 0 THEN NULL ELSE $5 END,
		project_limit = CASE WHEN $6::bigint IS NULL THEN project_limit WHEN $6 < 0 THEN NULL ELSE $6 END,
		read_only_at = CASE WHEN $7::boolean IS NULL THEN read_only_at WHEN $7 THEN COALESCE(read_only_at, now()) ELSE NULL END,
		read_only_reason = CASE WHEN $7::boolean IS NOT NULL AND NOT $7 THEN '' ELSE COALESCE($8, read_only_reason) END,
		report_mode = COALESCE($9, report_mode)
		WHERE id = $1`, id, u.Name, u.Disabled, u.Plan, u.AssetLimit, u.ProjectLimit, u.ReadOnly, u.ReadOnlyReason, u.ReportMode)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ensureUser returns the id of the user with email, creating the account
// when it does not exist yet (a password is then required).
func ensureUser(ctx context.Context, tx pgx.Tx, email, name, password string) (int64, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !strings.Contains(email, "@") {
		return 0, fmt.Errorf("a valid email is required: %w", ErrInvalid)
	}
	var id int64
	err := tx.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&id)
	if err == nil {
		return id, nil
	}
	if err != pgx.ErrNoRows {
		return 0, err
	}
	if err := auth.ValidPassword(password); err != nil {
		return 0, err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return 0, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3) RETURNING id`,
		email, name, hash).Scan(&id)
	return id, err
}

// UserExists reports whether an account with email exists.
func (s *Store) UserExists(ctx context.Context, email string) (bool, error) {
	var ok bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE email = lower($1))`, strings.TrimSpace(email)).Scan(&ok)
	return ok, err
}

// SetSessionWorkspace switches a browser session to another workspace the
// user belongs to.
func (s *Store) SetSessionWorkspace(ctx context.Context, secret string, userID, workspaceID int64) error {
	member, err := s.IsMember(ctx, workspaceID, userID)
	if err != nil {
		return err
	}
	if !member {
		return ErrNotFound
	}
	// A session pinned to a workspace (CreateSSOSession) stays there.
	tag, err := s.Pool.Exec(ctx, `UPDATE sessions SET workspace_id = $3 WHERE token_hash = $1 AND user_id = $2
		AND (sso_workspace_id IS NULL OR sso_workspace_id = $3)`,
		auth.HashToken(secret), userID, workspaceID)
	if err == nil && tag.RowsAffected() == 0 {
		return fmt.Errorf("this session was started by an organisation's single sign-on and works only there; sign in again to use another organisation: %w", ErrConflict)
	}
	return err
}

// UpdateUserInstanceAdmin grants or removes the right to operate the
// installation (manage workspaces).
func (s *Store) UpdateUserInstanceAdmin(ctx context.Context, email string, on bool) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE users SET instance_admin = $2 WHERE email = lower($1)`, strings.TrimSpace(email), on)
	return tag.RowsAffected() > 0, err
}
