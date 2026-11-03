package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

// User is an account. Accounts are global; Role is the user's role in the
// workspace the context is scoped to, empty when they are not a member.
type User struct {
	ID            int64      `json:"id"`
	Email         string     `json:"email"`
	Name          string     `json:"name"`
	Role          auth.Role  `json:"role"`
	Disabled      bool       `json:"disabled"`
	CreatedAt     time.Time  `json:"created_at"`
	LastLoginAt   *time.Time `json:"last_login_at"`
	Teams         []string   `json:"teams"`
	InstanceAdmin bool       `json:"instance_admin"`
	// Access is "organisation" for a member with an organisation-wide
	// role, "projects" for one with project access only (Role is then
	// empty), and "" for someone who is not a member.
	Access string `json:"access"`
	// MFAEnabled: the account has a second factor (any method).
	MFAEnabled bool `json:"mfa_enabled"`
	// MFAMethods lists the account's second factors (passkey, totp, email).
	MFAMethods []string `json:"mfa_methods"`
	// Phone is contact information kept on the membership in this
	// workspace (migration 0080); empty when not given.
	Phone string `json:"phone"`
	// ProjectGrants and AssetGrants count the person's own grants in this
	// workspace (not their teams'): what a member with project access only
	// sees, at a glance.
	ProjectGrants int64 `json:"project_grants"`
	AssetGrants   int64 `json:"asset_grants"`
	// AccessTeams names their teams in this workspace that can see
	// something (a grant on an active project or an unmerged asset):
	// access they have through team membership.
	AccessTeams []string `json:"access_teams"`
}

const userCols = `u.id, u.email, u.name,
	COALESCE((SELECT wm.role FROM workspace_members wm WHERE wm.user_id = u.id AND wm.workspace_id = stackurity_ws()), ''),
	u.disabled, u.created_at, u.last_login_at,
	COALESCE((SELECT array_agg(t.name ORDER BY t.name) FROM team_members m JOIN teams t ON t.id = m.team_id WHERE m.user_id = u.id), '{}'),
	u.instance_admin,
	COALESCE((SELECT CASE WHEN wm.role IS NULL THEN 'projects' ELSE 'organisation' END FROM workspace_members wm
	  WHERE wm.user_id = u.id AND wm.workspace_id = stackurity_ws()), ''),
	` + mfaMethodsSQL + ` <> '{}', ` + mfaMethodsSQL + `,
	COALESCE((SELECT wm.phone FROM workspace_members wm WHERE wm.user_id = u.id AND wm.workspace_id = stackurity_ws()), ''),
	(SELECT count(*) FROM access_grants g WHERE g.user_id = u.id AND g.workspace_id = stackurity_ws() AND g.project_id IS NOT NULL),
	(SELECT count(*) FROM access_grants g WHERE g.user_id = u.id AND g.workspace_id = stackurity_ws() AND g.asset_id IS NOT NULL),
	COALESCE((SELECT array_agg(t.name ORDER BY t.name) FROM team_members m JOIN teams t ON t.id = m.team_id
	  WHERE m.user_id = u.id AND t.workspace_id = stackurity_ws() AND EXISTS (SELECT 1 FROM access_grants g
	    LEFT JOIN projects p ON p.id = g.project_id LEFT JOIN assets a ON a.id = g.asset_id
	    WHERE g.team_id = t.id AND (g.project_id IS NOT NULL AND p.archived_at IS NULL OR g.asset_id IS NOT NULL AND a.merged_into IS NULL))), '{}')`

func (s *Store) CountUsers(ctx context.Context) (int64, error) {
	var n int64
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser adds a user to the context's workspace: a new account with
// password, or an existing account (whose password is left alone).
func (s *Store) CreateUser(ctx context.Context, email, name string, role auth.Role, password string) (*User, error) {
	_, err := s.AddMember(ctx, email, name, role, password)
	if err != nil {
		return nil, err
	}
	var id int64
	if err := s.Pool.QueryRow(ctx, `SELECT id FROM users WHERE email = lower($1)`, strings.TrimSpace(email)).Scan(&id); err != nil {
		return nil, err
	}
	return s.GetUser(ctx, id)
}

// AddMember adds the user with email to the context's workspace with role,
// creating the account (with password) when it does not exist. It reports
// whether a new account was created.
func (s *Store) AddMember(ctx context.Context, email, name string, role auth.Role, password string) (created bool, err error) {
	if !role.ValidUser() && role != RoleNone {
		return false, fmt.Errorf("invalid role %q", role)
	}
	var orgRole *auth.Role // RoleNone: project access only
	if role != RoleNone {
		orgRole = &role
	}
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return false, errNoWorkspace
	}
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var before int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&before); err != nil {
			return err
		}
		id, err := ensureUser(ctx, tx, email, name, password)
		if err != nil {
			return err
		}
		var after int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&after); err != nil {
			return err
		}
		created = after > before
		tag, err := tx.Exec(ctx, `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, $3)
			ON CONFLICT (workspace_id, user_id) DO NOTHING`, ws, id, orgRole)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("a user with that email is already a member: %w", ErrConflict)
		}
		return nil
	})
	return created, err
}

// RemoveMember removes a user from the context's workspace. The account and
// its other memberships are untouched; its tokens for this workspace stop
// working because tokens require membership.
func (s *Store) RemoveMember(ctx context.Context, userID int64) error {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return errNoWorkspace
	}
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM workspace_members WHERE workspace_id = $1 AND user_id = $2`, ws, userID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err := requireActiveAdmin(ctx, tx, ws); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM team_members WHERE user_id = $1`, userID); err != nil {
			return err
		}
		// Their project and asset grants go too, so rejoining later starts
		// with no access.
		if _, err := tx.Exec(ctx, `DELETE FROM access_grants WHERE user_id = $1`, userID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE sessions SET workspace_id = NULL WHERE user_id = $1 AND workspace_id = $2`, userID, ws)
		return err
	})
}

// requireActiveAdmin refuses to leave a workspace without an active admin.
func requireActiveAdmin(ctx context.Context, tx pgx.Tx, ws int64) error {
	var admins int64
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM workspace_members m JOIN users u ON u.id = m.user_id
		WHERE m.workspace_id = $1 AND m.role = 'admin' AND NOT u.disabled`, ws).Scan(&admins); err != nil {
		return err
	}
	if admins == 0 {
		return fmt.Errorf("at least one active admin is required: %w", ErrConflict)
	}
	return nil
}

var errNoWorkspace = errors.New("no workspace selected")

// CreateFirstAdmin creates an admin only if no users exist, atomically.
func (s *Store) CreateFirstAdmin(ctx context.Context, email, name, password string) (*User, error) {
	if err := auth.ValidPassword(password); err != nil {
		return nil, err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}
	var id int64
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `LOCK TABLE users IN EXCLUSIVE MODE`); err != nil {
			return err
		}
		var n int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("setup already completed: %w", ErrConflict)
		}
		// The first user operates the installation and administers the
		// default workspace.
		if err := tx.QueryRow(ctx, `INSERT INTO users (email, name, role, password_hash, instance_admin)
			VALUES (lower($1), $2, 'admin', $3, true) RETURNING id`, strings.TrimSpace(email), name, hash).Scan(&id); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, 'admin')`,
			tenant.DefaultWorkspace, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.GetUser(tenant.WithWorkspace(ctx, tenant.DefaultWorkspace), id)
}

func (s *Store) GetUser(ctx context.Context, id int64) (*User, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+userCols+` FROM users u WHERE u.id = $1`, id)
	if err != nil {
		return nil, err
	}
	u, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[User])
	return u, notFound(err)
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+userCols+` FROM users u
		WHERE EXISTS (SELECT 1 FROM workspace_members wm WHERE wm.user_id = u.id AND wm.workspace_id = stackurity_ws())
		ORDER BY u.email`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[User])
}

type UserUpdate struct {
	Name     *string    `json:"name"`
	Role     *auth.Role `json:"role"`
	Disabled *bool      `json:"disabled"`
	Password *string    `json:"password"`
	// Phone is contact information on the membership in this workspace,
	// so any admin of it may change it ("" clears it).
	Phone *string `json:"phone"`
	// Temporary: the password is set by an administrator for someone
	// else; they must choose their own at their next sign-in.
	Temporary bool `json:"-"`
}

// UpdateUser changes a member of the context's workspace. The role is the
// workspace role. Name, password and disabled belong to the account, which
// other workspaces may share, so they can be changed only by an instance
// admin or when the account belongs to this workspace alone.
func (s *Store) UpdateUser(ctx context.Context, id int64, u UserUpdate, instanceAdmin bool) error {
	if u.Role != nil && !u.Role.ValidUser() && *u.Role != RoleNone {
		return fmt.Errorf("invalid role %q", *u.Role)
	}
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return errNoWorkspace
	}
	if u.Phone != nil {
		p, err := NormalizePhone(*u.Phone)
		if err != nil {
			return err
		}
		u.Phone = &p
	}
	var hash *string
	if u.Password != nil {
		if err := auth.ValidPassword(*u.Password); err != nil {
			return err
		}
		h, err := auth.HashPassword(*u.Password)
		if err != nil {
			return err
		}
		hash = &h
	}
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var others int64
		err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE workspace_id <> $2) FROM workspace_members
			WHERE user_id = $1 HAVING bool_or(workspace_id = $2)`, id, ws).Scan(&others)
		if err == pgx.ErrNoRows {
			return ErrNotFound // not a member of this workspace
		}
		if err != nil {
			return err
		}
		var targetInstanceAdmin bool
		if err := tx.QueryRow(ctx, `SELECT instance_admin FROM users WHERE id = $1`, id).Scan(&targetInstanceAdmin); err != nil {
			return notFound(err)
		}
		account := u.Name != nil || u.Disabled != nil || hash != nil
		if account && others > 0 && !instanceAdmin {
			return fmt.Errorf("this account also belongs to other workspaces; only an instance admin can change its name, password or status: %w", ErrConflict)
		}
		// An instance admin's password is the key to the whole installation;
		// a workspace admin must not be able to set it.
		if account && targetInstanceAdmin && !instanceAdmin {
			return fmt.Errorf("this account is an instance admin; only an instance admin can change its name, password or status: %w", ErrConflict)
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET name = COALESCE($2, name), disabled = COALESCE($3, disabled),
			password_hash = COALESCE($4, password_hash),
			password_change_required = CASE WHEN $4::text IS NULL THEN password_change_required ELSE $5 END
			WHERE id = $1`, id, u.Name, u.Disabled, hash, u.Temporary); err != nil {
			return err
		}
		if u.Role != nil {
			// RoleNone keeps the membership without an organisation-wide
			// role: the person then sees only what they are granted.
			var role *auth.Role
			if *u.Role != RoleNone {
				role = u.Role
			}
			if _, err := tx.Exec(ctx, `UPDATE workspace_members SET role = $3 WHERE workspace_id = $1 AND user_id = $2`,
				ws, id, role); err != nil {
				return err
			}
		}
		if u.Phone != nil {
			if _, err := tx.Exec(ctx, `UPDATE workspace_members SET phone = $3 WHERE workspace_id = $1 AND user_id = $2`,
				ws, id, *u.Phone); err != nil {
				return err
			}
		}
		// Never leave the workspace without an active admin.
		if err := requireActiveAdmin(ctx, tx, ws); err != nil {
			return err
		}
		// Disabling a user or changing their password ends their sessions. A
		// role change needs no sign-out: roles are read on every request, and
		// the user's sessions in other workspaces must not be disturbed.
		if (u.Disabled != nil && *u.Disabled) || hash != nil {
			_, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id)
			return err
		}
		return nil
	})
}

// Authenticate checks credentials and returns the user.
func (s *Store) Authenticate(ctx context.Context, email, password string) (*User, error) {
	var id int64
	var hash string
	var disabled bool
	err := s.Pool.QueryRow(ctx, `SELECT id, password_hash, disabled FROM users WHERE email = lower($1)`, strings.TrimSpace(email)).
		Scan(&id, &hash, &disabled)
	exists := err == nil
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if !auth.CheckPasswordOrDummy(hash, exists, password) || disabled {
		return nil, ErrNotFound
	}
	_, _ = s.Pool.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, id)
	return s.GetUser(ctx, id)
}

// TouchLastLogin records a sign-in without a password (a passkey).
func (s *Store) TouchLastLogin(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, id)
	return err
}

const SessionTTL = 12 * time.Hour

// CreateSession starts a browser session working in workspaceID (0: none yet).
func (s *Store) CreateSession(ctx context.Context, userID, workspaceID int64) (string, error) {
	return s.CreateSessionWith(ctx, userID, workspaceID, SessionOpts{})
}

// How a session was signed in (SessionOpts.Login). The two-factor policy
// of the session's workspace applies to every session except single
// sign-on's (LoginSSO, or one pinned to a workspace's own identity
// provider), where the identity provider does the second factor. A session
// with no method, or one this release does not know, is held to the policy
// too: only a sign-in that says it is single sign-on is exempt.
const (
	LoginPassword = "password"
	LoginPasskey  = "passkey"
	LoginInvite   = "invite"
	// LoginSignup: a new organisation's first session, from a hosted
	// edition's sign-up link.
	LoginSignup = "signup"
	// LoginSocial: a hosted edition's "Continue with Google, Microsoft or
	// GitHub". It is not single sign-on (the provider is the person's, not
	// the organisation's), so the policy applies.
	LoginSocial = "social"
	// LoginSSO: an OpenID Connect or SAML sign-in.
	LoginSSO = "sso"
)

// Second factors (SessionOpts.MFA, and the methods a workspace allows).
const (
	MFAPasskey  = "passkey"
	MFATOTP     = "totp"
	MFARecovery = "recovery_code"
	MFAEmail    = "email"
)

// SessionOpts says how a session was signed in.
type SessionOpts struct {
	// Login is how the session was signed in: LoginPassword, LoginPasskey,
	// LoginInvite, LoginSignup, LoginSocial or LoginSSO.
	Login string
	// MFA is the second factor checked ("" for none). A passkey sign-in
	// without a password checks one too: the passkey with user
	// verification.
	MFA string
	// MFACredential is the passkey that MFA (MFAPasskey) was checked with
	// (0: none), so removing it can downgrade the session.
	MFACredential int64
	// Pinned is the workspace a sign-in through that workspace's own
	// identity provider pins the session to (CreateSSOSession); 0: none.
	// A session that replaces a pinned one keeps its pin.
	Pinned int64
	// Expires keeps a replaced session's end; zero: SessionTTL from now.
	Expires time.Time
	// Replaces is the secret of the session this one replaces (a new ID for
	// the same sign-in): that session's row takes the new secret, keeping
	// its public ID, sign-in time, browser, address, pin and end (Pinned and
	// Expires are then not used). The old secret stops working in the same
	// transaction. When it is no longer a session of userID (signed out
	// meanwhile), nothing is created: ErrSessionEnded.
	Replaces string
}

// CreateSessionWith starts a browser session signed in as opts says.
func (s *Store) CreateSessionWith(ctx context.Context, userID, workspaceID int64, opts SessionOpts) (string, error) {
	if opts.Pinned > 0 {
		workspaceID = opts.Pinned
	}
	secret, _, err := auth.NewToken("sess")
	if err != nil {
		return "", err
	}
	var ws, pinned *int64
	if workspaceID > 0 {
		ws = &workspaceID
	}
	if opts.Pinned > 0 {
		pinned = &opts.Pinned
	}
	var mfaAt *time.Time
	if opts.MFA != "" {
		now := time.Now()
		mfaAt = &now
	}
	expires := opts.Expires
	if expires.IsZero() {
		expires = time.Now().Add(SessionTTL)
	}
	var cred *int64
	if opts.MFA == MFAPasskey && opts.MFACredential > 0 {
		cred = &opts.MFACredential
	}
	// A session signed in or confirmed with a passkey is created only while
	// that passkey is not marked as possibly copied. The row lock makes a
	// concurrent PasskeyCloneWarning (which marks it and ends its sessions
	// in one transaction) either wait for this session, and so end it, or
	// finish first, and then nothing is created: ErrPasskeyCounter.
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if cred != nil {
			var ok bool
			err := tx.QueryRow(ctx, `SELECT true FROM webauthn_credentials WHERE id = $1 AND user_id = $2 AND clone_warning_at IS NULL FOR SHARE`,
				*cred, userID).Scan(&ok)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrPasskeyCounter
			}
			if err != nil {
				return err
			}
		}
		if opts.Replaces != "" {
			// A new ID for the same sign-in: the row itself gets the new
			// token, so it keeps its public ID, browser, address, sign-in
			// time, pin and end. A session signed out meanwhile (Your account,
			// another tab's sign-out, expiry) has no row: nothing is created.
			// A concurrent sign-out by public ID either runs first (no row
			// here) or waits for this update and then deletes the renamed row.
			tag, err := tx.Exec(ctx, `UPDATE sessions SET token_hash = $3, created_at = now(), last_seen_at = now(),
				workspace_id = CASE WHEN sso_workspace_id IS NOT NULL THEN sso_workspace_id ELSE $4 END,
				password_login = $5, mfa_at = $6, login_method = NULLIF($7, ''), mfa_method = NULLIF($8, ''), mfa_credential_id = $9,
				signed_in_at = COALESCE(signed_in_at, created_at)
				WHERE token_hash = $1 AND user_id = $2 AND expires_at > now()`,
				auth.HashToken(opts.Replaces), userID, auth.HashToken(secret), ws, opts.Login == LoginPassword || opts.Login == LoginSocial, mfaAt,
				opts.Login, opts.MFA, cred)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return ErrSessionEnded
			}
			return nil
		}
		// password_login is what releases before migration 0087 read: a social
		// sign-in was one there too (held to "Require two-factor sign-in").
		// The browser is the request's (WithSessionClient).
		client := sessionClientOf(ctx)
		_, err := tx.Exec(ctx, `INSERT INTO sessions (token_hash, user_id, expires_at, workspace_id, password_login, mfa_at, sso_workspace_id,
			login_method, mfa_method, mfa_credential_id, user_agent, ip, signed_in_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), NULLIF($9, ''), $10, NULLIF($11, ''), NULLIF($12, ''), now())`,
			auth.HashToken(secret), userID, expires, ws, opts.Login == LoginPassword || opts.Login == LoginSocial, mfaAt, pinned, opts.Login, opts.MFA, cred,
			client.UserAgent, client.IP)
		return err
	})
	if err != nil {
		return "", err
	}
	return secret, err
}

// CreateSSOSession starts a browser session pinned to workspaceID, for a
// sign-in through that workspace's own identity provider: SessionUser never
// moves it to another workspace and SetSessionWorkspace refuses to.
func (s *Store) CreateSSOSession(ctx context.Context, userID, workspaceID int64) (string, error) {
	if workspaceID <= 0 {
		return "", fmt.Errorf("a pinned session needs a workspace: %w", ErrInvalid)
	}
	return s.CreateSessionWith(ctx, userID, workspaceID, SessionOpts{Login: LoginSSO, Pinned: workspaceID})
}

// Session is a resolved browser session.
type Session struct {
	User      *User
	Workspace int64
	// SSOWorkspace is the workspace the session is pinned to
	// (CreateSSOSession), 0 for an ordinary session. A pinned session works
	// only there: if the user has left it, Workspace is 0, never another.
	SSOWorkspace int64
	// Login is how the session was signed in (LoginPassword, ...; "" for
	// a session from before migration 0087 that was not a password one).
	Login string
	// MFA is the second factor checked for this session ("" for none), and
	// MFACredential the passkey it was checked with (0: none).
	MFA           string
	MFACredential int64
	// PasswordChangeRequired: an administrator set a temporary password;
	// only changing it is allowed until then.
	PasswordChangeRequired bool
	// ExpiresAt is the session's absolute end.
	ExpiresAt time.Time
}

// SessionUser resolves a browser session to its user and the workspace it
// works in. When the session has no workspace, or the user has left it, the
// user's first workspace is used; 0 means the user belongs to none. The
// returned user's Role is their role in that workspace.
func (s *Store) SessionUser(ctx context.Context, secret string) (*User, int64, error) {
	sess, err := s.SessionInfo(ctx, secret)
	if err != nil {
		return nil, 0, err
	}
	return sess.User, sess.Workspace, nil
}

// SessionUserSSO is SessionUser that also returns the workspace the session
// is pinned to (CreateSSOSession), 0 for an ordinary session.
func (s *Store) SessionUserSSO(ctx context.Context, secret string) (*User, int64, int64, error) {
	sess, err := s.SessionInfo(ctx, secret)
	if err != nil {
		return nil, 0, 0, err
	}
	return sess.User, sess.Workspace, sess.SSOWorkspace, nil
}

// SessionExpired is a session that ended because it was unused for too
// long ("idle") or reached SessionTTL ("absolute"). It is deleted when
// found; the caller records it.
type SessionExpired struct {
	Reason    string
	UserID    int64
	Email     string
	Workspace int64
}

func (e *SessionExpired) Error() string { return "session expired (" + e.Reason + ")" }

// Unwrap makes an expired session ErrNotFound to callers that only check
// whether it is valid.
func (e *SessionExpired) Unwrap() error { return ErrNotFound }

// SessionInfo is SessionUser with how the session was signed in. A session
// past its idle or absolute limit is deleted and returned as
// *SessionExpired (which is ErrNotFound).
func (s *Store) SessionInfo(ctx context.Context, secret string) (*Session, error) {
	var id int64
	var ws, pinned *int64
	var login, mfa string
	var mfaCred int64
	var expiresAt time.Time
	var changePassword, absolute, idle, touch bool
	var email string
	err := s.Pool.QueryRow(ctx, `SELECT s.user_id, s.workspace_id, s.sso_workspace_id,
		COALESCE(s.login_method, CASE WHEN s.password_login THEN 'password' ELSE '' END),
		COALESCE(s.mfa_method, CASE WHEN s.mfa_at IS NOT NULL THEN 'totp' ELSE '' END), COALESCE(s.mfa_credential_id, 0), s.expires_at,
		u.password_change_required, u.email,
		s.expires_at <= now(), $2 > 0 AND s.last_seen_at < now() - make_interval(secs => $2), s.last_seen_at < now() - interval '1 minute'
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND NOT u.disabled`, auth.HashToken(secret), s.SessionIdle.Seconds()).
		Scan(&id, &ws, &pinned, &login, &mfa, &mfaCred, &expiresAt, &changePassword, &email, &absolute, &idle, &touch)
	if err != nil {
		return nil, notFound(err)
	}
	if absolute || idle {
		tag, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, auth.HashToken(secret))
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 0 {
			return nil, ErrNotFound // another request ended it and records it
		}
		e := &SessionExpired{Reason: "idle", UserID: id, Email: email}
		if absolute {
			e.Reason = "absolute"
		}
		if ws != nil {
			e.Workspace = *ws
		}
		return nil, e
	}
	if touch {
		_, _ = s.Pool.Exec(ctx, `UPDATE sessions SET last_seen_at = now() WHERE token_hash = $1`, auth.HashToken(secret))
	}
	if pinned != nil {
		var wsID int64
		if member, err := s.IsMember(ctx, *pinned, id); err != nil {
			return nil, err
		} else if member {
			wsID = *pinned
		}
		u, err := s.GetUser(tenant.WithWorkspace(ctx, wsID), id)
		if err != nil {
			return nil, err
		}
		// An organisation's identity provider vouches for membership of
		// that organisation only, never for operating the installation.
		u.InstanceAdmin = false
		return &Session{User: u, Workspace: wsID, SSOWorkspace: *pinned, Login: login, MFA: mfa, MFACredential: mfaCred,
			PasswordChangeRequired: changePassword, ExpiresAt: expiresAt}, nil
	}
	var wsID int64
	if ws != nil {
		if member, err := s.IsMember(ctx, *ws, id); err != nil {
			return nil, err
		} else if member {
			wsID = *ws
		}
	}
	if wsID == 0 {
		ms, err := s.Memberships(ctx, id)
		if err != nil {
			return nil, err
		}
		if len(ms) > 0 {
			wsID = ms[0].WorkspaceID
			_, _ = s.Pool.Exec(ctx, `UPDATE sessions SET workspace_id = $2 WHERE token_hash = $1`, auth.HashToken(secret), wsID)
		}
	}
	u, err := s.GetUser(tenant.WithWorkspace(ctx, wsID), id)
	if err != nil {
		return nil, err
	}
	return &Session{User: u, Workspace: wsID, Login: login, MFA: mfa, MFACredential: mfaCred, PasswordChangeRequired: changePassword,
		ExpiresAt: expiresAt}, nil
}

func (s *Store) DeleteSession(ctx context.Context, secret string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, auth.HashToken(secret))
	return err
}

// EndSession signs a session out and returns whose it was (userID 0 when
// there was none), for the activity log.
func (s *Store) EndSession(ctx context.Context, secret string) (userID, workspace int64, email string, err error) {
	var ws *int64
	err = s.Pool.QueryRow(ctx, `DELETE FROM sessions s USING users u WHERE s.token_hash = $1 AND u.id = s.user_id
		RETURNING s.user_id, s.workspace_id, u.email`, auth.HashToken(secret)).Scan(&userID, &ws, &email)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, "", nil
	}
	if ws != nil {
		workspace = *ws
	}
	return userID, workspace, email, err
}

func (s *Store) PurgeExpiredSessions(ctx context.Context) error {
	for _, q := range []string{`DELETE FROM mfa_challenges WHERE expires_at < now()`, `DELETE FROM webauthn_ceremonies WHERE expires_at < now()`,
		`DELETE FROM user_email_mfa WHERE enabled_at IS NULL AND code_expires_at < now()`} {
		if _, err := s.Pool.Exec(ctx, q); err != nil {
			return err
		}
	}
	if err := s.PurgePasswordResets(ctx); err != nil {
		return err
	}
	// Sessions nobody came back to: each ending is recorded where it was
	// working, as when one is found expired at a request.
	rows, err := s.Pool.Query(ctx, `DELETE FROM sessions s USING users u
		WHERE u.id = s.user_id AND (s.expires_at < now() OR ($1 > 0 AND s.last_seen_at < now() - make_interval(secs => $1)))
		RETURNING CASE WHEN s.expires_at < now() THEN 'absolute' ELSE 'idle' END, s.user_id, u.email, COALESCE(s.workspace_id, 0)`, s.SessionIdle.Seconds())
	if err != nil {
		return err
	}
	ended, err := pgx.CollectRows(rows, pgx.RowToStructByPos[SessionExpired])
	if err != nil {
		return err
	}
	for _, e := range ended {
		s.AuditSessionExpired(ctx, &e, "")
	}
	return nil
}

type Token struct {
	ID          int64      `json:"id"`
	WorkspaceID int64      `json:"workspace_id"`
	Name        string     `json:"name"`
	Prefix      string     `json:"prefix"`
	UserID      *int64     `json:"user_id"`
	Role        auth.Role  `json:"role"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
	UserEmail   string     `json:"user_email"`
	// ProjectID: assets this collector token creates are added to this
	// project.
	ProjectID *int64 `json:"project_id"`
	// RepositoryURL: a token exchanged by a CI job (POST /ci/token) may
	// report only the repository with this git-url identity.
	RepositoryURL string `json:"repository_url,omitempty"`
}

const tokenCols = `id, workspace_id, name, prefix, user_id, role, created_at, expires_at, last_used_at, revoked_at,
	COALESCE((SELECT email FROM users u WHERE u.id = api_tokens.user_id), ''), project_id, repository_url`

// CreateToken returns the stored token and its secret, shown once.
func (s *Store) CreateToken(ctx context.Context, name string, role auth.Role, userID *int64, createdBy int64, ttl time.Duration) (*Token, string, error) {
	if !role.ValidToken() {
		return nil, "", fmt.Errorf("invalid role %q", role)
	}
	secret, prefix, err := auth.NewToken("stk")
	if err != nil {
		return nil, "", err
	}
	var expires *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expires = &t
	}
	var by *int64
	if createdBy > 0 {
		by = &createdBy
	}
	rows, err := s.Pool.Query(ctx, `INSERT INTO api_tokens (name, prefix, token_hash, user_id, role, created_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING `+tokenCols, name, prefix, auth.HashToken(secret), userID, role, by, expires)
	if err != nil {
		return nil, "", err
	}
	t, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Token])
	return t, secret, err
}

// TokenPrincipal resolves a bearer token. For user tokens the effective role
// is the lower of the token role and the user's current role.
//
// Tokens belong to one workspace. The lookup spans workspaces, so it runs in
// system scope; the returned user's Role is their role in the token's
// workspace, and a user token stops working when its user leaves it.
func (s *Store) TokenPrincipal(ctx context.Context, secret string) (*Token, *User, error) {
	sys := tenant.System(ctx)
	rows, err := s.Pool.Query(sys, `SELECT `+tokenCols+` FROM api_tokens WHERE token_hash = $1
		AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`, auth.HashToken(secret))
	if err != nil {
		return nil, nil, err
	}
	t, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Token])
	if err != nil {
		return nil, nil, notFound(err)
	}
	if ok, err := s.WorkspaceEnabled(ctx, t.WorkspaceID); err != nil {
		return nil, nil, err
	} else if !ok {
		return nil, nil, ErrNotFound
	}
	_, _ = s.Pool.Exec(sys, `UPDATE api_tokens SET last_used_at = now() WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`, t.ID)
	var u *User
	if t.UserID != nil {
		u, err = s.GetUser(tenant.WithWorkspace(ctx, t.WorkspaceID), *t.UserID)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, nil, err
		}
		if err != nil || u.Disabled {
			return nil, nil, ErrNotFound
		}
		// A member with project access only acts with at most their
		// highest grant; the request is then narrowed to what they may see.
		access, err := s.UserAccess(ctx, t.WorkspaceID, u.ID)
		if err != nil {
			return nil, nil, err
		}
		most := auth.Higher(access.OrgRole, access.ProjectRole)
		if !access.Member || most == "" {
			return nil, nil, ErrNotFound
		}
		if t.Role != auth.RoleCollector && !most.AtLeast(t.Role) {
			t.Role = most
		}
	}
	return t, u, nil
}

func (s *Store) ListTokens(ctx context.Context, userID int64) ([]Token, error) {
	// Short-lived tokens of CI jobs (one per job) are not listed: they are
	// managed through their CI trust.
	sql := `SELECT ` + tokenCols + ` FROM api_tokens WHERE ci_trust_id IS NULL`
	args := []any{}
	if userID > 0 {
		sql += ` AND user_id = $1`
		args = append(args, userID)
	}
	rows, err := s.Pool.Query(ctx, sql+` ORDER BY created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Token])
}

func (s *Store) GetToken(ctx context.Context, id int64) (*Token, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+tokenCols+` FROM api_tokens WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	t, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Token])
	return t, notFound(err)
}

func (s *Store) RevokeToken(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

type Team struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	Email      string    `json:"email"`
	CreatedAt  time.Time `json:"created_at"`
	Members    []int64   `json:"members"`
	AssetCount int64     `json:"asset_count"`
	// Access is what the team's members see through it ("Can see"): its
	// grants, each marked available unless the project is archived or
	// the asset merged. Owning assets (AssetCount) gives no access.
	Access []InvitationGrant `json:"access"`
}

const teamCols = `t.id, t.name, t.email, t.created_at,
	COALESCE((SELECT array_agg(user_id ORDER BY user_id) FROM team_members m WHERE m.team_id = t.id), '{}'),
	(SELECT count(*) FROM assets a WHERE a.owner_team_id = t.id AND a.merged_into IS NULL),
	COALESCE((SELECT json_agg(json_build_object('kind', CASE WHEN g.project_id IS NOT NULL THEN 'project' ELSE 'asset' END,
	    'project_id', g.project_id, 'asset_id', g.asset_id, 'role', g.role, 'name', COALESCE(p.name, a.name, ''),
	    'available', CASE WHEN g.project_id IS NOT NULL THEN p.archived_at IS NULL ELSE a.merged_into IS NULL END,
	    'unavailable', CASE WHEN g.project_id IS NOT NULL AND p.archived_at IS NOT NULL THEN 'archived'
	                        WHEN g.asset_id IS NOT NULL AND a.merged_into IS NOT NULL THEN 'merged' ELSE '' END)
	    ORDER BY g.project_id IS NULL, COALESCE(p.name, a.name))
	  FROM access_grants g LEFT JOIN projects p ON p.id = g.project_id LEFT JOIN assets a ON a.id = g.asset_id
	  WHERE g.team_id = t.id), '[]')`

func (s *Store) ListTeams(ctx context.Context) ([]Team, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+teamCols+` FROM teams t ORDER BY t.name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Team])
}

func (s *Store) CreateTeam(ctx context.Context, name, email string) (*Team, error) {
	var id int64
	err := s.Pool.QueryRow(ctx, `INSERT INTO teams (name, email) VALUES ($1, $2) RETURNING id`, strings.TrimSpace(name), email).Scan(&id)
	if isUniqueViolation(err) {
		return nil, fmt.Errorf("team exists: %w", ErrConflict)
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+teamCols+` FROM teams t WHERE t.id = $1`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Team])
}

func (s *Store) GetTeam(ctx context.Context, id int64) (*Team, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+teamCols+` FROM teams t WHERE t.id = $1`, id)
	if err != nil {
		return nil, err
	}
	t, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Team])
	return t, notFound(err)
}

func (s *Store) UpdateTeam(ctx context.Context, id int64, name, email *string, members *[]int64) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		return updateTeam(ctx, tx, id, name, email, members)
	})
}

func updateTeam(ctx context.Context, tx pgx.Tx, id int64, name, email *string, members *[]int64) error {
	tag, err := tx.Exec(ctx, `UPDATE teams SET name = COALESCE($2, name), email = COALESCE($3, email) WHERE id = $1`, id, name, email)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("team exists: %w", ErrConflict)
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if members != nil {
		if _, err := tx.Exec(ctx, `DELETE FROM team_members WHERE team_id = $1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO team_members (team_id, user_id) SELECT $1, u.id FROM users u WHERE u.id = ANY($2)`, id, *members); err != nil {
			if isForeignKey(err) {
				return fmt.Errorf("team members must be members of this workspace: %w", ErrInvalid)
			}
			return err
		}
	}
	return nil
}

func (s *Store) DeleteTeam(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM teams WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// Actor identifies who performed an audited action.
type Actor struct {
	Type       string // user, token, system
	ID         int64
	Name       string
	RemoteAddr string
}

func (s *Store) Audit(ctx context.Context, a Actor, action, objectType, objectID string, detail any) error {
	d, _ := json.Marshal(detail)
	if detail == nil {
		d = []byte("{}")
	}
	var id *int64
	if a.ID > 0 {
		id = &a.ID
	}
	// Events outside any workspace (sign-in, setup) belong to the platform.
	if _, ok := tenant.Workspace(ctx); !ok {
		ctx = tenant.System(ctx)
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO audit_events (actor_type, actor_id, actor_name, action, object_type, object_id, detail, remote_addr)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, a.Type, id, a.Name, action, objectType, objectID, d, a.RemoteAddr)
	return err
}

// auditTx records an event in tx, in workspace ws (nil: the platform's
// events), so it commits or rolls back with the change it records. tx must
// run in system scope (tenant.System), whose insert policy admits a row of
// any workspace; the insert trigger links it into that workspace's hash
// chain like any other event (migration 0052).
func auditTx(ctx context.Context, tx pgx.Tx, ws *int64, a Actor, action, objectType, objectID string, detail any) error {
	d, _ := json.Marshal(detail)
	if detail == nil {
		d = []byte("{}")
	}
	var id *int64
	if a.ID > 0 {
		id = &a.ID
	}
	_, err := tx.Exec(ctx, `INSERT INTO audit_events (workspace_id, actor_type, actor_id, actor_name, action, object_type, object_id, detail, remote_addr)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, ws, a.Type, id, a.Name, action, objectType, objectID, d, a.RemoteAddr)
	return err
}

type AuditEvent struct {
	ID         int64           `json:"id"`
	At         time.Time       `json:"at"`
	ActorType  string          `json:"actor_type"`
	ActorID    *int64          `json:"actor_id"`
	ActorName  string          `json:"actor_name"`
	Action     string          `json:"action"`
	ObjectType string          `json:"object_type"`
	ObjectID   string          `json:"object_id"`
	Detail     json.RawMessage `json:"detail"`
	RemoteAddr string          `json:"remote_addr"`
}

func (s *Store) ListAudit(ctx context.Context, objectType, objectID string, p Page) ([]AuditEvent, int64, error) {
	w := &where{}
	if objectType != "" {
		w.add("object_type = ?", objectType)
	}
	if objectID != "" {
		w.add("object_id = ?", objectID)
	}
	var total int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events`+w.sql(), w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	p = p.norm()
	rows, err := s.Pool.Query(ctx, `SELECT id, at, actor_type, actor_id, actor_name, action, object_type, object_id, detail, remote_addr
		FROM audit_events`+w.sql()+fmt.Sprintf(` ORDER BY at DESC, id DESC LIMIT %d OFFSET %d`, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[AuditEvent])
	return out, total, err
}

// AuditSessionExpired records a session that ended by itself, in the
// workspace it was working in (the platform's log when none).
func (s *Store) AuditSessionExpired(ctx context.Context, e *SessionExpired, remoteAddr string) {
	if e.Workspace > 0 {
		ctx = tenant.WithWorkspace(ctx, e.Workspace)
	}
	_ = s.Audit(ctx, Actor{Type: "user", ID: e.UserID, Name: e.Email, RemoteAddr: remoteAddr}, "auth.session_expired", "user",
		strconv.FormatInt(e.UserID, 10), map[string]any{"reason": e.Reason})
}
