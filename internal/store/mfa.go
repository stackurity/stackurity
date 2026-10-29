package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Two-factor sign-in (migration 0053): a TOTP secret sealed with
// STACKURITY_SECRET_KEY, one-time recovery codes stored hashed, and the
// short-lived challenge between the password and the code.

// MFAState is what an account has set up.
type MFAState struct {
	Enabled      bool       `json:"enabled"`
	EnabledAt    *time.Time `json:"enabled_at"`
	RecoveryLeft int        `json:"recovery_codes_left"`
}

// MFAStatus reports userID's two-factor set-up.
func (s *Store) MFAStatus(ctx context.Context, userID int64) (MFAState, error) {
	var st MFAState
	err := s.Pool.QueryRow(ctx, `SELECT m.enabled_at,
		(SELECT count(*) FROM mfa_recovery_codes c WHERE c.user_id = $1 AND c.used_at IS NULL)
		FROM users u LEFT JOIN user_mfa m ON m.user_id = u.id WHERE u.id = $1`, userID).Scan(&st.EnabledAt, &st.RecoveryLeft)
	if err != nil {
		return st, notFound(err)
	}
	st.Enabled = st.EnabledAt != nil
	if !st.Enabled {
		st.RecoveryLeft = 0
	}
	return st, nil
}

// HasMFA reports whether userID has a second factor turned on.
func (s *Store) HasMFA(ctx context.Context, userID int64) (bool, error) {
	var ok bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_mfa WHERE user_id = $1 AND enabled_at IS NOT NULL)`, userID).Scan(&ok)
	return ok, err
}

// ErrMFAEnabled: enrolment was started while a second factor is on.
var ErrMFAEnabled = fmt.Errorf("two-factor sign-in is already on; turn it off first: %w", ErrConflict)

// StartTOTPEnrolment stores a new, not yet confirmed, sealed TOTP secret
// for userID, replacing an unconfirmed one.
func (s *Store) StartTOTPEnrolment(ctx context.Context, userID int64, sealed []byte) error {
	tag, err := s.Pool.Exec(ctx, `INSERT INTO user_mfa (user_id, totp_sealed) VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET totp_sealed = EXCLUDED.totp_sealed, created_at = now(), last_step = 0
		WHERE user_mfa.enabled_at IS NULL`, userID, sealed)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrMFAEnabled
	}
	return nil
}

// TOTPSecret returns userID's sealed secret and whether it is confirmed.
func (s *Store) TOTPSecret(ctx context.Context, userID int64) (sealed []byte, enabled bool, err error) {
	var at *time.Time
	err = s.Pool.QueryRow(ctx, `SELECT totp_sealed, enabled_at FROM user_mfa WHERE user_id = $1`, userID).Scan(&sealed, &at)
	return sealed, at != nil, notFound(err)
}

// EnableTOTP confirms enrolment with the code's time step and stores the
// recovery codes' hashes.
func (s *Store) EnableTOTP(ctx context.Context, userID, step int64, recovery [][]byte) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE user_mfa SET enabled_at = now(), last_step = $2 WHERE user_id = $1 AND enabled_at IS NULL`, userID, step)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("no enrolment in progress: %w", ErrConflict)
		}
		return replaceRecoveryCodes(ctx, tx, userID, recovery)
	})
}

func replaceRecoveryCodes(ctx context.Context, tx pgx.Tx, userID int64, hashes [][]byte) error {
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO mfa_recovery_codes (user_id, code_hash) SELECT $1, h FROM unnest($2::bytea[]) h`, userID, hashes)
	return err
}

// ReplaceRecoveryCodes issues a new set, ending the old one.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID int64, hashes [][]byte) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var on bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_mfa WHERE user_id = $1 AND enabled_at IS NOT NULL)`, userID).Scan(&on); err != nil {
			return err
		}
		if !on {
			return fmt.Errorf("two-factor sign-in is off: %w", ErrConflict)
		}
		return replaceRecoveryCodes(ctx, tx, userID, hashes)
	})
}

// UseTOTPStep records step as used, and reports false when a code at or
// after it was already accepted: the same code (or an older one) cannot be
// used twice, even within its 90-second window.
func (s *Store) UseTOTPStep(ctx context.Context, userID, step int64) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE user_mfa SET last_step = $2 WHERE user_id = $1 AND enabled_at IS NOT NULL AND last_step < $2`, userID, step)
	return err == nil && tag.RowsAffected() == 1, err
}

// UseRecoveryCode spends a recovery code. It reports whether the code was
// valid and unused, and how many remain.
func (s *Store) UseRecoveryCode(ctx context.Context, userID int64, hash []byte) (ok bool, left int, err error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE mfa_recovery_codes SET used_at = now()
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
		  AND EXISTS (SELECT 1 FROM user_mfa m WHERE m.user_id = $1 AND m.enabled_at IS NOT NULL)`, userID, hash)
	if err != nil {
		return false, 0, err
	}
	err = s.Pool.QueryRow(ctx, `SELECT count(*) FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`, userID).Scan(&left)
	return tag.RowsAffected() == 1, left, err
}

// DisableMFA removes userID's second factor and recovery codes. It reports
// whether there was one (confirmed or not).
func (s *Store) DisableMFA(ctx context.Context, userID int64) (bool, error) {
	var had bool
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM user_mfa WHERE user_id = $1`, userID)
		if err != nil {
			return err
		}
		had = tag.RowsAffected() > 0
		if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM mfa_challenges WHERE user_id = $1`, userID)
		return err
	})
	return had, err
}

// MFAChallengeTTL is how long the code step of a sign-in may take.
const MFAChallengeTTL = 5 * time.Minute

// CreateMFAChallenge starts the second step of userID's sign-in and returns
// the secret for its cookie.
func (s *Store) CreateMFAChallenge(ctx context.Context, userID int64) (string, error) {
	secret, _, err := auth.NewToken("mfa")
	if err != nil {
		return "", err
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO mfa_challenges (token_hash, user_id, expires_at)
		VALUES ($1, $2, now() + make_interval(secs => $3))`, auth.HashToken(secret), userID, MFAChallengeTTL.Seconds())
	return secret, err
}

// MFAChallengeUser resolves a live challenge to its user.
func (s *Store) MFAChallengeUser(ctx context.Context, secret string) (int64, error) {
	var id int64
	err := s.Pool.QueryRow(ctx, `SELECT c.user_id FROM mfa_challenges c JOIN users u ON u.id = c.user_id
		WHERE c.token_hash = $1 AND c.expires_at > now() AND NOT u.disabled`, auth.HashToken(secret)).Scan(&id)
	return id, notFound(err)
}

// FailMFAChallenge counts a wrong code. Once max are counted the challenge
// is deleted and the person must enter their password again; it returns
// how many tries remain.
func (s *Store) FailMFAChallenge(ctx context.Context, secret string, max int) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `UPDATE mfa_challenges SET failures = failures + 1 WHERE token_hash = $1 RETURNING failures`,
		auth.HashToken(secret)).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if n >= max {
		return 0, s.DeleteMFAChallenge(ctx, secret)
	}
	return max - n, nil
}

func (s *Store) DeleteMFAChallenge(ctx context.Context, secret string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM mfa_challenges WHERE token_hash = $1`, auth.HashToken(secret))
	return err
}

// WorkspaceRequiresMFA reports the workspace's "Require two-factor sign-in"
// setting.
func (s *Store) WorkspaceRequiresMFA(ctx context.Context, ws int64) (bool, error) {
	var on bool
	err := s.Pool.QueryRow(ctx, `SELECT require_mfa FROM workspaces WHERE id = $1`, ws).Scan(&on)
	return on, notFound(err)
}

// SetWorkspaceRequireMFA changes it.
func (s *Store) SetWorkspaceRequireMFA(ctx context.Context, ws int64, on bool) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE workspaces SET require_mfa = $2 WHERE id = $1`, ws, on)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// MembersWithoutMFA counts the workspace's enabled members who have no
// second factor (single sign-on users included: the identity provider
// handles theirs).
func (s *Store) MembersWithoutMFA(ctx context.Context, ws int64) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM workspace_members wm JOIN users u ON u.id = wm.user_id
		WHERE wm.workspace_id = $1 AND NOT u.disabled
		  AND NOT EXISTS (SELECT 1 FROM user_mfa m WHERE m.user_id = u.id AND m.enabled_at IS NOT NULL)`, ws).Scan(&n)
	return n, err
}

// EndSessions signs userID out everywhere except the session keep (empty:
// everywhere). It returns how many sessions ended.
func (s *Store) EndSessions(ctx context.Context, userID int64, keep string) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2`, userID, auth.HashToken(keep))
	return tag.RowsAffected(), err
}

// CheckOwnPassword reports whether password is userID's (re-checked before
// a change to their second factor).
func (s *Store) CheckOwnPassword(ctx context.Context, userID int64, password string) (bool, error) {
	var hash string
	if err := s.Pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1 AND NOT disabled`, userID).Scan(&hash); err != nil {
		return false, notFound(err)
	}
	return auth.CheckPassword(hash, password), nil
}

// CountCredentials counts userID's live API tokens and connected
// assistants in every workspace: they sign in without a second factor.
func (s *Store) CountCredentials(ctx context.Context, userID int64) (tokens, assistants int, err error) {
	err = s.Pool.QueryRow(tenant.System(ctx), `SELECT
		(SELECT count(*) FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())),
		(SELECT count(*) FROM oauth_grants WHERE user_id = $1 AND revoked_at IS NULL AND (refresh_expires_at IS NULL OR refresh_expires_at > now()))`,
		userID).Scan(&tokens, &assistants)
	return tokens, assistants, err
}

// WorkspacesRequiringMFA names userID's workspaces that require two-factor
// sign-in.
func (s *Store) WorkspacesRequiringMFA(ctx context.Context, userID int64) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT w.name FROM workspace_members wm JOIN workspaces w ON w.id = wm.workspace_id
		WHERE wm.user_id = $1 AND w.require_mfa AND w.disabled_at IS NULL ORDER BY w.name`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// ResetMemberMFA removes the second factor of a member of the context's
// workspace and ends their sessions, returning their email. Like a
// password, it belongs to the account: only an instance admin may reset it
// for an account in other workspaces too, or for an instance admin.
func (s *Store) ResetMemberMFA(ctx context.Context, id int64, instanceAdmin bool) (string, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return "", errNoWorkspace
	}
	var email string
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var others int64
		err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE workspace_id <> $2) FROM workspace_members
			WHERE user_id = $1 HAVING bool_or(workspace_id = $2)`, id, ws).Scan(&others)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var targetInstanceAdmin bool
		if err := tx.QueryRow(ctx, `SELECT email, instance_admin FROM users WHERE id = $1`, id).Scan(&email, &targetInstanceAdmin); err != nil {
			return notFound(err)
		}
		if !instanceAdmin && others > 0 {
			return fmt.Errorf("this account also belongs to other workspaces; only an instance admin can reset its two-factor sign-in: %w", ErrConflict)
		}
		if !instanceAdmin && targetInstanceAdmin {
			return fmt.Errorf("this account is an instance admin; only an instance admin can reset its two-factor sign-in: %w", ErrConflict)
		}
		tag, err := tx.Exec(ctx, `DELETE FROM user_mfa WHERE user_id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("this member has no two-factor sign-in: %w", ErrConflict)
		}
		for _, q := range []string{`DELETE FROM mfa_recovery_codes WHERE user_id = $1`, `DELETE FROM mfa_challenges WHERE user_id = $1`,
			`DELETE FROM sessions WHERE user_id = $1`} {
			if _, err := tx.Exec(ctx, q, id); err != nil {
				return err
			}
		}
		return nil
	})
	return email, err
}
