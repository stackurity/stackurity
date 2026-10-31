package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Two-factor sign-in (migrations 0053 and 0066): passkeys and security keys
// (webauthn.go), a TOTP secret sealed with STACKURITY_SECRET_KEY, email
// codes as a fallback, one-time recovery codes stored hashed, and the
// short-lived challenge between the password and the second factor.
//
// Recovery codes back up the strong factors (passkeys and TOTP): they are
// issued with the first of them and deleted with the last.

// mfaMethodsSQL lists the second factors of the account u.id, strongest
// first.
const mfaMethodsSQL = `ARRAY(SELECT x.m FROM (VALUES
	  ('passkey', EXISTS (SELECT 1 FROM webauthn_credentials c WHERE c.user_id = u.id)),
	  ('totp', EXISTS (SELECT 1 FROM user_mfa m WHERE m.user_id = u.id AND m.enabled_at IS NOT NULL)),
	  ('email', EXISTS (SELECT 1 FROM user_email_mfa e WHERE e.user_id = u.id AND e.enabled_at IS NOT NULL))) x(m, on_)
	WHERE x.on_)`

// strongFactorSQL is true when the account $1 has a passkey or TOTP.
const strongFactorSQL = `(EXISTS (SELECT 1 FROM webauthn_credentials c WHERE c.user_id = $1)
	OR EXISTS (SELECT 1 FROM user_mfa m WHERE m.user_id = $1 AND m.enabled_at IS NOT NULL))`

// MFAState is what an account has set up.
type MFAState struct {
	// Enabled: the account has a second factor (any method).
	Enabled bool `json:"enabled"`
	// EnabledAt is when the authenticator app was confirmed (null: no app).
	EnabledAt *time.Time `json:"enabled_at"`
	// RecoveryLeft counts unused recovery codes (0 without a passkey or app).
	RecoveryLeft int `json:"recovery_codes_left"`
	// Methods lists the second factors: passkey, totp, email.
	Methods []string `json:"methods"`
	// TOTP: an authenticator app is set up.
	TOTP bool `json:"totp"`
	// Email: email codes are on (the fallback).
	Email bool `json:"email"`
}

// MFAStatus reports userID's two-factor set-up.
func (s *Store) MFAStatus(ctx context.Context, userID int64) (MFAState, error) {
	var st MFAState
	err := s.Pool.QueryRow(ctx, `SELECT m.enabled_at,
		(SELECT count(*) FROM mfa_recovery_codes c WHERE c.user_id = $1 AND c.used_at IS NULL), `+mfaMethodsSQL+`
		FROM users u LEFT JOIN user_mfa m ON m.user_id = u.id WHERE u.id = $1`, userID).Scan(&st.EnabledAt, &st.RecoveryLeft, &st.Methods)
	if err != nil {
		return st, notFound(err)
	}
	for _, m := range st.Methods {
		switch m {
		case MFATOTP:
			st.TOTP = true
		case MFAEmail:
			st.Email = true
		}
	}
	if !st.TOTP {
		st.EnabledAt = nil
	}
	st.Enabled = len(st.Methods) > 0
	if !st.TOTP && !slices.Contains(st.Methods, MFAPasskey) {
		st.RecoveryLeft = 0
	}
	return st, nil
}

// MFAMethods lists userID's second factors (passkey, totp, email).
func (s *Store) MFAMethods(ctx context.Context, userID int64) ([]string, error) {
	var ms []string
	err := s.Pool.QueryRow(ctx, `SELECT `+mfaMethodsSQL+` FROM users u WHERE u.id = $1`, userID).Scan(&ms)
	return ms, notFound(err)
}

// HasMFA reports whether userID has a second factor turned on.
func (s *Store) HasMFA(ctx context.Context, userID int64) (bool, error) {
	ms, err := s.MFAMethods(ctx, userID)
	return len(ms) > 0, err
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

// EnableTOTP confirms enrolment with the code's time step. The recovery
// codes' hashes are stored when it is the account's first strong factor
// (issued reports it); otherwise the existing codes stay.
func (s *Store) EnableTOTP(ctx context.Context, userID, step int64, recovery [][]byte) (issued bool, err error) {
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		first, err := firstStrongFactor(ctx, tx, userID)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE user_mfa SET enabled_at = now(), last_step = $2 WHERE user_id = $1 AND enabled_at IS NULL`, userID, step)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("no enrolment in progress: %w", ErrConflict)
		}
		if !first {
			return nil
		}
		issued = true
		return addedStrongFactor(ctx, tx, userID, recovery)
	})
	return issued, err
}

// firstStrongFactor locks userID's row and reports whether the account has
// no passkey or authenticator app yet.
func firstStrongFactor(ctx context.Context, tx pgx.Tx, userID int64) (bool, error) {
	if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, userID); err != nil {
		return false, err
	}
	var has bool
	err := tx.QueryRow(ctx, `SELECT `+strongFactorSQL, userID).Scan(&has)
	return !has, err
}

// addedStrongFactor follows the account's first passkey or authenticator
// app: new recovery codes, and email codes (a fallback for accounts with
// nothing else) end.
func addedStrongFactor(ctx context.Context, tx pgx.Tx, userID int64, recovery [][]byte) error {
	if _, err := tx.Exec(ctx, `DELETE FROM user_email_mfa WHERE user_id = $1`, userID); err != nil {
		return err
	}
	return replaceRecoveryCodes(ctx, tx, userID, recovery)
}

// removedStrongFactor follows the removal of a passkey or the app: when
// none is left, the recovery codes go too.
func removedStrongFactor(ctx context.Context, tx pgx.Tx, userID int64) error {
	_, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1 AND NOT `+strongFactorSQL, userID)
	return err
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
		if err := tx.QueryRow(ctx, `SELECT `+strongFactorSQL, userID).Scan(&on); err != nil {
			return err
		}
		if !on {
			return fmt.Errorf("recovery codes back up a passkey or an authenticator app; set one up first: %w", ErrConflict)
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
		  AND `+strongFactorSQL, userID, hash)
	if err != nil {
		return false, 0, err
	}
	err = s.Pool.QueryRow(ctx, `SELECT count(*) FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`, userID).Scan(&left)
	return tag.RowsAffected() == 1, left, err
}

// DisableMFA removes every second factor of userID (passkeys, the app,
// email codes) with the recovery codes and sign-ins in progress. It
// reports the methods that were on.
func (s *Store) DisableMFA(ctx context.Context, userID int64) ([]string, error) {
	var had []string
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var err error
		had, err = removeAllFactors(ctx, tx, userID)
		return err
	})
	return had, err
}

// removeAllFactors deletes every second factor of userID in tx and returns
// the methods that were on.
func removeAllFactors(ctx context.Context, tx pgx.Tx, userID int64) ([]string, error) {
	var had []string
	if err := tx.QueryRow(ctx, `SELECT `+mfaMethodsSQL+` FROM users u WHERE u.id = $1 FOR UPDATE`, userID).Scan(&had); err != nil {
		return nil, notFound(err)
	}
	for _, q := range []string{`DELETE FROM user_mfa WHERE user_id = $1`, `DELETE FROM webauthn_credentials WHERE user_id = $1`,
		`DELETE FROM user_email_mfa WHERE user_id = $1`, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`,
		`DELETE FROM mfa_challenges WHERE user_id = $1`, `DELETE FROM webauthn_ceremonies WHERE user_id = $1`} {
		if _, err := tx.Exec(ctx, q, userID); err != nil {
			return nil, err
		}
	}
	return had, nil
}

// RemoveTOTP removes userID's authenticator app (confirmed or not). It
// reports whether one was confirmed; the recovery codes go with the last
// strong factor.
func (s *Store) RemoveTOTP(ctx context.Context, userID int64) (bool, error) {
	var had bool
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, userID); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `DELETE FROM user_mfa WHERE user_id = $1 RETURNING enabled_at IS NOT NULL`, userID).Scan(&had)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return removedStrongFactor(ctx, tx, userID)
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

// WorkspaceRequiresMFA reports whether the workspace's two-factor policy
// requires a second factor of anyone.
func (s *Store) WorkspaceRequiresMFA(ctx context.Context, ws int64) (bool, error) {
	p, err := s.MFAPolicyOf(ctx, ws)
	return p.RequiresAny(), err
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

// ResetMemberMFA removes every second factor of a member of the context's
// workspace (passkeys, the app, email codes, recovery codes) and ends their
// sessions, returning their email and the methods removed. Like a
// password, it belongs to the account: only an instance admin may reset it
// for an account in other workspaces too, or for an instance admin.
func (s *Store) ResetMemberMFA(ctx context.Context, id int64, instanceAdmin bool) (email string, removed []string, err error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return "", nil, errNoWorkspace
	}
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
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
		if removed, err = removeAllFactors(ctx, tx, id); err != nil {
			return err
		}
		if len(removed) == 0 {
			return fmt.Errorf("this member has no two-factor sign-in: %w", ErrConflict)
		}
		_, err = tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id)
		return err
	})
	return email, removed, err
}
