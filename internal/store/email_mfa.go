package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
)

// Email codes, the fallback second factor (migration 0066): six digits sent
// by the transactional mail, valid for ten minutes, used once. A person
// turns them on themselves (confirmed with a code), only while they have no
// passkey or authenticator app; adding either turns them off.
//
// Only a hash of each code is stored, bound to what the code is for: the
// sign-in's challenge secret, or the session confirming it, so a code is
// worthless without the cookie that asked for it.

// EmailCodeTTL is how long an email code works.
const EmailCodeTTL = 10 * time.Minute

// NewEmailCode returns six random digits.
func NewEmailCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// EmailCodeHash binds a code to the secret it was sent for.
func EmailCodeHash(secret, code string) []byte {
	h := sha256.Sum256([]byte("stackurity-email-code\x00" + secret + "\x00" + code))
	return h[:]
}

// ErrEmailCodeTooSoon: a code was sent moments ago, or too many were sent
// for this sign-in.
var ErrEmailCodeTooSoon = fmt.Errorf("a code was sent moments ago; wait a little before asking for another: %w", ErrConflict)

// SendLimits bounds codes sent for one sign-in or confirmation.
type SendLimits struct {
	Gap time.Duration // between two codes
	Max int           // codes in all
}

// SetChallengeEmailCode stores a new code (its hash) for a sign-in's
// challenge, replacing an earlier one, and keeps the challenge alive for
// the code's ten minutes.
func (s *Store) SetChallengeEmailCode(ctx context.Context, challenge string, hash []byte, lim SendLimits) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE mfa_challenges SET email_code_hash = $2, email_code_expires_at = now() + make_interval(secs => $3),
		expires_at = GREATEST(expires_at, now() + make_interval(secs => $3)), email_sends = email_sends + 1, email_sent_at = now()
		WHERE token_hash = $1 AND expires_at > now() AND email_sends < $4
		  AND (email_sent_at IS NULL OR email_sent_at < now() - make_interval(secs => $5))`,
		auth.HashToken(challenge), hash, EmailCodeTTL.Seconds(), lim.Max, lim.Gap.Seconds())
	if err == nil && tag.RowsAffected() == 0 {
		return ErrEmailCodeTooSoon
	}
	return err
}

// UseChallengeEmailCode spends the sign-in's email code if hash is it and
// it is still valid; a code works once.
func (s *Store) UseChallengeEmailCode(ctx context.Context, challenge string, hash []byte) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE mfa_challenges SET email_code_hash = NULL, email_code_expires_at = NULL
		WHERE token_hash = $1 AND email_code_hash = $2 AND email_code_expires_at > now()`, auth.HashToken(challenge), hash)
	return err == nil && tag.RowsAffected() == 1, err
}

// HasEmailMFA reports whether userID has email codes on.
func (s *Store) HasEmailMFA(ctx context.Context, userID int64) (bool, error) {
	var on bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_email_mfa WHERE user_id = $1 AND enabled_at IS NOT NULL)`, userID).Scan(&on)
	return on, err
}

// SetAccountEmailCode stores a code for userID outside a sign-in: to turn
// email codes on (a pending row is made when there is none), or to confirm
// a session with them. It refuses an account with a passkey or the app.
func (s *Store) SetAccountEmailCode(ctx context.Context, userID int64, hash []byte, lim SendLimits) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, userID); err != nil {
			return err
		}
		var strong bool
		if err := tx.QueryRow(ctx, `SELECT `+strongFactorSQL, userID).Scan(&strong); err != nil {
			return err
		}
		if strong {
			return fmt.Errorf("email codes are only for accounts with no passkey or authenticator app: %w", ErrConflict)
		}
		var sentAt *time.Time
		err := tx.QueryRow(ctx, `SELECT code_expires_at - make_interval(secs => $2) FROM user_email_mfa WHERE user_id = $1`,
			userID, EmailCodeTTL.Seconds()).Scan(&sentAt)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			_, err = tx.Exec(ctx, `INSERT INTO user_email_mfa (user_id) VALUES ($1)`, userID)
			if err != nil {
				return err
			}
		case err != nil:
			return err
		case sentAt != nil && time.Since(*sentAt) < lim.Gap:
			return ErrEmailCodeTooSoon
		}
		_, err = tx.Exec(ctx, `UPDATE user_email_mfa SET code_hash = $2, code_expires_at = now() + make_interval(secs => $3), failures = 0
			WHERE user_id = $1`, userID, hash, EmailCodeTTL.Seconds())
		return err
	})
}

// UseAccountEmailCode checks a code SetAccountEmailCode stored. A right
// code is spent, and turns email codes on when enable is set; a wrong one
// counts, and after maxFailures the code is spent too. It reports whether
// the code was right and whether email codes were just turned on.
func (s *Store) UseAccountEmailCode(ctx context.Context, userID int64, hash []byte, enable bool, maxFailures int) (ok, enabled bool, err error) {
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var stored []byte
		var expires *time.Time
		var on bool
		var failures int
		err := tx.QueryRow(ctx, `SELECT code_hash, code_expires_at, enabled_at IS NOT NULL, failures FROM user_email_mfa WHERE user_id = $1 FOR UPDATE`, userID).
			Scan(&stored, &expires, &on, &failures)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if stored == nil || expires == nil || time.Now().After(*expires) || (!enable && !on) {
			return nil
		}
		if subtle.ConstantTimeCompare(stored, hash) != 1 {
			failures++
			if failures >= maxFailures {
				_, err = tx.Exec(ctx, `UPDATE user_email_mfa SET code_hash = NULL, code_expires_at = NULL, failures = 0 WHERE user_id = $1`, userID)
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE user_email_mfa SET failures = $2 WHERE user_id = $1`, userID, failures)
			return err
		}
		ok = true
		if enable && !on {
			var strong bool
			if err := tx.QueryRow(ctx, `SELECT `+strongFactorSQL, userID).Scan(&strong); err != nil {
				return err
			}
			if strong {
				return fmt.Errorf("email codes are only for accounts with no passkey or authenticator app: %w", ErrConflict)
			}
			enabled = true
		}
		_, err = tx.Exec(ctx, `UPDATE user_email_mfa SET code_hash = NULL, code_expires_at = NULL, failures = 0,
			enabled_at = CASE WHEN $2 THEN COALESCE(enabled_at, now()) ELSE enabled_at END WHERE user_id = $1`, userID, enable)
		return err
	})
	return ok, enabled, err
}

// RemoveEmailMFA turns userID's email codes off, unless floor refuses. It
// reports whether they were on.
func (s *Store) RemoveEmailMFA(ctx context.Context, userID int64, floor MFAFloor) (bool, error) {
	var had bool
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, userID); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `DELETE FROM user_email_mfa WHERE user_id = $1 RETURNING enabled_at IS NOT NULL`, userID).Scan(&had)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return checkFloor(ctx, tx, userID, floor)
	})
	return had, err
}
