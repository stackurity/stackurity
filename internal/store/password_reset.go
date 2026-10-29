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

// Password reset by email (migration 0054) and what a new password ends.

// PasswordResetTTL is how long a reset link works.
const PasswordResetTTL = 15 * time.Minute

// ErrResetInvalid: the link is unknown, used or expired. One error for all
// three, so the answer says nothing more.
var ErrResetInvalid = errors.New("this password reset link is not valid any more; ask for a new one")

// CreatePasswordReset makes a reset link for the enabled account with
// email, replacing its earlier links. It returns "" (and no error) when no
// such account exists, so callers answer the same either way.
func (s *Store) CreatePasswordReset(ctx context.Context, email string) (token string, userID int64, err error) {
	err = s.Pool.QueryRow(ctx, `SELECT id FROM users WHERE email = lower($1) AND NOT disabled`, strings.TrimSpace(email)).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	token, _, err = auth.NewToken("pwr")
	if err != nil {
		return "", 0, err
	}
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM password_resets WHERE user_id = $1`, userID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES ($1, $2, now() + make_interval(secs => $3))`,
			auth.HashToken(token), userID, PasswordResetTTL.Seconds())
		return err
	})
	return token, userID, err
}

// PasswordResetUser resolves a live reset link to its account.
func (s *Store) PasswordResetUser(ctx context.Context, token string) (*User, error) {
	var id int64
	err := s.Pool.QueryRow(ctx, `SELECT r.user_id FROM password_resets r JOIN users u ON u.id = r.user_id
		WHERE r.token_hash = $1 AND r.used_at IS NULL AND r.expires_at > now() AND NOT u.disabled`, auth.HashToken(token)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrResetInvalid
	}
	if err != nil {
		return nil, err
	}
	return s.GetUser(ctx, id)
}

// Revoke says what else a new password ends besides sessions.
type Revoke struct {
	Tokens     bool `json:"tokens"`
	Assistants bool `json:"assistants"`
}

// Revoked counts what a new password ended.
type Revoked struct {
	Sessions   int64 `json:"sessions"`
	Tokens     int64 `json:"tokens"`
	Assistants int64 `json:"assistants"`
}

// ResetPassword sets a new password through a reset link: the link is
// spent, every session of the account ends, and what rv names is revoked
// in every workspace. The account's second factor stays: signing in still
// asks for it.
func (s *Store) ResetPassword(ctx context.Context, token, password string, rv Revoke) (int64, Revoked, error) {
	var out Revoked
	if err := auth.ValidPassword(password); err != nil {
		return 0, out, err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return 0, out, err
	}
	var uid int64
	sys := tenant.System(ctx)
	err = pgx.BeginFunc(sys, s.Pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(sys, `UPDATE password_resets r SET used_at = now() FROM users u
			WHERE r.token_hash = $1 AND r.used_at IS NULL AND r.expires_at > now() AND u.id = r.user_id AND NOT u.disabled
			RETURNING r.user_id`, auth.HashToken(token)).Scan(&uid)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrResetInvalid
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(sys, `UPDATE users SET password_hash = $2, password_change_required = false WHERE id = $1`, uid, hash); err != nil {
			return err
		}
		if _, err := tx.Exec(sys, `DELETE FROM password_resets WHERE user_id = $1 AND used_at IS NULL`, uid); err != nil {
			return err
		}
		out, err = revokeCredentials(sys, tx, uid, "", rv)
		return err
	})
	return uid, out, err
}

// revokeCredentials ends userID's sessions except keep, their sign-ins in
// progress, and what rv names, in every workspace. tx must be in system
// scope.
func revokeCredentials(ctx context.Context, tx pgx.Tx, userID int64, keep string, rv Revoke) (Revoked, error) {
	var out Revoked
	tag, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2`, userID, auth.HashToken(keep))
	if err != nil {
		return out, err
	}
	out.Sessions = tag.RowsAffected()
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_challenges WHERE user_id = $1`, userID); err != nil {
		return out, err
	}
	if rv.Tokens {
		tag, err := tx.Exec(ctx, `UPDATE api_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
		if err != nil {
			return out, err
		}
		out.Tokens = tag.RowsAffected()
	}
	if rv.Assistants {
		rows, err := tx.Query(ctx, `UPDATE oauth_grants SET revoked_at = now(), revoked_reason = 'password changed', refresh_hash = NULL
			WHERE user_id = $1 AND revoked_at IS NULL RETURNING id`, userID)
		if err != nil {
			return out, err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			return out, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM oauth_access_tokens WHERE grant_id = ANY($1)`, ids); err != nil {
			return out, err
		}
		out.Assistants = int64(len(ids))
	}
	return out, nil
}

// ChangePassword verifies the current password, sets the new one, and ends
// every other session of the user (keepSession stays) plus what rv names.
func (s *Store) ChangePassword(ctx context.Context, userID int64, current, next, keepSession string, rv Revoke) (Revoked, error) {
	var out Revoked
	var hash string
	if err := s.Pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1 AND NOT disabled`, userID).Scan(&hash); err != nil {
		return out, notFound(err)
	}
	if !auth.CheckPassword(hash, current) {
		return out, ErrNotFound
	}
	if err := auth.ValidPassword(next); err != nil {
		return out, err
	}
	if current == next {
		return out, fmt.Errorf("the new password must differ from the current one: %w", ErrConflict)
	}
	h, err := auth.HashPassword(next)
	if err != nil {
		return out, err
	}
	sys := tenant.System(ctx)
	err = pgx.BeginFunc(sys, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(sys, `UPDATE users SET password_hash = $2, password_change_required = false WHERE id = $1`, userID, h); err != nil {
			return err
		}
		if _, err := tx.Exec(sys, `DELETE FROM password_resets WHERE user_id = $1`, userID); err != nil {
			return err
		}
		out, err = revokeCredentials(sys, tx, userID, keepSession, rv)
		return err
	})
	return out, err
}

// PurgePasswordResets removes links that expired or were used over a day
// ago.
func (s *Store) PurgePasswordResets(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM password_resets WHERE expires_at < now() - interval '1 day'`)
	return err
}
