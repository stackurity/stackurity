package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Email sent by Stackurity (channel kind stackurity_email, hosted
// installations): confirmation of addresses that are not members, and the
// organisation's email limits. See internal/notify/platform_email.go.

// EmailConfirmTTL is how long a confirmation link works.
const EmailConfirmTTL = 7 * 24 * time.Hour

// emailResendAfter is how soon a confirmation may be sent again to one
// address.
const emailResendAfter = 10 * time.Minute

// ErrEmailConfirmInvalid hides whether a confirmation token is unknown,
// used or expired.
var ErrEmailConfirmInvalid = errors.New("this link is not valid any more; ask the person who added you to send a new one")

// ErrTooSoon: a confirmation was sent to this address a few minutes ago.
var ErrTooSoon = errors.New("a confirmation was sent to this address a few minutes ago")

// EmailRecipient is an address outside the organisation's members that
// email sent by Stackurity may go to once it has confirmed.
type EmailRecipient struct {
	Email       string     `json:"email"`
	Status      string     `json:"status"` // pending or confirmed
	RequestedAt time.Time  `json:"requested_at"`
	ConfirmedAt *time.Time `json:"confirmed_at"`
}

func newEmailToken() (token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	token = "emc_" + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

// RequestEmailConfirmations records addresses of the context's workspace
// that must confirm, and returns a fresh token for each that is not
// confirmed and was not asked in the last few minutes (or ever), to email
// it. Addresses are lower-cased.
func (s *Store) RequestEmailConfirmations(ctx context.Context, emails []string, by int64) (map[string]string, error) {
	out := map[string]string{}
	var requester *int64
	if by > 0 {
		requester = &by
	}
	for _, e := range emails {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || out[e] != "" {
			continue
		}
		token, hash, err := newEmailToken()
		if err != nil {
			return nil, err
		}
		tag, err := s.Pool.Exec(ctx, `INSERT INTO email_recipients AS r (email, token_hash, requested_by, requested_at, expires_at)
			VALUES ($1, $2, $3, now(), now() + make_interval(secs => $4))
			ON CONFLICT (workspace_id, email) DO UPDATE SET token_hash = EXCLUDED.token_hash, requested_by = EXCLUDED.requested_by,
				requested_at = now(), expires_at = EXCLUDED.expires_at
			WHERE r.confirmed_at IS NULL AND r.requested_at < now() - make_interval(secs => $5)`,
			e, hash, requester, EmailConfirmTTL.Seconds(), emailResendAfter.Seconds())
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 1 {
			out[e] = token
		}
	}
	return out, nil
}

// ResendEmailConfirmation returns a new token for a pending address of the
// context's workspace: ErrNotFound when it is unknown or already
// confirmed, ErrTooSoon when one was sent a few minutes ago.
func (s *Store) ResendEmailConfirmation(ctx context.Context, email string, by int64) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var confirmed bool
	err := s.Pool.QueryRow(ctx, `SELECT confirmed_at IS NOT NULL FROM email_recipients WHERE email = $1`, email).Scan(&confirmed)
	if errors.Is(err, pgx.ErrNoRows) || confirmed {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	tokens, err := s.RequestEmailConfirmations(ctx, []string{email}, by)
	if err != nil {
		return "", err
	}
	if tokens[email] == "" {
		return "", ErrTooSoon
	}
	return tokens[email], nil
}

// ListEmailRecipients lists the context's workspace's addresses.
func (s *Store) ListEmailRecipients(ctx context.Context) ([]EmailRecipient, error) {
	rows, err := s.Pool.Query(ctx, `SELECT email, CASE WHEN confirmed_at IS NULL THEN 'pending' ELSE 'confirmed' END, requested_at, confirmed_at
		FROM email_recipients ORDER BY email`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[EmailRecipient])
}

// ConfirmedEmails returns which of emails may receive email sent by
// Stackurity in the context's workspace: confirmed addresses, and the
// addresses of its enabled members.
func (s *Store) ConfirmedEmails(ctx context.Context, emails []string) (map[string]bool, error) {
	lower := make([]string, len(emails))
	for i, e := range emails {
		lower[i] = strings.ToLower(strings.TrimSpace(e))
	}
	rows, err := s.Pool.Query(ctx, `SELECT email FROM email_recipients WHERE email = ANY($1) AND confirmed_at IS NOT NULL
		UNION SELECT lower(u.email) FROM users u WHERE lower(u.email) = ANY($1) AND NOT u.disabled
		  AND EXISTS (SELECT 1 FROM workspace_members wm WHERE wm.user_id = u.id AND wm.workspace_id = stackurity_ws())`, lower)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, pgx.RowTo[string])
	out := map[string]bool{}
	for _, e := range list {
		out[e] = true
	}
	return out, err
}

// ConfirmEmail confirms the address a token was sent to, in whichever
// workspace it belongs to (the link is opened by someone who may have no
// account), and returns the address and the organisation's name. The
// token works once.
func (s *Store) ConfirmEmail(ctx context.Context, token string) (email, organisation string, err error) {
	sum := sha256.Sum256([]byte(token))
	err = s.Pool.QueryRow(tenant.System(ctx), `UPDATE email_recipients r SET confirmed_at = now(), token_hash = NULL
		FROM workspaces w
		WHERE r.token_hash = $1 AND r.confirmed_at IS NULL AND r.expires_at > now() AND w.id = r.workspace_id AND w.disabled_at IS NULL
		RETURNING r.email, w.name`, sum[:]).Scan(&email, &organisation)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrEmailConfirmInvalid
	}
	return email, organisation, err
}

// MemberEmails returns the addresses of the given members of the context's
// workspace that are enabled (others are left out).
func (s *Store) MemberEmails(ctx context.Context, ids []int64) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := s.Pool.Query(ctx, `SELECT lower(u.email) FROM users u
		WHERE u.id = ANY($1) AND NOT u.disabled
		  AND EXISTS (SELECT 1 FROM workspace_members wm WHERE wm.user_id = u.id AND wm.workspace_id = stackurity_ws())
		ORDER BY u.email`, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// EmailLimits are an organisation's limits on email sent by Stackurity,
// counted in emails (one per recipient). Zero means no limit.
type EmailLimits struct {
	PerMinute int `json:"per_minute"`
	PerHour   int `json:"per_hour"`
	PerDay    int `json:"per_day"`
}

// EmailOverLimit says which limit a send would pass and when it frees.
type EmailOverLimit struct {
	Limit string // minute, hour or day
	Until time.Time
}

func (e *EmailOverLimit) Error() string {
	return fmt.Sprintf("the organisation's email limit per %s is reached", e.Limit)
}

// ReserveEmails counts n emails against the context's workspace's limits
// before they are sent and returns the reservation, or an *EmailOverLimit
// when they would pass a limit. Reservations of one workspace are taken one
// at a time (a transaction-scoped advisory lock), so replicas sending at
// once never pass a limit together. ReleaseEmails gives one back.
func (s *Store) ReserveEmails(ctx context.Context, n int, l EmailLimits) (int64, error) {
	if n <= 0 {
		return 0, nil
	}
	var id int64
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('stackurity-email-quota'), stackurity_ws()::int)`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM email_sends WHERE sent_at < now() - interval '1 day 1 hour'`); err != nil {
			return err
		}
		var now time.Time
		var minute, hour, day int
		var oldestMinute, oldestHour, oldestDay *time.Time
		if err := tx.QueryRow(ctx, `SELECT now(),
			COALESCE(sum(emails) FILTER (WHERE sent_at > now() - interval '1 minute'), 0),
			COALESCE(sum(emails) FILTER (WHERE sent_at > now() - interval '1 hour'), 0),
			COALESCE(sum(emails), 0),
			min(sent_at) FILTER (WHERE sent_at > now() - interval '1 minute'),
			min(sent_at) FILTER (WHERE sent_at > now() - interval '1 hour'),
			min(sent_at)
			FROM email_sends WHERE sent_at > now() - interval '1 day'`).Scan(&now, &minute, &hour, &day, &oldestMinute, &oldestHour, &oldestDay); err != nil {
			return err
		}
		over := func(limit, used int) bool { return limit > 0 && used+n > limit }
		// A single send larger than a limit would never pass it: it goes
		// when nothing else was sent in the window.
		switch {
		case over(l.PerDay, day) && day > 0:
			return &EmailOverLimit{Limit: "day", Until: later(oldestDay, now).Add(24 * time.Hour)}
		case over(l.PerHour, hour) && hour > 0:
			return &EmailOverLimit{Limit: "hour", Until: later(oldestHour, now).Add(time.Hour)}
		case over(l.PerMinute, minute) && minute > 0:
			return &EmailOverLimit{Limit: "minute", Until: later(oldestMinute, now).Add(time.Minute)}
		}
		return tx.QueryRow(ctx, `INSERT INTO email_sends (emails) VALUES ($1) RETURNING id`, n).Scan(&id)
	})
	return id, err
}

func later(t *time.Time, now time.Time) time.Time {
	if t == nil {
		return now
	}
	return *t
}

// ReleaseEmails gives back a reservation whose send failed.
func (s *Store) ReleaseEmails(ctx context.Context, id int64) error {
	if id == 0 {
		return nil
	}
	_, err := s.Pool.Exec(ctx, `DELETE FROM email_sends WHERE id = $1`, id)
	return err
}

// EmailUsage is what the context's workspace sent in the last minute, hour
// and day.
func (s *Store) EmailUsage(ctx context.Context) (EmailLimits, error) {
	var u EmailLimits
	err := s.Pool.QueryRow(ctx, `SELECT
		COALESCE(sum(emails) FILTER (WHERE sent_at > now() - interval '1 minute'), 0),
		COALESCE(sum(emails) FILTER (WHERE sent_at > now() - interval '1 hour'), 0),
		COALESCE(sum(emails), 0)
		FROM email_sends WHERE sent_at > now() - interval '1 day'`).Scan(&u.PerMinute, &u.PerHour, &u.PerDay)
	return u, err
}

// Why a delivery was held (deliveries.held_by).
const (
	HeldHourlyLimit = "hourly_limit"
	HeldEmailQuota  = "email_quota"
)

// HoldDeliveryBy keeps a due delivery for the next summary or digest,
// recording why. It does nothing to a delivery another replica has claimed.
func (s *Store) HoldDeliveryBy(ctx context.Context, id int64, by, reason string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE deliveries SET status = 'held', held_by = $3, last_error = $2
		WHERE id = $1 AND status = 'pending' AND next_attempt <= now()`, id, reason, by)
	return err
}

// EmailQuotaHeld is, across workspaces, how many messages the email limits
// held in the last day and in how many organisations (Platform health).
func (s *Store) EmailQuotaHeld(ctx context.Context) (messages, workspaces int, err error) {
	err = s.Pool.QueryRow(tenant.System(ctx), `SELECT count(*), count(DISTINCT workspace_id) FROM deliveries
		WHERE held_by = 'email_quota' AND created_at > now() - interval '1 day'`).Scan(&messages, &workspaces)
	return messages, workspaces, err
}
