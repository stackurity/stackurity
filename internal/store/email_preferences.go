package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Email preferences for bulk email: the categories a person can unsubscribe
// from, suppressed addresses, and the record of each bulk email (campaign)
// and who it went to. All of it is platform data (system scope); callers
// act for one person, found from their session or a signed link. See
// internal/notify/bulk.go and migration 0056_email_preferences.

// Bulk email categories.
const (
	CategoryMarketing         = "marketing"
	CategoryVulnerabilityNews = "vulnerability_news"
)

// EmailCategories are the categories a person can unsubscribe from, in the
// order they are shown.
var EmailCategories = []string{CategoryMarketing, CategoryVulnerabilityNews}

// ValidEmailCategory reports whether c is a bulk email category.
func ValidEmailCategory(c string) bool {
	return c == CategoryMarketing || c == CategoryVulnerabilityNews
}

// How a preference was changed.
const (
	EmailSourceLink     = "link"     // the preference page opened from an email
	EmailSourceHeader   = "header"   // a mail client's one-click unsubscribe (RFC 8058)
	EmailSourceSettings = "settings" // signed in, Your account
	EmailSourceSupport  = "support"  // an operator, on the person's request
)

// EmailPreference is a person's choice for one category.
type EmailPreference struct {
	Category   string `json:"category"`
	Subscribed bool   `json:"subscribed"`
	// Source and ChangedAt are empty for the default (never changed).
	Source    string     `json:"source,omitempty"`
	ChangedAt *time.Time `json:"changed_at,omitempty"`
}

// EmailPreferences returns a person's choice for every category: subscribed
// unless they unsubscribed (or their address is suppressed).
func (s *Store) EmailPreferences(ctx context.Context, userID int64) ([]EmailPreference, error) {
	ctx = tenant.System(ctx)
	var email string
	if err := s.Pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, userID).Scan(&email); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	out := make([]EmailPreference, 0, len(EmailCategories))
	for _, c := range EmailCategories {
		p := EmailPreference{Category: c, Subscribed: true}
		var sub *bool
		var src *string
		var at *time.Time
		var suppressed bool
		err := s.Pool.QueryRow(ctx, `SELECT p.subscribed, p.source, p.changed_at,
				EXISTS (SELECT 1 FROM email_suppressions x WHERE x.email_hash = $3 AND x.category = $2)
			FROM (SELECT 1) one LEFT JOIN email_preferences p ON p.user_id = $1 AND p.category = $2`,
			userID, c, emailHash(email)).Scan(&sub, &src, &at, &suppressed)
		if err != nil {
			return nil, err
		}
		if sub != nil {
			p.Subscribed, p.Source, p.ChangedAt = *sub, *src, at
		}
		if suppressed {
			p.Subscribed = false
		}
		out = append(out, p)
	}
	return out, nil
}

// SetEmailPreference records a person's choice for one category, at once:
// a send that has not started yet sees it. Unsubscribing also suppresses
// the person's current address for the category; subscribing again lifts
// that. It reports whether anything changed.
func (s *Store) SetEmailPreference(ctx context.Context, userID int64, category string, subscribed bool, source string) (bool, error) {
	if !ValidEmailCategory(category) {
		return false, fmt.Errorf("unknown email category %q: %w", category, ErrInvalid)
	}
	ctx = tenant.System(ctx)
	changed := false
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var email string
		if err := tx.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, userID).Scan(&email); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		h := emailHash(email)
		var was bool
		if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT subscribed FROM email_preferences WHERE user_id = $1 AND category = $2), true)
			AND NOT EXISTS (SELECT 1 FROM email_suppressions WHERE email_hash = $3 AND category = $2)`, userID, category, h).Scan(&was); err != nil {
			return err
		}
		changed = was != subscribed
		if _, err := tx.Exec(ctx, `INSERT INTO email_preferences (user_id, category, subscribed, source) VALUES ($1, $2, $3, $4)
			ON CONFLICT (user_id, category) DO UPDATE SET subscribed = EXCLUDED.subscribed, source = EXCLUDED.source, changed_at = now()
			WHERE email_preferences.subscribed <> EXCLUDED.subscribed`, userID, category, subscribed, source); err != nil {
			return err
		}
		if subscribed {
			_, err := tx.Exec(ctx, `DELETE FROM email_suppressions WHERE email_hash = $1 AND category = $2`, h, category)
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO email_suppressions (email_hash, category, source) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, h, category, source)
		return err
	})
	return changed, err
}

// SuppressEmail unsubscribes an address from categories on its owner's
// request (an operator acting for them): it is suppressed whether or not
// it has an account, and an account with it is unsubscribed. It returns
// whether an account has the address.
func (s *Store) SuppressEmail(ctx context.Context, email string, categories []string, source string) (bool, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	ctx = tenant.System(ctx)
	var userID int64
	err := s.Pool.QueryRow(ctx, `SELECT id FROM users WHERE lower(email) = $1`, email).Scan(&userID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	for _, c := range categories {
		if !ValidEmailCategory(c) {
			return false, fmt.Errorf("unknown email category %q: %w", c, ErrInvalid)
		}
		if userID > 0 {
			if _, err := s.SetEmailPreference(ctx, userID, c, false, source); err != nil {
				return false, err
			}
			continue
		}
		if _, err := s.Pool.Exec(ctx, `INSERT INTO email_suppressions (email_hash, category, source) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			emailHash(email), c, source); err != nil {
			return false, err
		}
	}
	return userID > 0, nil
}

// BulkRecipient is someone a bulk email may go to.
type BulkRecipient struct {
	UserID int64
	Email  string
}

// Why a recipient of a campaign is skipped (email_campaign_sends.reason).
const (
	SkipUnsubscribed = "unsubscribed"
	SkipSuppressed   = "suppressed"
	SkipBlocked      = "blocked" // "never email me again"
	SkipDisabled     = "disabled"
	SkipChanged      = "address_changed"
	SkipGone         = "no_account"
)

// BulkEligible checks, now, whether a category's email may go to a
// recipient: the account exists, is enabled and still has that address,
// the person has not unsubscribed, the address is not suppressed for the
// category and did not ask never to be emailed. It returns "" or the
// reason (Skip*).
func (s *Store) BulkEligible(ctx context.Context, r BulkRecipient, category string) (string, error) {
	return bulkEligible(tenant.System(ctx), s.Pool, r, category)
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func bulkEligible(ctx context.Context, q querier, r BulkRecipient, category string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(r.Email))
	h := emailHash(email)
	var exists, disabled, sameEmail, unsub, suppressed, blocked bool
	err := q.QueryRow(ctx, `SELECT u.id IS NOT NULL, COALESCE(u.disabled, false), COALESCE(lower(u.email) = $2, false),
			EXISTS (SELECT 1 FROM email_preferences p WHERE p.user_id = $1 AND p.category = $3 AND NOT p.subscribed),
			EXISTS (SELECT 1 FROM email_suppressions x WHERE x.email_hash = $4 AND x.category = $3),
			EXISTS (SELECT 1 FROM email_blocks b WHERE b.email_hash = $4)
		FROM (SELECT 1) one LEFT JOIN users u ON u.id = $1`, r.UserID, email, category, h).
		Scan(&exists, &disabled, &sameEmail, &unsub, &suppressed, &blocked)
	if err != nil {
		return "", err
	}
	switch {
	case !exists:
		return SkipGone, nil
	case disabled:
		return SkipDisabled, nil
	case !sameEmail:
		return SkipChanged, nil
	case blocked:
		return SkipBlocked, nil
	case unsub:
		return SkipUnsubscribed, nil
	case suppressed:
		return SkipSuppressed, nil
	}
	return "", nil
}

// Campaign is one bulk email.
type Campaign struct {
	ID       int64
	Key      string
	Category string
	Subject  string
	Message  json.RawMessage
}

// ErrCampaignDiffers: a campaign with this key exists with another
// category, subject or message, so it cannot be continued as this one.
var ErrCampaignDiffers = errors.New("a bulk email with this key was already started with different content; use a new key")

// EnsureCampaign returns the campaign with c's key, creating it the first
// time. Running a campaign again continues it, so the content must match.
func (s *Store) EnsureCampaign(ctx context.Context, c Campaign, createdBy string) (*Campaign, error) {
	ctx = tenant.System(ctx)
	if _, err := s.Pool.Exec(ctx, `INSERT INTO email_campaigns (key, category, subject, message, created_by) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (key) DO NOTHING`, c.Key, c.Category, c.Subject, c.Message, createdBy); err != nil {
		return nil, err
	}
	var got Campaign
	var same bool
	err := s.Pool.QueryRow(ctx, `SELECT id, key, category, subject, message, message = $2::jsonb FROM email_campaigns WHERE key = $1`, c.Key, c.Message).
		Scan(&got.ID, &got.Key, &got.Category, &got.Subject, &got.Message, &same)
	if err != nil {
		return nil, err
	}
	if got.Category != c.Category || got.Subject != c.Subject || !same {
		return nil, ErrCampaignDiffers
	}
	return &got, nil
}

// CampaignByKey returns a campaign, or ErrNotFound.
func (s *Store) CampaignByKey(ctx context.Context, key string) (*Campaign, error) {
	var c Campaign
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT id, key, category, subject, message FROM email_campaigns WHERE key = $1`, key).
		Scan(&c.ID, &c.Key, &c.Category, &c.Subject, &c.Message)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &c, err
}

// Claim results.
const (
	ClaimSend    = "send"    // claimed: send it now, then FinishCampaignSend
	ClaimDone    = "done"    // already sent, being sent or skipped by an earlier run
	ClaimSkipped = "skipped" // not eligible now; recorded with its reason
)

// ClaimCampaignSend decides, just before sending, whether a campaign goes
// to a recipient, and records the decision in one transaction: eligibility
// is checked then (an unsubscribe a moment earlier counts), and a claim is
// taken only by one run, so the email never goes twice. A recipient whose
// earlier send failed, or who was skipped and is eligible now, is claimed
// again. It returns Claim* and, for ClaimSkipped, the reason.
func (s *Store) ClaimCampaignSend(ctx context.Context, campaign int64, r BulkRecipient, category string) (string, string, error) {
	ctx = tenant.System(ctx)
	result, reason := "", ""
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		// One claim per recipient at a time, across replicas and runs.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(format('stackurity-campaign:%s:%s', $1::bigint, $2::bigint), 0))`,
			campaign, r.UserID); err != nil {
			return err
		}
		var status string
		err := tx.QueryRow(ctx, `SELECT status FROM email_campaign_sends WHERE campaign_id = $1 AND user_id = $2`, campaign, r.UserID).Scan(&status)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if status == "sending" || status == "sent" {
			result = ClaimDone
			return nil
		}
		why, err := bulkEligible(ctx, tx, r, category)
		if err != nil {
			return err
		}
		next := "sending"
		result = ClaimSend
		if why != "" {
			next, result, reason = "skipped", ClaimSkipped, why
		}
		_, err = tx.Exec(ctx, `INSERT INTO email_campaign_sends (campaign_id, user_id, status, reason) VALUES ($1, $2, $3, $4)
			ON CONFLICT (campaign_id, user_id) DO UPDATE SET status = EXCLUDED.status, reason = EXCLUDED.reason, updated_at = now()`,
			campaign, r.UserID, next, why)
		return err
	})
	return result, reason, err
}

// FinishCampaignSend records how a claimed send went: sent, or failed
// with the mail server's error (a later run tries it again).
func (s *Store) FinishCampaignSend(ctx context.Context, campaign, userID int64, sendErr error) error {
	status, reason := "sent", ""
	if sendErr != nil {
		status, reason = "failed", sendErr.Error()
		if len(reason) > 500 {
			reason = reason[:500]
		}
	}
	_, err := s.Pool.Exec(tenant.System(ctx), `UPDATE email_campaign_sends SET status = $3, reason = $4, updated_at = now()
		WHERE campaign_id = $1 AND user_id = $2 AND status = 'sending'`, campaign, userID, status, reason)
	return err
}

// CampaignStatus counts a campaign's recipients by status.
func (s *Store) CampaignStatus(ctx context.Context, campaign int64) (map[string]int, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT status, count(*) FROM email_campaign_sends WHERE campaign_id = $1 GROUP BY status`, campaign)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

// CampaignSendStatus is a recipient's status in a campaign ("" when the
// campaign has not reached them).
func (s *Store) CampaignSendStatus(ctx context.Context, campaign, userID int64) (string, error) {
	var st string
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT status FROM email_campaign_sends WHERE campaign_id = $1 AND user_id = $2`, campaign, userID).Scan(&st)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return st, err
}
