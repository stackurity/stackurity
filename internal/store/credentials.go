package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// CredentialItem is one connection, token or stored secret that needs
// attention.
type CredentialItem struct {
	Kind   string     `json:"kind"` // integration, channel, aws, token, secret
	ID     int64      `json:"id,omitempty"`
	Name   string     `json:"name"`
	Detail string     `json:"detail"`
	At     *time.Time `json:"at,omitempty"` // when it expires, last worked, was last used or set
}

// CredentialGroup is a count and the first items of one kind of problem.
type CredentialGroup struct {
	Total int64            `json:"total"`
	Items []CredentialItem `json:"items"`
}

// CredentialHealth is what the Dashboard says about the credentials the
// organisation gave Stackurity (stored secrets, API tokens, connections).
// It never reads a secret's value.
type CredentialHealth struct {
	// Failing: connections whose latest attempt failed; often an expired,
	// revoked or replaced credential.
	Failing CredentialGroup `json:"failing"`
	// Expiring: API tokens that expire within ExpiringDays, or expired
	// within the last ExpiringDays and were not revoked.
	Expiring CredentialGroup `json:"expiring"`
	// Unused: API tokens older than UnusedDays not used for UnusedDays.
	Unused CredentialGroup `json:"unused"`
	// Old: stored secrets whose value was last set more than OldDays ago.
	Old          CredentialGroup `json:"old"`
	ExpiringDays int             `json:"expiring_days"`
	UnusedDays   int             `json:"unused_days"`
	OldDays      int             `json:"old_days"`
}

const (
	credExpiringDays = 14
	credUnusedDays   = 90
	credOldDays      = 365
)

// CredentialHealth summarises the workspace's credentials, at most limit
// items per group. Tokens of CI jobs are left out (they last 15 minutes).
func (s *Store) CredentialHealth(ctx context.Context, limit int) (*CredentialHealth, error) {
	h := &CredentialHealth{ExpiringDays: credExpiringDays, UnusedDays: credUnusedDays, OldDays: credOldDays}
	groups := []struct {
		g   *CredentialGroup
		sql string
		arg any
	}{
		{&h.Failing, `SELECT 'integration', a.id, a.name, a.kind || ': ' || left(a.last_error, 300), a.last_success
			FROM integrations a WHERE a.enabled AND a.last_error <> '' AND a.last_attempt IS NOT NULL
			  AND (a.last_success IS NULL OR a.last_success < a.last_attempt)
			UNION ALL
			SELECT 'channel', c.id, c.name, c.kind || ': ' || left(c.last_error, 300), c.last_ok_at
			FROM channels c WHERE c.enabled AND c.last_error <> ''
			UNION ALL
			SELECT 'aws', w.id, 'AWS ' || COALESCE(NULLIF(w.account_id, ''), 'connection #' || w.id), left(w.last_error, 300), NULL::timestamptz
			FROM aws_connections w WHERE w.status = 'failed'
			ORDER BY 5 NULLS FIRST, 3`, nil},
		{&h.Expiring, `SELECT 'token', t.id, t.name,
			  CASE WHEN t.expires_at <= now() THEN 'expired' ELSE 'expires soon' END, t.expires_at
			FROM api_tokens t WHERE t.ci_trust_id IS NULL AND t.revoked_at IS NULL
			  AND t.expires_at BETWEEN now() - make_interval(days => $1) AND now() + make_interval(days => $1)
			ORDER BY t.expires_at, t.id`, credExpiringDays},
		{&h.Unused, `SELECT 'token', t.id, t.name,
			  CASE WHEN t.last_used_at IS NULL THEN 'never used' ELSE 'not used recently' END, t.last_used_at
			FROM api_tokens t WHERE t.ci_trust_id IS NULL AND t.revoked_at IS NULL
			  AND (t.expires_at IS NULL OR t.expires_at > now())
			  AND t.created_at < now() - make_interval(days => $1)
			  AND (t.last_used_at IS NULL OR t.last_used_at < now() - make_interval(days => $1))
			ORDER BY t.last_used_at NULLS FIRST, t.id`, credUnusedDays},
		{&h.Old, `SELECT 'secret', 0::bigint, s.name, 'not changed for over a year', s.updated_at
			FROM workspace_secrets s WHERE s.updated_at < now() - make_interval(days => $1)
			ORDER BY s.updated_at, s.name`, credOldDays},
	}
	for _, q := range groups {
		var args []any
		if q.arg != nil {
			args = append(args, q.arg)
		}
		rows, err := s.Pool.Query(ctx, q.sql, args...)
		if err != nil {
			return nil, err
		}
		all, err := pgx.CollectRows(rows, pgx.RowToStructByPos[CredentialItem])
		if err != nil {
			return nil, err
		}
		q.g.Total = int64(len(all))
		if len(all) > limit {
			all = all[:limit]
		}
		q.g.Items = append([]CredentialItem{}, all...)
	}
	return h, nil
}
