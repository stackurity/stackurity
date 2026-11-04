package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// PeopleCredentialsRevoked counts what RevokePeopleCredentials ended.
type PeopleCredentialsRevoked struct {
	APITokens            int64 `json:"api_tokens"`
	AssistantConnections int64 `json:"assistant_connections"`
}

// RevokePeopleCredentials revokes, in the workspace tx is scoped to, the
// credentials people hold outside a session: their API tokens and their AI
// assistant connections (with the connections' access tokens and any
// consent not yet exchanged for one). keep is a user whose credentials stay
// (0: none), such as an organisation owner who may still sign in with a
// password.
//
// Credentials of machines stay: collector tokens (agents, including tokens
// bound to one asset) and the short-lived tokens of CI jobs. Those have no
// user; a person's token always has one (CreateToken).
//
// It runs in tx so that the caller can commit it with the change that
// called for it. tx must be scoped to workspace ws (tenant.WithWorkspace);
// row-level security keeps every other workspace out of reach, and each
// statement names ws as well.
func RevokePeopleCredentials(ctx context.Context, tx pgx.Tx, ws, keep int64) (PeopleCredentialsRevoked, error) {
	var out PeopleCredentialsRevoked
	if got, ok := tenant.Workspace(ctx); !ok || got != ws || tenant.Narrowed(ctx) {
		return out, errors.New("revoking people's credentials needs the whole workspace's scope")
	}
	tag, err := tx.Exec(ctx, `UPDATE api_tokens SET revoked_at = now()
		WHERE workspace_id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
		AND user_id IS NOT NULL AND user_id <> $2 AND role <> 'collector' AND ci_trust_id IS NULL`, ws, keep)
	if err != nil {
		return out, err
	}
	out.APITokens = tag.RowsAffected()
	// As RevokeAssistantGrant: the refresh token goes with the connection
	// and its access tokens are deleted, so both stop working at once.
	rows, err := tx.Query(ctx, `UPDATE oauth_grants SET revoked_at = now(), revoked_reason = 'single sign-on required', refresh_hash = NULL
		WHERE workspace_id = $1 AND revoked_at IS NULL AND user_id <> $2 RETURNING id`, ws, keep)
	if err != nil {
		return out, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return out, err
	}
	out.AssistantConnections = int64(len(ids))
	if _, err := tx.Exec(ctx, `DELETE FROM oauth_access_tokens WHERE workspace_id = $1 AND grant_id = ANY($2)`, ws, ids); err != nil {
		return out, err
	}
	// A consent given just before, not yet exchanged: used up, so it
	// cannot make a new connection.
	if _, err := tx.Exec(ctx, `UPDATE oauth_codes SET used_at = now()
		WHERE workspace_id = $1 AND used_at IS NULL AND user_id <> $2`, ws, keep); err != nil {
		return out, err
	}
	return out, nil
}
