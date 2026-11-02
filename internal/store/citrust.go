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

// CITrust lets a CI provider's OpenID Connect tokens for one repository (or
// every repository of one owner) be exchanged for a short-lived collector
// token (POST /ci/token, internal/api/ci_oidc.go).
type CITrust struct {
	ID            int64      `json:"id"`
	WorkspaceID   int64      `json:"workspace_id"`
	Name          string     `json:"name"`
	Provider      string     `json:"provider"`
	Issuer        string     `json:"issuer"`
	Repository    string     `json:"repository"`
	OwnerWildcard bool       `json:"owner_wildcard"`
	Ref           string     `json:"ref"`
	Environment   string     `json:"environment"`
	WorkflowRef   string     `json:"workflow_ref"`
	ProjectID     *int64     `json:"project_id"`
	OwnerID       string     `json:"owner_id"`
	CreatedBy     *int64     `json:"created_by"`
	CreatedByName string     `json:"created_by_name"`
	CreatedAt     time.Time  `json:"created_at"`
	LastUsedAt    *time.Time `json:"last_used_at"`
}

const ciTrustCols = `id, workspace_id, name, provider, issuer, repository, owner_wildcard, ref, environment, workflow_ref,
	project_id, owner_id, created_by, created_by_name, created_at, last_used_at`

// ErrCITrustOwner: the token's owner has the trusted name but not the id
// recorded from the first token accepted under the trust.
var ErrCITrustOwner = errors.New("the repository owner's id differs from the one this CI trust first saw (was the organisation or group deleted and its name taken again?); delete and re-create the trust if this is expected")

// CreateCITrust stores a trust; the caller has validated it.
func (s *Store) CreateCITrust(ctx context.Context, t CITrust) (*CITrust, error) {
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `INSERT INTO ci_trusts (name, provider, issuer, repository, owner_wildcard, ref, environment,
		workflow_ref, project_id, created_by, created_by_name)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11
		WHERE $9::bigint IS NULL OR EXISTS (SELECT 1 FROM projects WHERE id = $9 AND archived_at IS NULL)
		RETURNING `+ciTrustCols,
		t.Name, t.Provider, t.Issuer, t.Repository, t.OwnerWildcard, t.Ref, t.Environment, t.WorkflowRef, t.ProjectID, t.CreatedBy, t.CreatedByName)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[CITrust])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("no such project: %w", ErrInvalid)
	}
	return out, err
}

// ListCITrusts returns the workspace's trusts, newest first.
func (s *Store) ListCITrusts(ctx context.Context) ([]CITrust, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+ciTrustCols+` FROM ci_trusts ORDER BY created_at DESC, id DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[CITrust])
}

// DeleteCITrust removes a trust and, with it, the tokens issued under it.
func (s *Store) DeleteCITrust(ctx context.Context, id int64) (*CITrust, error) {
	rows, err := s.Pool.Query(ctx, `DELETE FROM ci_trusts WHERE id = $1 RETURNING `+ciTrustCols, id)
	if err != nil {
		return nil, err
	}
	t, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[CITrust])
	return t, notFound(err)
}

// CITrustsForIssuer returns every trust, in every workspace, of tokens from
// exactly this issuer. The exchange is not signed in, so it runs in system
// scope; nothing is trusted until the token's signature has been checked.
func (s *Store) CITrustsForIssuer(ctx context.Context, issuer string) ([]CITrust, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT `+ciTrustCols+` FROM ci_trusts t WHERE issuer = $1
		AND EXISTS (SELECT 1 FROM workspaces w WHERE w.id = t.workspace_id AND w.disabled_at IS NULL)
		ORDER BY id LIMIT 1000`, issuer)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[CITrust])
}

// CIToken is what IssueCIToken needs to know about the job.
type CIToken struct {
	Name          string
	RepositoryURL string
	// OwnerID is the id of the owner the trust names, from the token; ""
	// leaves the trust's recorded id unchecked (see pinnedOwnerID in the
	// API).
	OwnerID string
	TTL     time.Duration
}

// IssueCIToken records that trust t accepted a token (pinning the owner's
// id the first time) and issues a collector token in t's workspace and
// project that expires after req.TTL and may report only req.RepositoryURL.
func (s *Store) IssueCIToken(ctx context.Context, t CITrust, req CIToken) (*Token, string, error) {
	ctx = tenant.System(ctx)
	var tok *Token
	var secret string
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var pinned string
		err := tx.QueryRow(ctx, `UPDATE ci_trusts SET owner_id = CASE WHEN owner_id = '' THEN $2 ELSE owner_id END, last_used_at = now()
			WHERE id = $1 RETURNING CASE WHEN $2 = '' THEN '' ELSE owner_id END`, t.ID, req.OwnerID).Scan(&pinned)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound // deleted meanwhile
		}
		if err != nil {
			return err
		}
		if pinned != req.OwnerID {
			return ErrCITrustOwner
		}
		if err := readOnly(ctx, tx, t.WorkspaceID); err != nil {
			return err
		}
		value, prefix, err := auth.NewToken("stk")
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `INSERT INTO api_tokens (name, prefix, token_hash, role, created_by, workspace_id, project_id, expires_at,
			ci_trust_id, repository_url) VALUES ($1,$2,$3,$4,NULL,$5,$6, now() + make_interval(secs => $7), $8, $9) RETURNING `+tokenCols,
			req.Name, prefix, auth.HashToken(value), auth.RoleCollector, t.WorkspaceID, t.ProjectID, req.TTL.Seconds(), t.ID, req.RepositoryURL)
		if err != nil {
			return err
		}
		tok, err = pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Token])
		secret = value
		return err
	})
	if err != nil {
		return nil, "", err
	}
	return tok, secret, nil
}

// PurgeCITokens deletes tokens of CI jobs a day after they expired: there
// is one per job, and an expired one is never accepted again. Scans they
// submitted keep their results (submitted_by is set to NULL).
func (s *Store) PurgeCITokens(ctx context.Context) (int64, error) {
	tag, err := s.Pool.Exec(tenant.System(ctx), `DELETE FROM api_tokens WHERE ci_trust_id IS NOT NULL AND expires_at < now() - interval '1 day'`)
	return tag.RowsAffected(), err
}
