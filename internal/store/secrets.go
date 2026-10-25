package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// SecretInfo describes a stored secret; the value is never returned.
type SecretInfo struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Sealer encrypts and decrypts stored secrets (secrets.Box).
type Sealer interface {
	Seal(workspace int64, name, value string) ([]byte, error)
	Open(workspace int64, name string, sealed []byte) (string, error)
}

func (s *Store) ListSecrets(ctx context.Context) ([]SecretInfo, error) {
	rows, err := s.Pool.Query(ctx, `SELECT name, created_at, updated_at FROM workspace_secrets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[SecretInfo])
}

// PutSecret stores or replaces a secret in the context's workspace.
func (s *Store) PutSecret(ctx context.Context, box Sealer, name, value string, by int64) error {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return errNoWorkspace
	}
	sealed, err := box.Seal(ws, name, value)
	if err != nil {
		return err
	}
	var creator *int64
	if by > 0 {
		creator = &by
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO workspace_secrets (name, sealed, created_by) VALUES ($1, $2, $3)
		ON CONFLICT (workspace_id, name) DO UPDATE SET sealed = EXCLUDED.sealed, updated_at = now()`, name, sealed, creator)
	return err
}

// SecretValue decrypts a secret of the context's workspace.
func (s *Store) SecretValue(ctx context.Context, box Sealer, name string) (string, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return "", errNoWorkspace
	}
	var sealed []byte
	if err := s.Pool.QueryRow(ctx, `SELECT sealed FROM workspace_secrets WHERE name = $1`, name).Scan(&sealed); err != nil {
		return "", notFound(err)
	}
	return box.Open(ws, name, sealed)
}

func (s *Store) DeleteSecret(ctx context.Context, name string) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM workspace_secrets WHERE name = $1`, name)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
