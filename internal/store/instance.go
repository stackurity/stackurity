package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// InstanceValue reads a value every replica shares from instance_state. It
// reports false when the key has never been set. instance_state is a
// platform table, so this always runs in system scope.
func (s *Store) InstanceValue(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT value FROM instance_state WHERE key = $1`, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// SetInstanceValue stores a value every replica shares in instance_state.
func (s *Store) SetInstanceValue(ctx context.Context, key, value string) error {
	_, err := s.Pool.Exec(tenant.System(ctx), `INSERT INTO instance_state (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, key, value)
	return err
}
