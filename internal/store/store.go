// Package store holds all SQL. Handlers and workers call Store methods and
// never build queries themselves.
package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/stackurity/stackurity/internal/tenant"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	ErrInvalid  = errors.New("invalid")
)

type Store struct {
	Pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store { return &Store{Pool: pool} }

// q is satisfied by both the pool and a transaction.
type q interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// asSystem runs fn inside tx with system scope, for writes to shared tables
// (the component catalogue, intelligence) made on behalf of a workspace. The
// workspace id setting is kept, so tenant rows inserted by fn still default to
// the caller's workspace.
func asSystem(ctx context.Context, tx pgx.Tx, fn func() error) error {
	if _, err := tx.Exec(ctx, `SELECT set_config('stackurity.scope', 'system', true)`); err != nil {
		return err
	}
	if err := fn(); err != nil {
		return err
	}
	scope, _ := tenant.Settings(ctx)
	_, err := tx.Exec(ctx, `SELECT set_config('stackurity.scope', $1, true)`, scope)
	return err
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func isUniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// Page is a simple limit/offset page request.
type Page struct {
	Limit  int
	Offset int
}

func (p Page) norm() Page {
	if p.Limit <= 0 || p.Limit > 500 {
		p.Limit = 100
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	return p
}
