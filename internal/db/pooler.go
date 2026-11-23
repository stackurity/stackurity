package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrSessionNotPinned means the server's database connections do not keep
// their PostgreSQL session: a connection pooler in transaction or statement
// mode (PgBouncer pool_mode=transaction, for example) sits between the
// server and PostgreSQL. Stackurity sets its database role and the
// workspace scope once per connection, so behind such a pooler a query can
// run with another request's scope, or none, or as the login role, which
// would break workspace isolation (issues #539 and #540).
var ErrSessionNotPinned = errors.New("the database connections do not keep their PostgreSQL session, as behind a connection pooler " +
	"in transaction or statement mode (PgBouncer pool_mode=transaction). Stackurity sets its database role and the workspace " +
	"scope once per connection, so workspaces would not be isolated. Set the pooler to session mode " +
	"(PgBouncer pool_mode=session), or connect STACKURITY_DATABASE_URL straight to PostgreSQL: Stackurity pools its own connections")

// pinProbeTimeout bounds each statement of the check. A statement that
// waits this long for a plain SELECT is waiting for a server connection
// another client holds: a pooler with no free server connection.
const pinProbeTimeout = 10 * time.Second

// CheckSessionPinned returns ErrSessionNotPinned when a connection of pool
// does not keep its PostgreSQL session from one statement to the next.
//
// It holds one connection and marks its session, then holds a second
// connection in an open transaction, and asks the first again. Connected
// directly, or through a pooler in session mode, a client connection keeps
// its server session: the same backend answers and the mark is still
// there. A pooler in transaction mode gives the second connection's
// transaction a server connection that is free, typically the one the
// first just released (PgBouncer reuses the most recent by default), so
// the first must move: another backend answers, without the mark.
func CheckSessionPinned(ctx context.Context, pool *pgxpool.Pool) error {
	a, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer a.Release()
	b, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer b.Release()

	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	mark := hex.EncodeToString(buf)

	// Simple protocol: no prepared statements, which a pooler in
	// transaction mode may not carry between server connections either.
	const simple = pgx.QueryExecModeSimpleProtocol
	var pid1 int32
	if err := queryTimeout(ctx, func(ctx context.Context) error {
		return a.QueryRow(ctx, `SELECT pg_backend_pid(), set_config('stackurity.session_probe', $1, false)`, simple, mark).Scan(&pid1, new(string))
	}); err != nil {
		return err
	}

	tx, err := b.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var pidB int32
	if err := queryTimeout(ctx, func(ctx context.Context) error {
		return tx.QueryRow(ctx, `SELECT pg_backend_pid()`, simple).Scan(&pidB)
	}); err != nil {
		return err
	}
	if pidB == pid1 {
		// Two client connections on one backend: only a pooler does that.
		return ErrSessionNotPinned
	}

	var pid2 int32
	var got string
	err = queryTimeout(ctx, func(ctx context.Context) error {
		return a.QueryRow(ctx, `SELECT pg_backend_pid(), current_setting('stackurity.session_probe', true)`, simple).Scan(&pid2, &got)
	})
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		// The held connection waited for a server connection that the
		// open transaction holds: a pooler with no free one.
		return fmt.Errorf("%w (a query waited %s for a server connection)", ErrSessionNotPinned, pinProbeTimeout)
	}
	if err != nil {
		return err
	}
	if pid2 != pid1 || got != mark {
		return ErrSessionNotPinned
	}
	return nil
}

func queryTimeout(ctx context.Context, fn func(context.Context) error) error {
	qctx, cancel := context.WithTimeout(ctx, pinProbeTimeout)
	defer cancel()
	return fn(qctx)
}
