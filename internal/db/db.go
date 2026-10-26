// Package db opens the PostgreSQL pool and applies embedded migrations.
package db

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/stackurity/stackurity/internal/tenant"
)

//go:embed migrations/*.sql
var migrations embed.FS

// migrationLock is an arbitrary constant for pg_advisory_lock so concurrent
// server starts do not race.
const migrationLock = 726_354_100

func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	cfg.MaxConns = 20
	Configure(cfg)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var pool *pgxpool.Pool
	// Postgres may still be starting under Compose; retry briefly.
	for {
		pool, err = pgxpool.NewWithConfig(ctx, cfg)
		if err == nil {
			if err = pool.Ping(ctx); err == nil {
				return pool, nil
			}
			pool.Close()
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("connect to database: %w", err)
		case <-time.After(time.Second):
		}
	}
}

// appRole is the role the application switches to on every connection so
// that row-level security applies even when it logs in as a superuser.
const appRole = "stackurity_app"

// Configure installs the hooks that enforce workspace isolation: every new
// connection switches to the application role, and every connection handed
// out carries the scope of the context that asked for it.
func Configure(cfg *pgxpool.Config) {
	var mu sync.Mutex
	current := map[*pgx.Conn]string{}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		var member bool
		err := c.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)
			AND pg_has_role(current_user, (SELECT oid FROM pg_roles WHERE rolname = $1), 'MEMBER')`, appRole).Scan(&member)
		if err != nil || !member {
			return err // before migration 0010, or a managed database: FORCE RLS applies to the owner
		}
		_, err = c.Exec(ctx, "SET ROLE "+appRole)
		return err
	}
	cfg.PrepareConn = func(ctx context.Context, c *pgx.Conn) (bool, error) {
		scope, ws := tenant.Settings(ctx)
		want := scope + "/" + ws
		mu.Lock()
		have, ok := current[c]
		mu.Unlock()
		if ok && have == want {
			return true, nil
		}
		if _, err := c.Exec(ctx, `SELECT set_config('stackurity.scope', $1, false), set_config('stackurity.workspace_id', $2, false)`, scope, ws); err != nil {
			return false, err
		}
		mu.Lock()
		current[c] = want
		mu.Unlock()
		return true, nil
	}
	cfg.BeforeClose = func(c *pgx.Conn) {
		mu.Lock()
		delete(current, c)
		mu.Unlock()
	}
}

// ErrIsolationBypassed means the database role ignores row-level security.
var ErrIsolationBypassed = errors.New("the database role bypasses row-level security (superuser or BYPASSRLS); " +
	"workspaces would not be isolated. Let the migration create the stackurity_app role, or connect as a role without these attributes")

// CheckIsolation returns ErrIsolationBypassed when row-level security would not
// apply to the application's connections.
func CheckIsolation(ctx context.Context, pool *pgxpool.Pool) error {
	var bypass bool
	err := pool.QueryRow(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&bypass)
	if err != nil {
		return err
	}
	if bypass {
		return ErrIsolationBypassed
	}
	return nil
}

// Migrate applies pending migrations in filename order, each in its own
// transaction. It returns the names applied. Migrations run as the login role
// (the table owner), not the application role, on a connection that is
// discarded afterwards; call pool.Reset so that existing connections pick up
// roles a migration created.
func Migrate(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	pc, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	conn := pc.Hijack()
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, `RESET ROLE`); err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLock); err != nil {
		return nil, err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLock)

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	names, err := appliedMigrations(ctx, conn)
	if err != nil {
		return nil, err
	}
	// A database a newer version migrated is left exactly as it is: this
	// version's code may not work with that schema, and migrations are not
	// reversed. The way back is the backup taken before the upgrade.
	if err := newerSchema(names); err != nil {
		return nil, err
	}
	applied := map[string]bool{}
	for _, n := range names {
		applied[n] = true
	}
	var done []string
	for _, name := range Known() {
		if applied[name] {
			continue
		}
		sql, err := migrations.ReadFile("migrations/" + name + ".sql")
		if err != nil {
			return done, err
		}
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, name)
			return err
		})
		if err != nil {
			return done, fmt.Errorf("migration %s: %w", name, err)
		}
		done = append(done, name)
	}
	// Roles live in the cluster, not the database, so pg_dump does not carry
	// them: after a restore into a new server the role and its grants must
	// be created again, or the application would run without row-level
	// security. This repeats migration 0010's step on every start.
	if _, err := conn.Exec(ctx, ensureAppRole); err != nil {
		return done, fmt.Errorf("ensure %s role: %w", appRole, err)
	}
	return done, nil
}

// ensureAppRole creates the application role and grants it access to every
// table, sequence and function. Where the login role may not create roles
// (managed databases) it does nothing, and FORCE ROW LEVEL SECURITY applies
// to the table owner instead.
const ensureAppRole = `DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        BEGIN
            CREATE ROLE stackurity_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
        EXCEPTION
            WHEN duplicate_object OR unique_violation THEN NULL;
            WHEN insufficient_privilege THEN RETURN;
        END;
    END IF;
    IF NOT pg_has_role(current_user, 'stackurity_app', 'MEMBER') THEN
        BEGIN
            EXECUTE format('GRANT stackurity_app TO %I', current_user);
        EXCEPTION WHEN insufficient_privilege THEN RETURN;
        END;
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO stackurity_app', current_schema());
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO stackurity_app', current_schema());
    EXECUTE format('GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA %I TO stackurity_app', current_schema());
    EXECUTE format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA %I TO stackurity_app', current_schema());
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO stackurity_app', current_schema());
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO stackurity_app', current_schema());
END $$`
