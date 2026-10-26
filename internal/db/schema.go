package db

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// NewerSchemaError means the database was migrated by a newer Stackurity:
// schema_migrations names migrations this binary does not have. Migrations
// are not backward compatible, so this version must not run against it.
type NewerSchemaError struct {
	Unknown []string // migration names this binary does not know, sorted
}

func (e *NewerSchemaError) Error() string {
	return fmt.Sprintf("this database was upgraded by a newer Stackurity (migrations this version does not know: %s); "+
		"run that version or restore the backup taken before the upgrade", strings.Join(e.Unknown, ", "))
}

// ErrNewerSchema matches a *NewerSchemaError with errors.Is.
var ErrNewerSchema = errors.New("database schema is newer than this version")

func (e *NewerSchemaError) Is(target error) bool { return target == ErrNewerSchema }

// Known returns the names of the migrations built into this binary, in order.
func Known() []string {
	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		panic(err) // the pattern is constant
	}
	sort.Strings(files)
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = strings.TrimSuffix(strings.TrimPrefix(f, "migrations/"), ".sql")
	}
	return names
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// appliedMigrations reads schema_migrations; a database without the table
// has none.
func appliedMigrations(ctx context.Context, q querier) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT name FROM schema_migrations`)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "42P01" { // undefined_table
			return nil, nil
		}
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// newerSchema returns a *NewerSchemaError when applied names a migration
// this binary does not have.
func newerSchema(applied []string) error {
	known := map[string]bool{}
	for _, n := range Known() {
		known[n] = true
	}
	var unknown []string
	for _, n := range applied {
		if !known[n] {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return &NewerSchemaError{Unknown: unknown}
}

// CheckSchema returns a *NewerSchemaError when the database was migrated by
// a newer version, nil when this version may run against it, or the error
// that kept it from finding out.
func CheckSchema(ctx context.Context, q querier) error {
	applied, err := appliedMigrations(ctx, q)
	if err != nil {
		return err
	}
	return newerSchema(applied)
}

// SchemaGuard remembers whether a running server has found its database
// migrated by a newer version, which happens when a newer replica starts
// during an upgrade while this one still runs. Once found, it stays found:
// the schema is not migrated back down.
type SchemaGuard struct {
	mu  sync.RWMutex
	err error
}

// Check reads the database once. It returns the *NewerSchemaError when the
// schema is newer, and any error that kept it from reading; only the first
// changes what Err reports.
func (g *SchemaGuard) Check(ctx context.Context, q querier) error {
	err := CheckSchema(ctx, q)
	if errors.Is(err, ErrNewerSchema) {
		g.mu.Lock()
		g.err = err
		g.mu.Unlock()
	}
	return err
}

// Err is the *NewerSchemaError once a check has found one, else nil.
func (g *SchemaGuard) Err() error {
	if g == nil {
		return nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.err
}
