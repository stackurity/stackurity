package db_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/testdb"
)

// A database migrated by a newer version names a migration this binary does
// not have. Migrate must refuse it and change nothing; CheckSchema and the
// running server's guard must report it.
func TestNewerSchemaIsRefused(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()

	var guard db.SchemaGuard
	if err := guard.Check(ctx, pool); err != nil {
		t.Fatalf("a database this version migrated: %v", err)
	}
	if guard.Err() != nil {
		t.Fatal("guard reports a newer schema before there is one")
	}

	const future = "9999_from_a_newer_release"
	if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, future); err != nil {
		t.Fatal(err)
	}
	// Remove a known migration's record too: Migrate must not re-apply it
	// against a newer schema.
	known := db.Known()
	last := known[len(known)-1]
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE name = $1`, last); err != nil {
		t.Fatal(err)
	}

	applied, err := db.Migrate(ctx, pool)
	var ne *db.NewerSchemaError
	if !errors.As(err, &ne) || !errors.Is(err, db.ErrNewerSchema) {
		t.Fatalf("Migrate on a newer schema: applied %v, err %v; want a NewerSchemaError", applied, err)
	}
	if len(applied) != 0 {
		t.Errorf("Migrate applied %v to a newer schema", applied)
	}
	if len(ne.Unknown) != 1 || ne.Unknown[0] != future {
		t.Errorf("unknown migrations = %v, want [%s]", ne.Unknown, future)
	}
	for _, want := range []string{"upgraded by a newer Stackurity", future, "restore the backup"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE name = $1`, last).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("Migrate re-applied a migration against a newer schema")
	}

	if err := db.CheckSchema(ctx, pool); !errors.Is(err, db.ErrNewerSchema) {
		t.Errorf("CheckSchema = %v, want ErrNewerSchema", err)
	}
	if err := guard.Check(ctx, pool); !errors.Is(err, db.ErrNewerSchema) {
		t.Errorf("guard.Check = %v, want ErrNewerSchema", err)
	}
	if !errors.Is(guard.Err(), db.ErrNewerSchema) {
		t.Errorf("guard.Err = %v, want ErrNewerSchema", guard.Err())
	}
}

// The rollback procedure restores the pre-upgrade backup, whose
// schema_migrations has only migrations the previous version knows: an
// older set is never refused.
func TestOlderSchemaIsAccepted(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	known := db.Known()
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE name = $1`, known[len(known)-1]); err != nil {
		t.Fatal(err)
	}
	if err := db.CheckSchema(ctx, pool); err != nil {
		t.Fatalf("CheckSchema on an older schema: %v", err)
	}
}

// A nil guard (no server wiring) reports nothing.
func TestNilSchemaGuard(t *testing.T) {
	var g *db.SchemaGuard
	if g.Err() != nil {
		t.Fatal("nil guard reported an error")
	}
}
