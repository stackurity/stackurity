package db_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/testdb"
)

// A restore into a new server brings tables without the application role's
// grants (roles are not in pg_dump). Migrate must grant them again, or the
// application would run without row-level security.
func TestMigrateRestoresAppRoleGrants(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	var schema string
	if err := pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(os.Getenv("STACKURITY_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = schema
	owner, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	granted := func() bool {
		var ok bool
		if err := owner.QueryRow(ctx, `SELECT has_table_privilege('stackurity_app', $1, 'SELECT')`, schema+".assets").Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if _, err := owner.Exec(ctx, `REVOKE ALL ON assets FROM stackurity_app`); err != nil {
		t.Fatal(err)
	}
	if granted() {
		t.Fatal("revoke did not apply")
	}
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if !granted() {
		t.Error("Migrate must grant the application role access to every table again")
	}
}

// Migrate's blanket grants on every start must not give the application
// role back UPDATE or DELETE on the trust badge's append-only history, nor
// the purge function; the purge role keeps its right to run the purge.
func TestMigrateKeepsTrustBadgeHistoryAppendOnly(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	var schema string
	if err := pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	check := func(when string) {
		t.Helper()
		var upd, del, trunc, purgeApp, purgeRole, ins bool
		if err := pool.QueryRow(ctx, `SELECT has_table_privilege('stackurity_app', $1, 'UPDATE'),
			has_table_privilege('stackurity_app', $1, 'DELETE'), has_table_privilege('stackurity_app', $1, 'TRUNCATE'),
			has_function_privilege('stackurity_app', $2, 'EXECUTE'), has_function_privilege('stackurity_purge', $2, 'EXECUTE'),
			has_table_privilege('stackurity_app', $1, 'INSERT')`,
			schema+".trust_badge_status", schema+".trust_badge_status_purge(interval, text)").Scan(&upd, &del, &trunc, &purgeApp, &purgeRole, &ins); err != nil {
			t.Fatal(err)
		}
		if upd || del || trunc || purgeApp || !purgeRole || !ins {
			t.Errorf("%s: app update=%v delete=%v truncate=%v purge=%v insert=%v; purge role purge=%v", when, upd, del, trunc, purgeApp, ins, purgeRole)
		}
	}
	check("after the first migration")
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	check("after a restart")
}
