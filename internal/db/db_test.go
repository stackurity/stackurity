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

// A backup restored onto a server that lacked the roles comes back with
// the purge role's grant missing, and the application role then gets every
// table from ensureAppRole's blanket grants. Start-up must protect the
// history again: the purge role runs the purge, the application role may
// not update, delete or purge.
func TestMigrateReprotectsRestoredTrustBadgeHistory(t *testing.T) {
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
	// The state after such a restore and the blanket grants.
	for _, q := range []string{
		`REVOKE ALL ON FUNCTION trust_badge_status_purge(interval, text) FROM stackurity_purge`,
		`REVOKE USAGE ON SCHEMA ` + pgx.Identifier{schema}.Sanitize() + ` FROM stackurity_purge`,
		`GRANT ALL ON trust_badge_status, trust_badge_purges TO stackurity_app`,
		`GRANT EXECUTE ON FUNCTION trust_badge_status_purge(interval, text) TO stackurity_app`,
	} {
		if _, err := owner.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	privs := func() (appUpd, appDel, appPurge, publicPurge, rolePurge bool) {
		// publicPurge: EXECUTE for PUBLIC, which would let any role purge.
		t.Helper()
		if err := owner.QueryRow(ctx, `SELECT has_table_privilege('stackurity_app', 'trust_badge_status', 'UPDATE'),
			has_table_privilege('stackurity_app', 'trust_badge_status', 'DELETE'),
			has_function_privilege('stackurity_app', 'trust_badge_status_purge(interval, text)', 'EXECUTE'),
			EXISTS (SELECT 1 FROM pg_proc p, aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
			  WHERE p.oid = 'trust_badge_status_purge(interval, text)'::regprocedure AND a.grantee = 0 AND a.privilege_type = 'EXECUTE'),
			has_function_privilege('stackurity_purge', 'trust_badge_status_purge(interval, text)', 'EXECUTE')`).Scan(
			&appUpd, &appDel, &appPurge, &publicPurge, &rolePurge); err != nil {
			t.Fatal(err)
		}
		return
	}
	if u, d, p, pub, r := privs(); !u || !d || !p || pub || r {
		t.Fatalf("set-up did not apply: %v %v %v %v %v", u, d, p, pub, r)
	}
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if u, d, p, pub, r := privs(); u || d || p || pub || !r {
		t.Errorf("after start: app update=%v delete=%v purge=%v, public purge=%v, purge role purge=%v", u, d, p, pub, r)
	}
}
