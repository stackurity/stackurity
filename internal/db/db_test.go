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
