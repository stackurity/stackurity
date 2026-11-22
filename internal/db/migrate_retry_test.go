package db_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/testdb"
)

// A replica of the previous version can hold a table lock while a new one
// migrates. A migration that gives up on the lock (lock_timeout, or a
// deadlock) is rolled back by Postgres and must be tried again rather than
// stop the upgrade; the release check from 0.13.8 deadlocked this way on
// migration 0060.
func TestApplyMigrationRetriesLockConflict(t *testing.T) {
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
	connect := func() *pgx.Conn {
		c, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close(context.Background()) })
		return c
	}
	holder, migrator := connect(), connect()
	if _, err := holder.Exec(ctx, `CREATE TABLE retry_probe (id int)`); err != nil {
		t.Fatal(err)
	}

	// The holder keeps the table locked past the first attempt's 200ms
	// lock_timeout and lets go before the retry, a second later.
	tx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE retry_probe IN ACCESS SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	released := make(chan error, 1)
	go func() {
		time.Sleep(600 * time.Millisecond)
		released <- tx.Commit(ctx)
	}()

	name := "9999_retry_probe"
	sql := `SET LOCAL lock_timeout = '200ms'; ALTER TABLE retry_probe ADD COLUMN probe text`
	if err := db.ApplyMigration(ctx, migrator, name, sql); err != nil {
		t.Fatalf("migration that lost one lock wait: %v", err)
	}
	if err := <-released; err != nil {
		t.Fatal(err)
	}
	var recorded bool
	if err := migrator.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, name).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if !recorded {
		t.Error("the retried migration must be recorded once it applies")
	}
	if _, err := migrator.Exec(ctx, `DELETE FROM schema_migrations WHERE name = $1`, name); err != nil {
		t.Fatal(err)
	}

	// Any other error is returned at once, not retried.
	start := time.Now()
	if err := db.ApplyMigration(ctx, migrator, "9999_broken", `SELECT no_such_column FROM retry_probe`); err == nil {
		t.Fatal("a broken migration must fail")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Errorf("a broken migration was retried (took %s)", time.Since(start))
	}
}
