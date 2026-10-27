package db_test

import (
	"context"
	"testing"

	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/testdb"
)

// An edition's own migrations run after the core's, are recorded under
// their set's name, count as known (so the schema guard accepts them) and
// are not applied twice.
func TestRegisteredMigrations(t *testing.T) {
	db.RegisterMigrations("probe", map[string]string{
		"0001_probe": `CREATE FUNCTION probe_answer() RETURNS int LANGUAGE sql AS 'SELECT 42'`,
	})
	known := db.Known()
	if known[len(known)-1] != "probe/0001_probe" {
		t.Fatalf("known migrations end with %v", known[len(known)-3:])
	}
	pool := testdb.New(t)
	ctx := context.Background()
	var n int
	if err := pool.QueryRow(ctx, `SELECT probe_answer()`).Scan(&n); err != nil || n != 42 {
		t.Fatalf("extension migration not applied: %d %v", n, err)
	}
	if applied, err := db.Migrate(ctx, pool); err != nil || len(applied) != 0 {
		t.Errorf("second migrate: %v %v", applied, err)
	}
	if err := db.CheckSchema(ctx, pool); err != nil {
		t.Errorf("schema check: %v", err)
	}
	for _, bad := range []func(){
		func() { db.RegisterMigrations("probe", map[string]string{"0002_again": "SELECT 1"}) },
		func() { db.RegisterMigrations("Bad Name", map[string]string{"0001_x": "SELECT 1"}) },
		func() { db.RegisterMigrations("other", map[string]string{"x": "SELECT 1"}) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("an invalid registration was accepted")
				}
			}()
			bad()
		}()
	}
}
