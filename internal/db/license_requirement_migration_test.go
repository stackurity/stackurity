package db_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Migration 0072 records from when the server needs a key: at once on a new
// install, 30 days on for one that already has users or data (an upgrade).
// Ticks add running time by the database's clock, never more than the step
// and never a negative one.
func TestLicenseRequirementMigration(t *testing.T) {
	pool := testdb.New(t)
	s := store.New(pool)
	ctx := context.Background()

	// A new install: no users, no assets.
	from, upgraded, observed, err := s.LicenseRequirement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded || observed != 0 || time.Since(from) < 0 || time.Since(from) > time.Hour {
		t.Errorf("new install: from %v upgraded %v observed %v", from, upgraded, observed)
	}

	// An existing install upgrading: run the migration again with a user.
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
	exec := func(q string) {
		t.Helper()
		if _, err := owner.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := s.CreateUser(tenant.WithWorkspace(ctx, tenant.DefaultWorkspace), "a@x.io", "", auth.RoleAdmin, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	exec(`DROP TABLE license_requirement`)
	exec(`DELETE FROM schema_migrations WHERE name = '0072_license_requirement'`)
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	from, upgraded, _, err = s.LicenseRequirement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if left := time.Until(from); !upgraded || left < 29*24*time.Hour || left > 31*24*time.Hour {
		t.Errorf("upgrade: from %v (in %v) upgraded %v", from, left, upgraded)
	}

	// Ticks: a long gap counts as the step at most; a clock set back, as nothing.
	exec(`UPDATE license_requirement SET last_tick = now() - interval '3 days'`)
	got, err := s.TickLicenseRequirement(ctx, 20*time.Minute)
	if err != nil || got != 20*time.Minute {
		t.Errorf("tick after a long gap: %v %v", got, err)
	}
	exec(`UPDATE license_requirement SET last_tick = now() + interval '1 day'`)
	if got, err := s.TickLicenseRequirement(ctx, 20*time.Minute); err != nil || got != 20*time.Minute {
		t.Errorf("tick with the clock set back: %v %v", got, err)
	}
	exec(`UPDATE license_requirement SET last_tick = now() - interval '10 minutes'`)
	if got, err := s.TickLicenseRequirement(ctx, 20*time.Minute); err != nil || got < 29*time.Minute || got > 31*time.Minute {
		t.Errorf("tick after 10 minutes: %v %v", got, err)
	}
}
