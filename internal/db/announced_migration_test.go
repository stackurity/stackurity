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

// Migration 0035 moves announced_at back to first_seen for the assets
// migration 0030 marked as announced at upgrade time, so the first summary
// after an upgrade does not list every existing asset as newly connected.
// Assets announced later keep their time.
func TestAnnouncedBackfillMigration(t *testing.T) {
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
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	upgrade := time.Date(2026, 10, 26, 13, 34, 43, 0, time.UTC)
	firstSeen := upgrade.Add(-90 * 24 * time.Hour)
	later := upgrade.Add(26 * time.Hour)
	exec(`UPDATE schema_migrations SET applied_at = $1 WHERE name = '0030_grouped_notifications'`, upgrade)
	exec(`DELETE FROM schema_migrations WHERE name = '0035_announced_backfill'`)
	exec(`INSERT INTO assets (id, workspace_id, kind, name, first_seen, announced_at) VALUES
		(1, 1, 'host', 'existing', $1, $2),
		(2, 1, 'host', 'connected-later', $3, $3),
		(3, 1, 'host', 'not-announced-yet', $3, NULL)`, firstSeen, upgrade, later)

	applied, err := db.Migrate(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0] != "0035_announced_backfill" {
		t.Fatalf("applied %v", applied)
	}

	want := map[int64]*time.Time{1: &firstSeen, 2: &later, 3: nil}
	for id, w := range want {
		var got *time.Time
		if err := owner.QueryRow(ctx, `SELECT announced_at FROM assets WHERE id = $1`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		switch {
		case w == nil && got != nil:
			t.Errorf("asset %d announced_at = %v, want NULL", id, *got)
		case w != nil && (got == nil || !got.Equal(*w)):
			t.Errorf("asset %d announced_at = %v, want %v", id, got, *w)
		}
	}
}
