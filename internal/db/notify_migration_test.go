package db_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Migration 0030 maps routes and queued messages of the per-incident
// design to grouped notifications: every route becomes "urgent right away
// + daily summary" with its filters kept, an escalation route keeps its
// flag (now: the overdue section and daily overdue alert), existing assets
// count as announced, and per-incident messages still queued for people
// are held for the next summary. Jira deliveries are left alone.
func TestGroupedNotificationsMigration(t *testing.T) {
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
	// Back to the schema before 0030, with data as 0.5.1 left it.
	exec(`ALTER TABLE routes DROP COLUMN mode, DROP COLUMN summary_time, DROP COLUMN summary_day, DROP COLUMN last_summary_at`)
	exec(`ALTER TABLE routes ALTER COLUMN min_priority SET DEFAULT 'P2'`)
	exec(`ALTER TABLE assets DROP COLUMN announced_at`)
	exec(`DROP INDEX findings_resolved_in_group`)
	exec(`ALTER TABLE findings DROP COLUMN resolved_fix_group, DROP COLUMN resolved_fix_title`)
	exec(`DELETE FROM schema_migrations WHERE name = '0030_grouped_notifications'`)

	exec(`INSERT INTO channels (id, workspace_id, kind, name, config, secret_ref) VALUES
		(1, 1, 'slack', 'alerts', '{}', 'env:X'), (2, 1, 'jira', 'issues', '{}', 'env:Y')`)
	exec(`INSERT INTO routes (id, workspace_id, name, channel_id, min_priority, escalation, send_resolved, quiet_start, quiet_end, timezone, max_per_hour) VALUES
		(1, 1, 'main', 1, 'P2', false, true, '22:00', '07:00', 'Asia/Kolkata', 20),
		(2, 1, 'escalations', 1, 'P4', true, false, '', '', 'UTC', 20),
		(3, 1, 'jira', 2, 'P1', false, true, '', '', 'UTC', 0)`)
	exec(`INSERT INTO assets (id, workspace_id, kind, name) VALUES (1, 1, 'host', 'commmerceblog')`)
	exec(`INSERT INTO deliveries (id, workspace_id, channel_id, route_id, event, dedupe_key, payload, status) VALUES
		(1, 1, 1, 1, 'opened', 'a', '{}', 'pending'),
		(2, 1, 1, 2, 'escalated', 'b', '{}', 'pending'),
		(3, 1, 1, 1, 'opened', 'c', '{}', 'sent'),
		(4, 1, 2, 3, 'opened', 'd', '{}', 'pending'),
		(5, 1, 1, NULL, 'digest', 'e', '{}', 'pending'),
		(6, 1, 1, 1, 'opened', 'f', '{}', 'held')`)

	applied, err := db.Migrate(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0] != "0030_grouped_notifications" {
		t.Fatalf("applied %v", applied)
	}

	type route struct {
		mode, at, day, minPri, tz, quiet string
		esc, resolved                    bool
	}
	want := map[string]route{
		"main":        {"urgent_summary", "09:00", "monday", "P2", "Asia/Kolkata", "22:00", false, true},
		"escalations": {"urgent_summary", "09:00", "monday", "P4", "UTC", "", true, false},
		"jira":        {"urgent_summary", "09:00", "monday", "P1", "UTC", "", false, true},
	}
	rows, err := owner.Query(ctx, `SELECT name, mode, summary_time, summary_day, min_priority, timezone, quiet_start, escalation, send_resolved,
		last_summary_at IS NOT NULL FROM routes`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name string
		var got route
		var hasLast bool
		if err := rows.Scan(&name, &got.mode, &got.at, &got.day, &got.minPri, &got.tz, &got.quiet, &got.esc, &got.resolved, &hasLast); err != nil {
			t.Fatal(err)
		}
		if got != want[name] || !hasLast {
			t.Errorf("route %s = %+v, want %+v", name, got, want[name])
		}
	}
	rows.Close()

	var announced bool
	if err := owner.QueryRow(ctx, `SELECT announced_at IS NOT NULL FROM assets WHERE id = 1`).Scan(&announced); err != nil || !announced {
		t.Errorf("existing asset announced = %v (%v)", announced, err)
	}
	status := map[int64]string{1: "held", 2: "held", 3: "sent", 4: "pending", 5: "pending", 6: "held"}
	for id, s := range status {
		var got string
		if err := owner.QueryRow(ctx, `SELECT status FROM deliveries WHERE id = $1`, id).Scan(&got); err != nil || got != s {
			t.Errorf("delivery %d: %q, want %q (%v)", id, got, s, err)
		}
	}
	var def string
	if err := owner.QueryRow(ctx, `SELECT column_default FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = 'routes' AND column_name = 'min_priority'`, schema).Scan(&def); err != nil || def != "'P1'::text" {
		t.Errorf("new routes' min_priority default = %q (%v)", def, err)
	}
}
