package db_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Migration 0096 gives routes and channels an owner (the organisation, a
// project or an asset). A route limited to exactly one project becomes that
// project's; routes limited to several projects, or to none, stay the
// organisation's, and what every route sends is unchanged.
func TestScopedNotificationsMigration(t *testing.T) {
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
	// Back to the schema before 0096.
	exec(`DROP TABLE route_exclusions`)
	exec(`ALTER TABLE slack_oauth_states DROP COLUMN owner_project_id CASCADE`)
	exec(`ALTER TABLE teams_install_codes DROP COLUMN owner_project_id CASCADE`)
	exec(`DROP INDEX routes_name_key`)
	exec(`DROP INDEX channels_name_key`)
	exec(`ALTER TABLE routes DROP COLUMN owner_project_id CASCADE, DROP COLUMN owner_asset_id CASCADE, DROP COLUMN inherits_route_id CASCADE`)
	exec(`ALTER TABLE channels DROP COLUMN owner_project_id CASCADE, DROP COLUMN owner_asset_id CASCADE`)
	exec(`ALTER TABLE routes ADD CONSTRAINT routes_name_key UNIQUE (workspace_id, name)`)
	exec(`ALTER TABLE channels ADD CONSTRAINT channels_name_key UNIQUE (workspace_id, name)`)
	exec(`DELETE FROM schema_migrations WHERE name = '0096_scoped_notifications'`)

	exec(`INSERT INTO projects (id, workspace_id, name) VALUES (1, 1, 'shop'), (2, 1, 'blog')`)
	exec(`INSERT INTO channels (id, workspace_id, kind, name, config, secret_ref) VALUES (1, 1, 'slack', 'alerts', '{}', 'env:X')`)
	exec(`INSERT INTO routes (id, workspace_id, name, channel_id, enabled, project_ids, project_enabled) VALUES
		(1, 1, 'everything', 1, true, '{}', false),
		(2, 1, 'shop only', 1, false, '{1}', true),
		(3, 1, 'shop and blog', 1, false, '{1,2}', true)`)

	applied, err := db.Migrate(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0] != "0096_scoped_notifications" {
		t.Fatalf("applied %v", applied)
	}
	want := map[string]*int64{"everything": nil, "shop only": ptr(1), "shop and blog": nil}
	rows, err := owner.Query(ctx, `SELECT name, owner_project_id, owner_asset_id, enabled, project_enabled, project_ids FROM routes`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var name string
		var proj, asset *int64
		var enabled, projEnabled bool
		var ids []int64
		if err := rows.Scan(&name, &proj, &asset, &enabled, &projEnabled, &ids); err != nil {
			t.Fatal(err)
		}
		n++
		w := want[name]
		if (w == nil) != (proj == nil) || w != nil && *w != *proj || asset != nil {
			t.Errorf("%s: owner project %v, asset %v; want project %v", name, proj, asset, w)
		}
		// Unchanged: what it sends and its switch.
		if name == "shop only" && (enabled || !projEnabled || len(ids) != 1 || ids[0] != 1) {
			t.Errorf("%s changed: enabled %v, project_enabled %v, project_ids %v", name, enabled, projEnabled, ids)
		}
	}
	if n != 3 {
		t.Fatalf("%d routes", n)
	}
	// Names are unique per owner now.
	exec(`INSERT INTO routes (id, workspace_id, name, channel_id, project_ids, owner_project_id) VALUES (4, 1, 'everything', 1, '{2}', 2)`)
	if _, err := owner.Exec(ctx, `INSERT INTO routes (id, workspace_id, name, channel_id) VALUES (5, 1, 'everything', 1)`); err == nil {
		t.Error("a second organisation route named everything was accepted")
	}
	// A project's route is limited to that project.
	if _, err := owner.Exec(ctx, `INSERT INTO routes (id, workspace_id, name, channel_id, project_ids, owner_project_id) VALUES (6, 1, 'odd', 1, '{1}', 2)`); err == nil {
		t.Error("a route of project 2 limited to project 1 was accepted")
	}
}

func ptr(v int64) *int64 { return &v }
