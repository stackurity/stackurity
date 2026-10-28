package db_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Migration 0049 renames copies of one application on a host that carry
// the same generated name. The production case: "ghost on commmerceblog"
// for /var/www/ghost/versions/6.22.0 and .../6.52.0, both created before
// 0.13 named new copies by their paths.
func TestAppNameBackfill(t *testing.T) {
	pool := testdb.New(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(pool)
	var schema string
	if err := pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(os.Getenv("STACKURITY_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = schema
	owner, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(context.Background(), q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`SELECT set_config('stackurity.scope', 'system', false)`)

	host := func(name string) int64 {
		t.Helper()
		b := model.NewBatch(model.Collector{ID: "linux-agent", Version: "1", Method: "agent"},
			model.AssetRef{Kind: model.AssetHost, Name: name, Identifiers: []model.Identifier{{Scheme: "machine-id", Value: name}}})
		b.Complete = true
		r, err := s.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}
	app := func(hostID int64, hostName, name, dir string) int64 {
		t.Helper()
		b := model.NewBatch(model.Collector{ID: "linux-apps", Version: "1", Method: "agent"}, model.AssetRef{Kind: model.AssetApplication,
			Name: name + " on " + hostName, Identifiers: []model.Identifier{{Scheme: model.AppPathScheme, Value: fmt.Sprintf("host:%d:%s", hostID, dir)}},
			Attributes: map[string]string{"app_dir": dir, "host": hostName}})
		b.Complete = true
		r, err := s.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}
	blog := host("commmerceblog")
	dbc := host("DBC")
	g1 := app(blog, "commmerceblog", "ghost", "/var/www/ghost/versions/6.22.0")
	g2 := app(blog, "commmerceblog", "ghost", "/var/www/ghost/versions/6.52.0")
	p1 := app(dbc, "DBC", "phpmyadmin", "/var/www/html/phpmyadmin")
	p2 := app(dbc, "DBC", "phpmyadmin", "/var/www/html/demo/phpmyadmin")
	solo := app(dbc, "DBC", "codeigniter/framework", "/var/www/html")
	other := app(blog, "commmerceblog", "phpmyadmin", "/srv/phpmyadmin") // same app name, another host
	mine := app(dbc, "DBC", "adminer", "/opt/adminer")
	mine2 := app(dbc, "DBC", "adminer", "/srv/adminer")
	// As before 0.13 and before this migration: the plain names.
	exec(`UPDATE assets SET name = 'ghost on commmerceblog' WHERE id = ANY($1)`, []int64{g1, g2})
	exec(`UPDATE assets SET name = 'phpmyadmin on DBC' WHERE id = ANY($1)`, []int64{p1, p2})
	exec(`UPDATE assets SET name = 'adminer on DBC' WHERE id = $1`, mine2)
	exec(`UPDATE assets SET name = 'adminer on DBC', name_by_person = true WHERE id = $1`, mine)
	exec(`ALTER TABLE collections DROP COLUMN proves_absence`)
	exec(`DELETE FROM schema_migrations WHERE name = '0049_app_presence'`)
	if _, err := db.Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[int64]string{
		g1: "ghost (/6.22.0) on commmerceblog", g2: "ghost (/6.52.0) on commmerceblog",
		p1: "phpmyadmin (/phpmyadmin) on DBC", p2: "phpmyadmin (/demo/phpmyadmin) on DBC",
		solo: "codeigniter/framework on DBC", other: "phpmyadmin on commmerceblog",
		// A person's name stays; the other copy is told apart (nothing shared but /).
		mine: "adminer on DBC", mine2: "adminer (/srv/adminer) on DBC",
	} {
		var got string
		if err := owner.QueryRow(context.Background(), `SELECT name FROM assets WHERE id = $1`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("asset %d = %q, want %q", id, got, want)
		}
	}
	var proves bool
	if err := owner.QueryRow(context.Background(), `SELECT proves_absence FROM collections LIMIT 1`).Scan(&proves); err != nil || proves {
		t.Errorf("proves_absence default: %v %v", proves, err)
	}
	var def string
	if err := owner.QueryRow(context.Background(), `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'checks_outcome_check' AND conrelid = 'checks'::regclass`).Scan(&def); err != nil ||
		!strings.Contains(def, "incomplete") || !strings.Contains(def, "expired") {
		t.Errorf("checks_outcome_check = %q %v", def, err)
	}
}
