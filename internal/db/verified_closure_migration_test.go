package db_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Migration 0108 marks the empty collections written when Stackurity lost
// sight of an asset, and reclassifies the findings they closed as
// "removed" to "disappeared", which reports no longer count as remediation.
// A component a complete collection really saw go stays removed.
func TestVerifiedClosureBackfill(t *testing.T) {
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

	ingest := func(kind model.AssetKind, name, purl string) (asset, inv, comp int64) {
		t.Helper()
		b := model.NewBatch(model.Collector{ID: "test", Version: "1", Method: "agent"},
			model.AssetRef{Kind: kind, Name: name, Identifiers: []model.Identifier{{Scheme: "test", Value: name}}})
		b.Observations = append(b.Observations, model.Observation{Purl: purl, Confidence: model.ConfidenceConfirmed})
		b.Complete = true
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		r, err := s.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(context.Background(), `SELECT id, component_id FROM inventory WHERE asset_id = $1`, r.AssetID).
			Scan(&inv, &comp); err != nil {
			t.Fatal(err)
		}
		return r.AssetID, inv, comp
	}
	// gone writes what the old code wrote when an asset's software went:
	// an empty collection proving absence, noted in coverage history with
	// reason, and the inventory row removed at the same time; then the
	// finding closed as removed.
	closed := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	gone := func(asset, inv, comp int64, method, reason string) (finding, coll int64) {
		t.Helper()
		if err := owner.QueryRow(context.Background(), `INSERT INTO collections
			(workspace_id, asset_id, collector_id, collector_version, method, observed_at, complete, observation_count, proves_absence)
			VALUES (1, $1, 'test', '', $2, $3, true, 0, true) RETURNING id`, asset, method, closed).Scan(&coll); err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO coverage_history (workspace_id, collection_id, scope, status, reason) VALUES (1, $1, 'x', 'skipped', $2)`, coll, reason)
		exec(`UPDATE inventory SET removed_at = $2 WHERE id = $1`, inv, closed)
		if err := owner.QueryRow(context.Background(), `INSERT INTO findings (workspace_id, kind, key, inventory_id, asset_id, component_id,
			verification, status, resolution, resolution_kind, resolved_at, first_seen)
			VALUES (1, 'vulnerability', 'CVE-1', $1, $2, $3, 'confirmed', 'resolved', 'component no longer installed', 'removed', $4, $5)
			RETURNING id`, inv, asset, comp, closed.Add(5*time.Second), closed.Add(-48*time.Hour)).Scan(&finding); err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO finding_events (workspace_id, finding_id, at, actor_type, actor_name, action, note, detail)
			VALUES (1, $1, $2, 'system', 'matcher', 'resolved', 'component no longer installed', '{"resolution_kind": "removed"}')`,
			finding, closed.Add(5*time.Second))
		return finding, coll
	}
	repo, repoInv, repoComp := ingest(model.AssetRepository, "acme/shop", "pkg:npm/lodash@4.17.15")
	host, hostInv, hostComp := ingest(model.AssetHost, "web-1", "pkg:npm/express@4.0.0")
	lost, lostColl := gone(repo, repoInv, repoComp, "repository",
		"no longer granted to the Stackurity GitHub App: the repository was removed from the installation on GitHub, or the app was uninstalled")
	seen, _ := gone(host, hostInv, hostComp, "agent", "no longer installed on the host")

	exec(`ALTER TABLE collections DROP COLUMN absence_unverified`)
	exec(`DELETE FROM schema_migrations WHERE name = '0108_verified_closure'`)
	applied, err := db.Migrate(context.Background(), pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0] != "0108_verified_closure" {
		t.Fatalf("applied %v", applied)
	}

	var kind string
	var detail map[string]any
	if err := owner.QueryRow(context.Background(), `SELECT resolution_kind, resolution_detail FROM findings WHERE id = $1`, lost).
		Scan(&kind, &detail); err != nil {
		t.Fatal(err)
	}
	if kind != store.ResolutionDisappeared || detail["collection_id"] != float64(lostColl) || detail["method"] != "repository" ||
		detail["previous_resolution_kind"] != "removed" || detail["previous_resolution"] != "component no longer installed" {
		t.Errorf("lost access: %s %v", kind, detail)
	}
	if err := owner.QueryRow(context.Background(), `SELECT resolution_kind FROM findings WHERE id = $1`, seen).Scan(&kind); err != nil {
		t.Fatal(err)
	}
	if kind != store.ResolutionRemoved {
		t.Errorf("seen removed: %s", kind)
	}
	var evKind string
	if err := owner.QueryRow(context.Background(), `SELECT detail->>'resolution_kind' FROM finding_events WHERE finding_id = $1`, lost).
		Scan(&evKind); err != nil || evKind != store.ResolutionDisappeared {
		t.Errorf("event kind %q %v", evKind, err)
	}

	r, err := s.OutcomesReport(ctx, closed.Add(-24*time.Hour), closed.Add(time.Hour), map[string]int{"P1": 3, "P2": 14, "P3": 45, "P4": 90})
	if err != nil {
		t.Fatal(err)
	}
	if r.Removed != 1 || r.NotRemediation.ByKind[store.ResolutionDisappeared] != 1 {
		t.Errorf("outcomes: removed %d, not remediation %+v", r.Removed, r.NotRemediation)
	}
}
