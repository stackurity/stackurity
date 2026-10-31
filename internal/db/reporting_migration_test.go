package db_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Migration 0064 backfills each asset's reporting source from its latest
// collection and settles what the old 48-hour rule left behind for assets
// a scan reported once: they are no longer stale, and their open "stopped
// reporting" incidents resolve with no recovery message. A server's stays
// open for the dispatcher to regroup.
func TestReportingBackfill(t *testing.T) {
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
	tok, _, err := s.CreateToken(ctx, "ci", auth.RoleCollector, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	ingest := func(method string, kind model.AssetKind, name string, token int64) int64 {
		t.Helper()
		b := model.NewBatch(model.Collector{ID: "c-" + method, Version: "1", Method: method},
			model.AssetRef{Kind: kind, Name: name, Identifiers: []model.Identifier{{Scheme: "name:" + string(kind), Value: name}}})
		b.Complete = true
		r, err := s.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		if token > 0 {
			exec(`UPDATE collections SET submitted_by = $2 WHERE asset_id = $1`, r.AssetID, token)
		}
		return r.AssetID
	}
	server := ingest("agent", model.AssetHost, "web-1", 0)
	once := ingest("lockfile", model.AssetRepository, "analytics", tok.ID)
	twice := ingest("lockfile", model.AssetRepository, "shop", tok.ID)
	ingest("lockfile", model.AssetRepository, "shop", tok.ID)
	// commmerce_connect in production: four scans on 26 Oct, re-run by hand.
	sameDay := ingest("lockfile", model.AssetRepository, "commmerce_connect", tok.ID)
	for range 3 {
		ingest("lockfile", model.AssetRepository, "commmerce_connect", tok.ID)
	}
	exec(`UPDATE collections c SET received_at = v.at FROM (SELECT id, (ARRAY['2026-10-26 04:34+00', '2026-10-26 09:15+00',
		'2026-10-26 09:30+00', '2026-10-26 09:42+00'])[row_number() OVER (ORDER BY id)]::timestamptz AS at
		FROM collections WHERE asset_id = $1) v WHERE v.id = c.id`, sameDay)
	// shop, scanned on three days: a cadence.
	exec(`UPDATE collections SET received_at = now() - interval '2 days' WHERE asset_id = $1`, twice)
	exec(`UPDATE collections SET received_at = now() - interval '9 days' WHERE id = (SELECT min(id) FROM collections WHERE asset_id = $1)`, twice)
	ingest("lockfile", model.AssetRepository, "shop", tok.ID)
	uploaded := ingest("sbom", model.AssetSBOM, "vendor-app", 0)
	exec(`INSERT INTO integrations (workspace_id, kind, name, config) VALUES (1, 'plugin', 'k8s', '{"plugin": "kubernetes"}')`)
	workload := ingest("plugin", model.AssetWorkload, "shop", 0)
	exec(`UPDATE collections SET collector_id = 'plugin:kubernetes' WHERE asset_id = $1`, workload)

	// As 0.13.9 left them: all stale, each with an open, announced incident.
	exec(`UPDATE assets SET collection_status = 'stale', last_seen = now() - interval '5 days'`)
	for _, id := range []int64{server, once, twice, uploaded, sameDay} {
		exec(`INSERT INTO incidents (workspace_id, kind, key, title, priority, notified_priority, notified_at)
			VALUES (1, 'collection', $1, 'Asset has stopped reporting', 'P3', 'P3', now())`, fmt.Sprintf("asset:%d", id))
	}
	exec(`DROP INDEX incidents_reporting_resolved, assets_report_pending`)
	exec(`ALTER TABLE assets DROP COLUMN report_source, DROP COLUMN report_integration_id, DROP COLUMN report_override,
		DROP COLUMN report_runs, DROP COLUMN report_usual, DROP COLUMN report_due_after`)
	exec(`DELETE FROM jobs`) // the evaluations the ingests above queued
	exec(`DELETE FROM schema_migrations WHERE name = '0064_asset_reporting'`)
	if _, err := db.Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}

	type row struct {
		source, status string
		integ          *int64
	}
	for id, want := range map[int64]row{
		server:   {"agent", "stale", nil},
		once:     {"scan", "ok", nil},
		sameDay:  {"scan", "ok", nil},
		twice:    {"scan", "stale", nil},
		uploaded: {"manual", "ok", nil},
	} {
		var got row
		if err := owner.QueryRow(context.Background(), `SELECT report_source, collection_status, report_integration_id FROM assets WHERE id = $1`, id).
			Scan(&got.source, &got.status, &got.integ); err != nil {
			t.Fatal(err)
		}
		if got.source != want.source || got.status != want.status || got.integ != nil {
			t.Errorf("asset %d: %+v, want %+v", id, got, want)
		}
	}
	var src string
	var integ *int64
	if err := owner.QueryRow(context.Background(), `SELECT report_source, report_integration_id FROM assets WHERE id = $1`, workload).Scan(&src, &integ); err != nil {
		t.Fatal(err)
	}
	if src != "integration" || integ == nil {
		t.Errorf("workload: %s %v", src, integ)
	}
	for id, want := range map[int64]string{server: "open", once: "resolved", sameDay: "resolved", twice: "open", uploaded: "resolved"} {
		var status string
		var quiet bool
		var why *string
		if err := owner.QueryRow(context.Background(), `SELECT status, resolved_notified, detail->>'resolution' FROM incidents WHERE key = $1`,
			fmt.Sprintf("asset:%d", id)).Scan(&status, &quiet, &why); err != nil {
			t.Fatal(err)
		}
		if status != want || want == "resolved" && (!quiet || why == nil || *why != "one_off") {
			t.Errorf("incident of %d: %s, quiet %v, resolution %v", id, status, quiet, why)
		}
	}
	// The assets no longer stale are evaluated again, so their findings
	// lose the stale × 0.8.
	for id, want := range map[int64]bool{once: true, sameDay: true, uploaded: true, server: false, twice: false} {
		var queued bool
		if err := owner.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM jobs WHERE kind = 'evaluate' AND dedupe_key = $1
			AND done_at IS NULL AND run_at > now() - interval '1 minute')`, fmt.Sprintf("evaluate:asset:%d", id)).Scan(&queued); err != nil {
			t.Fatal(err)
		}
		if queued != want {
			t.Errorf("asset %d: evaluation queued %v, want %v", id, queued, want)
		}
	}
}
