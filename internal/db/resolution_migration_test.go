package db_test

import (
	"context"
	"encoding/json"
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

// Migration 0045 classifies the findings resolved before resolution kinds
// existed, from the sentence the matcher wrote and the inventory history.
// The production case: findings on an unchanged mysql-8.0 closed as "no
// longer affected" because Ubuntu withdrew the advisory.
func TestResolutionKindBackfill(t *testing.T) {
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

	ingest := func(purls ...string) int64 {
		t.Helper()
		b := model.NewBatch(model.Collector{ID: "test", Version: "1", Method: "agent"},
			model.AssetRef{Kind: model.AssetHost, Name: "db-1", Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "db-1"}}})
		for _, p := range purls {
			b.Observations = append(b.Observations, model.Observation{Purl: p, Confidence: model.ConfidenceConfirmed})
		}
		b.Complete = true
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		r, err := s.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}
	asset := ingest("pkg:deb/ubuntu/mysql-server-core-8.0@8.0.42-0ubuntu0.20.04.1?distro=ubuntu-20.04",
		"pkg:npm/lodash@4.17.15", "pkg:npm/express@4.0.0", "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2?distro=ubuntu-20.04")
	ingest("pkg:deb/ubuntu/mysql-server-core-8.0@8.0.42-0ubuntu0.20.04.1?distro=ubuntu-20.04",
		"pkg:npm/lodash@4.17.21", "pkg:npm/express@4.0.1")
	row := map[string]int64{} // name@version -> inventory id
	comp := map[string]int64{}
	rows, err := owner.Query(context.Background(), `SELECT c.name || '@' || i.version, i.id, c.id FROM inventory i
		JOIN components c ON c.id = i.component_id WHERE i.asset_id = $1`, asset)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var k string
		var id, c int64
		if err := rows.Scan(&k, &id, &c); err != nil {
			t.Fatal(err)
		}
		row[k], comp[k] = id, c
	}
	rows.Close()
	mysql := "mysql-server-core-8.0@8.0.42-0ubuntu0.20.04.1"
	if row[mysql] == 0 || row["lodash@4.17.15"] == 0 || row["express@4.0.1"] == 0 || row["openssl@1.1.1f-1ubuntu2"] == 0 {
		t.Fatalf("inventory = %v", row)
	}

	closed := time.Date(2026, 10, 27, 18, 8, 0, 0, time.UTC)
	exec(`INSERT INTO feeds (name, kind) VALUES ('osv:Ubuntu', 'vulnerability') ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO advisories (id, feed, group_key, modified, withdrawn) VALUES
		('UBUNTU-CVE-2026-101513', 'osv:Ubuntu', 'CVE-2026-101513', '2026-10-27T18:00:06Z', '2026-10-27T15:50:09Z'),
		('UBUNTU-CVE-2026-2', 'osv:Ubuntu', 'CVE-2026-2', '2026-10-27T18:00:06Z', NULL)`)
	exec(`ALTER TABLE findings DROP COLUMN resolution_kind, DROP COLUMN resolution_detail`)
	exec(`DELETE FROM schema_migrations WHERE name = '0045_resolution_kinds'`)

	ids := map[string]int64{}
	add := func(name, key, inv string, status, resolution string, sources []string, firstSeen time.Time) {
		t.Helper()
		var resolvedAt *time.Time
		if status == "resolved" {
			resolvedAt = &closed
		}
		var id int64
		if err := owner.QueryRow(context.Background(), `INSERT INTO findings (workspace_id, kind, key, inventory_id, asset_id, component_id,
			verification, status, resolution, resolved_at, first_seen, sources, evidence)
			VALUES (1, 'vulnerability', $1, $2, $3, $4, 'confirmed', $5, $6, $7, $8, $9, $10) RETURNING id`,
			key, row[inv], asset, comp[inv], status, resolution, resolvedAt, firstSeen, append([]string{}, sources...),
			map[string]any{"osv_package": map[bool]string{true: "mysql-8.0", false: ""}[inv == mysql]}).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids[name] = id
	}
	before := closed.Add(-time.Hour)
	add("withdrawn", "CVE-2026-101513", mysql, "resolved", "no longer affected (re-evaluated 2026-10-27)", []string{"UBUNTU-CVE-2026-101513"}, before)
	add("changed", "CVE-2026-2", mysql, "resolved", "no longer affected (re-evaluated 2026-10-27)", []string{"UBUNTU-CVE-2026-2"}, before)
	add("upgraded", "CVE-1", "lodash@4.17.15", "resolved", "upgraded to 4.17.21", nil, before)
	add("plan", "CVE-2", "lodash@4.17.15", "resolved", "fixed by remediation plan #7 (upgraded to 4.17.21)", nil, before)
	add("removed", "CVE-3", "openssl@1.1.1f-1ubuntu2", "resolved", "component no longer installed", nil, before)
	add("successor", "CVE-4", "express@4.0.1", "open", "", nil, before)
	add("superseded", "CVE-4", "express@4.0.0", "resolved", "upgraded to 4.0.1", nil, before)
	add("other", "CVE-5", "lodash@4.17.15", "resolved", "closed for some older reason", nil, before)
	add("open", "CVE-6", "lodash@4.17.21", "open", "", nil, before)
	exec(`INSERT INTO finding_events (workspace_id, finding_id, at, actor_type, actor_name, action, note)
		VALUES (1, $1, $2, 'system', 'matcher', 'resolved', 'no longer affected (re-evaluated 2026-10-27)')`, ids["withdrawn"], closed)

	applied, err := db.Migrate(context.Background(), pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0] != "0045_resolution_kinds" {
		t.Fatalf("applied %v", applied)
	}

	want := map[string][2]string{
		"withdrawn":  {"advisory_withdrawn", "advisory withdrawn by Ubuntu on 2026-10-27"},
		"changed":    {"advisory_changed", "advisory updated: UBUNTU-CVE-2026-2 no longer lists mysql-8.0 8.0.42-0ubuntu0.20.04.1"},
		"upgraded":   {"remediated", "upgraded to 4.17.21"},
		"plan":       {"remediated", "fixed by remediation plan #7 (upgraded to 4.17.21)"},
		"removed":    {"removed", "component no longer installed"},
		"superseded": {"superseded", "upgraded to 4.0.1"},
		"other":      {"other", "closed for some older reason"},
		"open":       {"", ""},
	}
	details := map[string]map[string]any{}
	for name, w := range want {
		var kind, resolution string
		var detail map[string]any
		if err := owner.QueryRow(context.Background(), `SELECT resolution_kind, resolution, resolution_detail FROM findings WHERE id = $1`,
			ids[name]).Scan(&kind, &resolution, &detail); err != nil {
			t.Fatal(err)
		}
		if kind != w[0] || resolution != w[1] {
			t.Errorf("%s: kind %q resolution %q, want %q %q", name, kind, resolution, w[0], w[1])
		}
		details[name] = detail
	}
	if d := details["withdrawn"]; d["source"] != "Ubuntu" || d["feed"] != "osv:Ubuntu" || d["withdrawn_at"] == nil ||
		d["version"] != "8.0.42-0ubuntu0.20.04.1" {
		t.Errorf("withdrawn detail = %v", d)
	}
	if d := details["plan"]; d["plan_id"] != float64(7) || d["version"] != "4.17.21" {
		t.Errorf("plan detail = %v", d)
	}
	if d := details["upgraded"]; d["version"] != "4.17.21" {
		t.Errorf("upgraded detail = %v", d)
	}
	var ev json.RawMessage
	if err := owner.QueryRow(context.Background(), `SELECT detail FROM finding_events WHERE finding_id = $1 AND action = 'resolved'`,
		ids["withdrawn"]).Scan(&ev); err != nil {
		t.Fatal(err)
	}
	var evd map[string]any
	if err := json.Unmarshal(ev, &evd); err != nil || evd["resolution_kind"] != "advisory_withdrawn" || evd["source"] != "Ubuntu" {
		t.Errorf("event detail = %s %v", ev, err)
	}

	// The outcomes report counts the remediated and removed findings only.
	r, err := s.OutcomesReport(ctx, closed.Add(-24*time.Hour), closed.Add(time.Hour), map[string]int{"P1": 3, "P2": 14, "P3": 45, "P4": 90})
	if err != nil {
		t.Fatal(err)
	}
	if r.Resolved != 3 || r.Remediated != 2 || r.Removed != 1 || r.NotRemediation.Total != 4 ||
		r.NotRemediation.ByKind["advisory_withdrawn"] != 1 || r.NotRemediation.ByKind["advisory_changed"] != 1 ||
		r.NotRemediation.ByKind["superseded"] != 1 || r.NotRemediation.ByKind["other"] != 1 {
		t.Errorf("outcomes: resolved %d remediated %d removed %d not remediation %+v", r.Resolved, r.Remediated, r.Removed, r.NotRemediation)
	}
}
