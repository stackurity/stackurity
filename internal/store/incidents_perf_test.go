package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// TestIncidentListPerformance is the incidents list in the shape of the
// production database where it took 8 to 27 seconds with a project chosen:
// one organisation with a few hosts and many findings, mostly resolved, and
// a second with one host and three applications in a project. It seeds
// STACKURITY_PERF_INCIDENT_FINDINGS findings (8,000 by default, a few seconds;
// production had 240,000), each as wide as a real one.
//
// It checks that the incidents row-level security check reads the findings
// of the visible assets, not every finding (the regression: a hashed SubPlan
// over a sequential scan of findings), that the list with a project chosen
// says what the incidents' visible findings say, and it times the list for
// each kind of caller. Run it with -v to see the numbers:
//
//	STACKURITY_PERF_INCIDENT_FINDINGS=240000 go test ./internal/store -run TestIncidentListPerformance -v
func TestIncidentListPerformance(t *testing.T) {
	n := 8000
	if v, _ := strconv.Atoi(os.Getenv("STACKURITY_PERF_INCIDENT_FINDINGS")); v > 0 {
		n = v
	}
	pool := testdb.New(t)
	st := store.New(pool)
	bg := context.Background()
	wsA := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	b, _, err := st.CreateWorkspace(bg, "Outdo", "", "owner@outdo.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	wsB := tenant.WithWorkspace(bg, b.ID)

	// Organisation A: three hosts with 60% of the findings. Organisation B:
	// a host and three applications in the project (37%), and a host
	// outside it (3%). A quarter of the findings are open; findings of one
	// key on every asset of an organisation share an incident.
	type asset struct {
		ws    int64
		kind  string
		name  string
		share float64
	}
	assets := []asset{
		{1, "host", "a-host-1", 0.20}, {1, "host", "a-host-2", 0.20}, {1, "host", "a-host-3", 0.20},
		{b.ID, "host", "b-host", 0.34}, {b.ID, "application", "b-app-1", 0.01}, {b.ID, "application", "b-app-2", 0.01},
		{b.ID, "application", "b-app-3", 0.01}, {b.ID, "host", "b-other", 0.03},
	}
	keys := max(n/8, 10)
	start := time.Now()
	err = pgx.BeginFunc(tenant.System(bg), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(bg, `INSERT INTO components (purl_key, type, name)
			SELECT 'pkg:deb/perf-lib-' || g, 'deb', 'perf-lib-' || g FROM generate_series(0, $1 - 1) g`, keys); err != nil {
			return err
		}
		for ws := range map[int64]bool{1: true, b.ID: true} {
			if _, err := tx.Exec(bg, `INSERT INTO incidents (workspace_id, kind, key, title, priority, sos, finding_count, asset_count)
				SELECT $1, 'vulnerability', 'CVE-2099-' || g, 'CVE-2099-' || g || ' in perf-lib-' || g, 'P4', false, 1, 1
				FROM generate_series(0, $2 - 1) g`, ws, keys); err != nil {
				return err
			}
		}
		for _, a := range assets {
			m := int(float64(n) * a.share)
			var id int64
			if err := tx.QueryRow(bg, `INSERT INTO assets (workspace_id, kind, name, environment, criticality)
				VALUES ($1, $2, $3, 'production', 'medium') RETURNING id`, a.ws, a.kind, a.name).Scan(&id); err != nil {
				return err
			}
			for _, q := range []string{
				`INSERT INTO collections (workspace_id, asset_id, collector_id, method, observed_at, complete, observation_count)
				 SELECT $1, $2, 'agent', 'agent', now(), true, $3 WHERE $4 > 0`,
				`INSERT INTO inventory (workspace_id, asset_id, component_id, purl, version, collector_id, confidence, first_seen, last_seen, last_collection_id)
				 SELECT $1, $2, c0.base + k % $4, 'pkg:deb/perf-lib-' || (k % $4) || '@1.0.' || k, '1.0.' || k, 'agent', 'confirmed', now(), now(),
				   (SELECT max(id) FROM collections WHERE asset_id = $2)
				 FROM generate_series(0, $3 - 1) k CROSS JOIN (SELECT min(id) AS base FROM components) c0`,
				// Every statement takes the same four arguments.
				// As wide as a real finding: evidence and priority factors
				// make the heap hundreds of megabytes in production.
				`INSERT INTO findings (workspace_id, kind, key, inventory_id, asset_id, component_id, status, resolved_at, verification, severity, score,
				   title, fixed_version, priority, priority_score, sos, escalation_level, state, incident_id, evidence, priority_factors)
				 SELECT $1, 'vulnerability', 'CVE-2099-' || (i.component_id - c0.base), i.id, i.asset_id, i.component_id,
				   CASE WHEN i.id % 4 = 0 THEN 'open' ELSE 'resolved' END, CASE WHEN i.id % 4 = 0 THEN NULL ELSE now() - interval '1 day' END,
				   'confirmed', (ARRAY['critical','high','medium','low'])[1 + i.id % 4], (i.id % 100) / 10.0,
				   'Perf finding ' || i.id, '9.9.9', (ARRAY['P1','P2','P3','P4'])[1 + (i.id / 4) % 4], i.id % 100, i.id % 97 = 0,
				   CASE WHEN i.id % 5 = 0 THEN 1 ELSE 0 END, CASE WHEN i.id % 11 = 0 THEN 'suppressed' ELSE 'new' END,
				   x.id,
				   jsonb_build_object('advisory', repeat('x', 600), 'known_exploited', i.id % 50 = 0),
				   jsonb_build_array(jsonb_build_object('factor', 'severity', 'detail', repeat('y', 300)))
				 FROM inventory i CROSS JOIN (SELECT min(id) AS base FROM components) c0
				 JOIN incidents x ON x.workspace_id = $1 AND x.kind = 'vulnerability' AND x.key = 'CVE-2099-' || (i.component_id - c0.base)
				   AND COALESCE(x.owner_team_id, 0) = 0 AND x.status = 'open'
				 WHERE i.asset_id = $2 AND $3 > 0 AND $4 > 0`,
			} {
				if _, err := tx.Exec(bg, q, a.ws, id, m, keys); err != nil {
					return fmt.Errorf("%s: %.60s: %w", a.name, q, err)
				}
			}
		}
		// Incidents with nothing active left are resolved, as correlation
		// leaves them.
		_, err := tx.Exec(bg, `UPDATE incidents i SET status = 'resolved', resolved_at = now()
			WHERE NOT EXISTS (SELECT 1 FROM findings f WHERE f.incident_id = i.id AND f.status = 'open' AND f.state = 'new')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := st.CreateProject(wsB, "Don't Be Content", "")
	if err != nil {
		t.Fatal(err)
	}
	var inProject []int64
	if err := pool.QueryRow(wsB, `SELECT array_agg(id) FROM assets WHERE name <> 'b-other'`).Scan(&inProject); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddProjectAssets(wsB, p.ID, inProject); err != nil {
		t.Fatal(err)
	}
	// As autovacuum would leave it: statistics and the visibility map that
	// index-only scans need. VACUUM needs the tables' owner.
	owner, err := pgx.Connect(bg, os.Getenv("STACKURITY_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(bg)
	var schema string
	if err := pool.QueryRow(wsA, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(bg, `SET search_path = `+schema); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"assets", "components", "inventory", "findings", "incidents", "projects", "project_assets"} {
		if _, err := owner.Exec(bg, `VACUUM ANALYZE `+tbl); err != nil {
			t.Fatal(err)
		}
	}
	var findingPages, allVisible int64
	if err := owner.QueryRow(bg, `SELECT relpages, relallvisible FROM pg_class WHERE oid = 'findings'::regclass`).Scan(&findingPages, &allVisible); err != nil {
		t.Fatal(err)
	}
	t.Logf("seeded %d findings (%d heap pages), %d incidents per organisation, in %s", n, findingPages, keys, time.Since(start).Round(time.Millisecond))

	project := tenant.WithProject(wsB, p.ID)

	// The row-level security check on incidents, with a project chosen,
	// reads the findings of the project's assets from an index: never the
	// findings table itself, and far fewer pages than it has.
	var raw []byte
	if err := pool.QueryRow(project, `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT count(*) FROM incidents i WHERE i.status = 'open'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var plans []struct{ Plan planNode }
	if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
		t.Fatalf("plan: %v %s", err, raw)
	}
	root := plans[0].Plan
	switch {
	case allVisible*10 < findingPages*9:
		// VACUUM could not mark the new rows visible to everyone (another
		// test's transaction is open), so an index-only scan would read the
		// heap too, and on a table this small PostgreSQL rightly prefers
		// reading it once. Autovacuum keeps a production table visible.
		t.Logf("plan not checked: %d of %d findings pages all-visible", allVisible, findingPages)
	default:
		root.walk(func(n planNode) {
			if n.NodeType == "Seq Scan" && n.Relation == "findings" {
				t.Errorf("the incidents policy reads every finding (Seq Scan on findings):\n%s", raw)
			}
		})
		if pages := root.SharedHit + root.SharedRead; pages*2 > findingPages {
			t.Errorf("counting the project's incidents read %d pages; findings has %d:\n%s", pages, findingPages, raw)
		}
	}

	// What the list says with a project chosen is what the incidents'
	// visible findings say: the total, and the order by their SOS and
	// priority (the reference is the per-incident form the list used before).
	type key struct {
		sos  bool
		prio string
	}
	refRows, err := pool.Query(project, `SELECT i.id, COALESCE(v.sos, i.sos), COALESCE(v.priority, i.priority) FROM incidents i
		LEFT JOIN LATERAL (SELECT min(f.priority) AS priority, bool_or(f.sos) AS sos FROM findings f WHERE f.incident_id = i.id
		  AND f.status = 'open' AND f.state IN ('new', 'acknowledged', 'in_progress')) v ON true
		WHERE i.status = 'open'`)
	if err != nil {
		t.Fatal(err)
	}
	ref := map[int64]key{}
	for refRows.Next() {
		var id int64
		var k key
		if err := refRows.Scan(&id, &k.sos, &k.prio); err != nil {
			t.Fatal(err)
		}
		ref[id] = k
	}
	refRows.Close()
	order := make([]key, 0, len(ref))
	for _, k := range ref {
		order = append(order, k)
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].sos != order[j].sos {
			return order[i].sos
		}
		return order[i].prio < order[j].prio
	})
	list, total, err := st.ListIncidents(project, store.IncidentFilter{Page: store.Page{Limit: 50}})
	if err != nil {
		t.Fatal(err)
	}
	if total != int64(len(ref)) || len(list) != min(50, len(ref)) {
		t.Fatalf("project list: %d of %d, want %d of %d", len(list), total, min(50, len(ref)), len(ref))
	}
	for i, in := range list {
		got, ok := ref[in.ID]
		if !ok || got != order[i] {
			t.Fatalf("project list #%d: incident %d sorts as %+v (visible: %v), want %+v", i, in.ID, got, ok, order[i])
		}
	}
	if _, total, err := st.ListIncidents(project, store.IncidentFilter{Page: store.Page{Limit: 50, Offset: len(ref) + 50}}); err != nil || total != int64(len(ref)) {
		t.Fatalf("past the last page: total %d (%v), want %d", total, err, len(ref))
	}

	callers := []struct {
		name string
		ctx  context.Context
	}{
		{"organisation B, project chosen", project},
		{"organisation B", wsB},
		{"organisation A", wsA},
	}
	ops := []struct {
		name string
		f    store.IncidentFilter
	}{
		{"open incidents, first page", store.IncidentFilter{Status: "open", Page: store.Page{Limit: 50}}},
		{"open SOS incidents, top 5", store.IncidentFilter{Status: "open", SOS: true, Page: store.Page{Limit: 5}}},
		{"all incidents, first page", store.IncidentFilter{Status: "all", Page: store.Page{Limit: 50}}},
	}
	for _, c := range callers {
		for _, op := range ops {
			var ds []time.Duration
			for i := 0; i < 7; i++ {
				s := time.Now()
				if _, _, err := st.ListIncidents(c.ctx, op.f); err != nil {
					t.Fatal(err)
				}
				ds = append(ds, time.Since(s))
			}
			sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
			d := ds[3] // median
			t.Logf("%-32s %-28s %8.1f ms", c.name, op.name, float64(d.Microseconds())/1000)
			if d >= time.Second {
				t.Errorf("%s, %s: %s", c.name, op.name, d)
			}
		}
	}
}

// planNode is the part of an EXPLAIN (FORMAT JSON) plan these tests read.
type planNode struct {
	NodeType   string     `json:"Node Type"`
	Relation   string     `json:"Relation Name"`
	SharedHit  int64      `json:"Shared Hit Blocks"`
	SharedRead int64      `json:"Shared Read Blocks"`
	Plans      []planNode `json:"Plans"`
}

func (n planNode) walk(fn func(planNode)) {
	fn(n)
	for _, c := range n.Plans {
		c.walk(fn)
	}
}
