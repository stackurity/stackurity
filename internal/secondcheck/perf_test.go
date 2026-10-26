package secondcheck_test

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/secondcheck"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// TestSecondCheckPerformance seeds a large workspace (STACKURITY_PERF_FINDINGS
// open findings on 2,000 hosts, a quarter of them P1, with real advisory
// records for every key) and times what the second check adds: choosing a
// batch, a whole run, the Coverage summary, and re-evaluating one host.
//
//	STACKURITY_PERF_FINDINGS=130000 go test ./internal/secondcheck -run TestSecondCheckPerformance -v
func TestSecondCheckPerformance(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("STACKURITY_PERF_FINDINGS"))
	if n <= 0 {
		t.Skip("set STACKURITY_PERF_FINDINGS (e.g. 130000) to run")
	}
	pool := testdb.New(t)
	st := store.New(pool)
	ctx := context.Background()
	ws := tenant.WithWorkspace(ctx, tenant.DefaultWorkspace)
	const hosts, keys = 2000, 3000
	perHost := (n + hosts - 1) / hosts
	start := time.Now()
	err := pgx.BeginFunc(tenant.System(ctx), pool, func(tx pgx.Tx) error {
		for _, q := range []string{
			`INSERT INTO assets (workspace_id, kind, name, environment, criticality)
			 SELECT 1, 'host', 'perf-host-' || g, 'production', 'medium' FROM generate_series(1, ` + strconv.Itoa(hosts) + `) g`,
			`INSERT INTO collections (workspace_id, asset_id, collector_id, method, observed_at, complete, observation_count)
			 SELECT 1, id, 'agent', 'agent', now(), true, ` + strconv.Itoa(perHost) + ` FROM assets`,
			`INSERT INTO components (purl_key, type, name) SELECT 'pkg:npm/perf-lib-' || g, 'npm', 'perf-lib-' || g FROM generate_series(0, ` + strconv.Itoa(keys-1) + `) g`,
			`INSERT INTO inventory (workspace_id, asset_id, component_id, purl, version, collector_id, confidence, first_seen, last_seen, last_collection_id)
			 SELECT 1, a.id, c0.base + ((a.id * 7919 + k) % ` + strconv.Itoa(keys) + `),
			   'pkg:npm/perf-lib-' || ((a.id * 7919 + k) % ` + strconv.Itoa(keys) + `) || '@1.0.' || (k % 9), '1.0.' || (k % 9),
			   'agent', 'confirmed', now(), now(), col.id
			 FROM assets a JOIN collections col ON col.asset_id = a.id
			 CROSS JOIN generate_series(1, ` + strconv.Itoa(perHost) + `) k
			 CROSS JOIN (SELECT min(id) AS base FROM components) c0`,
			`INSERT INTO feeds (name, kind, refresh, stale_after) VALUES ('osv:npm', 'vulnerability', interval '1 hour', interval '1 day')
			 ON CONFLICT (name) DO NOTHING`,
			`INSERT INTO advisories (id, feed, group_key, aliases, summary, severity_level, severity_source, modified, refs, known_exploited, fetched_at)
			 SELECT 'GHSA-perf-' || g, 'osv:npm', 'CVE-2099-' || g, '{}', 'perf', 'high', '', now(), '[]', false, now()
			 FROM generate_series(0, ` + strconv.Itoa(keys-1) + `) g`,
			`INSERT INTO advisory_packages (advisory_id, base_ecosystem, ecosystem, name, affected)
			 SELECT 'GHSA-perf-' || g, 'npm', 'npm', 'perf-lib-' || g,
			   ('{"package":{"ecosystem":"npm","name":"perf-lib-' || g || '"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]}')::jsonb
			 FROM generate_series(0, ` + strconv.Itoa(keys-1) + `) g`,
			`INSERT INTO findings (workspace_id, kind, key, inventory_id, asset_id, component_id, status, verification, severity, score,
			   title, fixed_version, sources, priority, priority_score, sos, state, first_seen, evidence)
			 SELECT 1, 'vulnerability', 'CVE-2099-' || (i.component_id - c0.base), i.id, i.asset_id, i.component_id, 'open', 'confirmed',
			   'high', 7.5, 'Perf finding ' || i.id, '9.9.9', ARRAY['GHSA-perf-' || (i.component_id - c0.base)],
			   (ARRAY['P1','P2','P3','P4'])[1 + i.id % 4], 10, i.id % 997 = 0, 'new', now(),
			   jsonb_build_object('known_exploited', i.id % 50 = 0, 'feed', 'osv:npm', 'comparator', 'semver', 'target_ecosystem', 'npm',
			     'osv_package', 'perf-lib-' || (i.component_id - c0.base), 'installed', i.version,
			     'matched_ranges', jsonb_build_array('GHSA-perf-' || (i.component_id - c0.base) || ': < 9.9.9'),
			     'match', jsonb_build_object('rule', 'range', 'record', 'GHSA-perf-' || (i.component_id - c0.base)))
			 FROM inventory i CROSS JOIN (SELECT min(id) AS base FROM components) c0 ORDER BY i.id LIMIT ` + strconv.Itoa(n),
		} {
			if _, err := tx.Exec(ctx, q); err != nil {
				return fmt.Errorf("%.80s: %w", q, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := pgx.Connect(ctx, os.Getenv("STACKURITY_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	var schema string
	if err := pool.QueryRow(ws, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `SET search_path = `+schema); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"assets", "components", "inventory", "findings", "advisories", "advisory_packages"} {
		if _, err := owner.Exec(ctx, `VACUUM ANALYZE `+tbl); err != nil {
			t.Fatal(err)
		}
	}
	var total, wanted int
	_ = pool.QueryRow(ws, `SELECT count(*), count(*) FILTER (WHERE priority = 'P1' OR sos OR (evidence->>'known_exploited') = 'true') FROM findings`).Scan(&total, &wanted)
	t.Logf("seeded %d open findings (%d covered by the second check) in %s", total, wanted, time.Since(start).Round(time.Millisecond))

	median := func(name string, f func()) time.Duration {
		var ds []time.Duration
		for i := 0; i < 5; i++ {
			s := time.Now()
			f()
			ds = append(ds, time.Since(s))
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		t.Logf("%-45s %s", name, ds[2].Round(100*time.Microsecond))
		return ds[2]
	}
	limit := 2 * time.Second
	if d := median("choose a batch of 500", func() {
		if _, err := st.SecondCheckCandidates(ws, secondcheck.DefaultBatch, false); err != nil {
			t.Fatal(err)
		}
	}); d > limit {
		t.Errorf("choosing a batch took %s", d)
	}
	run := &secondcheck.Runner{Store: st}
	var stats secondcheck.Stats
	if d := median("one run (500 findings, checked and recorded)", func() {
		if stats, err = run.Run(ws); err != nil {
			t.Fatal(err)
		}
	}); d > 5*time.Second {
		t.Errorf("a run took %s", d)
	}
	if stats.Checked != secondcheck.DefaultBatch || stats.Agreed != stats.Checked {
		t.Errorf("last run: %+v", stats)
	}
	if d := median("Coverage summary", func() {
		if _, err := st.SummarizeSecondChecks(ws); err != nil {
			t.Fatal(err)
		}
	}); d > limit {
		t.Errorf("summary took %s", d)
	}
	// Re-evaluating one host whose findings were checked: the extra work is
	// the basis comparison and the disagreement lookup.
	var asset int64
	_ = pool.QueryRow(ws, `SELECT f.asset_id FROM second_checks s JOIN findings f ON f.id = s.finding_id LIMIT 1`).Scan(&asset)
	rows, err := pool.Query(ws, `SELECT f.inventory_id, f.component_id, f.key, f.evidence FROM findings f WHERE f.asset_id = $1`, asset)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	var in []store.FindingInput
	for rows.Next() {
		var f store.FindingInput
		if err := rows.Scan(&f.InventoryID, &f.ComponentID, &f.Key, &f.Evidence); err != nil {
			t.Fatal(err)
		}
		f.Kind, f.AssetID, f.Verification, f.Severity, f.FixedVersion = "vulnerability", asset, "confirmed", "high", "9.9.9"
		f.Sources = []string{fmt.Sprint(f.Evidence["match"].(map[string]any)["record"])}
		ids = append(ids, f.InventoryID)
		in = append(in, f)
	}
	rows.Close()
	median(fmt.Sprintf("re-evaluate one host (%d findings)", len(in)), func() {
		if _, _, err := st.SyncFindings(ws, []string{"vulnerability"}, ids, in); err != nil {
			t.Fatal(err)
		}
	})
}
