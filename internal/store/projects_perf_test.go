package store_test

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// TestProjectScopePerformance seeds a workspace the size of production
// (STACKURITY_PERF_FINDINGS open findings, e.g. 130000, on 2,000 hosts) and
// times the findings list, its summary and the asset list for each kind of
// caller: organisation-wide (the fast path), organisation-wide with the
// 0.6 policies put back (the baseline), with a project chosen, and members
// with project access only on a small and a large project. Run it with
// -v to see the numbers; it fails only when a list takes a second or more.
func TestProjectScopePerformance(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("STACKURITY_PERF_FINDINGS"))
	if n <= 0 {
		t.Skip("set STACKURITY_PERF_FINDINGS (e.g. 130000) to run")
	}
	pool := testdb.New(t)
	st := store.New(pool)
	ctx := context.Background()
	ws := tenant.WithWorkspace(ctx, tenant.DefaultWorkspace)
	const hosts = 2000
	perHost := (n + hosts - 1) / hosts

	start := time.Now()
	err := pgx.BeginFunc(tenant.System(ctx), pool, func(tx pgx.Tx) error {
		for _, q := range []string{
			`INSERT INTO assets (workspace_id, kind, name, environment, criticality)
			 SELECT 1, 'host', 'perf-host-' || g, CASE WHEN g % 3 = 0 THEN 'production' ELSE 'staging' END, 'medium'
			 FROM generate_series(1, ` + strconv.Itoa(hosts) + `) g`,
			`INSERT INTO collections (workspace_id, asset_id, collector_id, method, observed_at, complete, observation_count)
			 SELECT 1, id, 'agent', 'agent', now(), true, ` + strconv.Itoa(perHost) + ` FROM assets`,
			`INSERT INTO components (purl_key, type, name) SELECT 'pkg:npm/perf-lib-' || g, 'npm', 'perf-lib-' || g FROM generate_series(1, 5000) g`,
			`INSERT INTO inventory (workspace_id, asset_id, component_id, purl, version, collector_id, confidence, first_seen, last_seen, last_collection_id)
			 SELECT 1, a.id, c0.base + ((a.id * 7919 + k) % 5000), 'pkg:npm/perf-lib@1.0.' || k, '1.0.' || k, 'agent', 'confirmed', now(), now(), col.id
			 FROM assets a JOIN collections col ON col.asset_id = a.id
			 CROSS JOIN generate_series(1, ` + strconv.Itoa(perHost) + `) k
			 CROSS JOIN (SELECT min(id) AS base FROM components) c0`,
			`INSERT INTO findings (workspace_id, kind, key, inventory_id, asset_id, component_id, status, verification, severity, score,
			   title, fixed_version, priority, priority_score, sos, state, first_seen, evidence)
			 SELECT 1, 'vulnerability', 'CVE-2099-' || (i.id % 3000), i.id, i.asset_id, i.component_id, 'open', 'confirmed',
			   (ARRAY['critical','high','medium','low'])[1 + i.id % 4], (i.id % 100) / 10.0, 'Perf finding ' || i.id, '9.9.9',
			   (ARRAY['P1','P2','P3','P4'])[1 + i.id % 4], i.id % 100, i.id % 997 = 0, 'new', now() - (i.id % 400) * interval '1 day',
			   CASE WHEN i.id % 50 = 0 THEN '{"known_exploited": true}'::jsonb ELSE '{}'::jsonb END
			 FROM inventory i ORDER BY i.id LIMIT ` + strconv.Itoa(n),
			`INSERT INTO projects (workspace_id, name) VALUES (1, 'small'), (1, 'large')`,
			`INSERT INTO project_assets (workspace_id, project_id, asset_id)
			 SELECT 1, (SELECT p.id FROM projects p WHERE p.name = 'small'), a.id FROM assets a ORDER BY a.id LIMIT 100`,
			`INSERT INTO project_assets (workspace_id, project_id, asset_id)
			 SELECT 1, (SELECT p.id FROM projects p WHERE p.name = 'large'), a.id FROM assets a ORDER BY a.id DESC LIMIT 1000`,
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
	// As autovacuum would leave it: statistics and the visibility map that
	// index-only scans need. VACUUM needs the tables' owner, not the
	// application role.
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
	for _, tbl := range []string{"assets", "collections", "components", "inventory", "findings", "projects", "project_assets", "access_grants"} {
		if _, err := owner.Exec(ctx, `VACUUM ANALYZE `+tbl); err != nil {
			t.Fatal(err)
		}
	}
	var total int
	_ = pool.QueryRow(ws, `SELECT count(*) FROM findings WHERE status = 'open'`).Scan(&total)
	t.Logf("seeded %d open findings on %d hosts in %s", total, hosts, time.Since(start).Round(time.Millisecond))

	var small, large int64
	_ = pool.QueryRow(ws, `SELECT id FROM projects WHERE name = 'small'`).Scan(&small)
	_ = pool.QueryRow(ws, `SELECT id FROM projects WHERE name = 'large'`).Scan(&large)
	member := func(email string, project int64) context.Context {
		id, _, err := st.EnsureMember(ws, email, "", "correct horse battery")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := st.SaveGrant(ws, store.GrantInput{ProjectID: &project, UserID: &id, Role: auth.RoleViewer}, 0); err != nil {
			t.Fatal(err)
		}
		return tenant.WithMember(ws, id)
	}
	callers := []struct {
		name string
		ctx  context.Context
	}{
		{"organisation-wide (fast path)", ws},
		{"organisation-wide, project of 100 hosts chosen", tenant.WithProject(ws, small)},
		{"member of a project of 100 hosts", member("small@x.io", small)},
		{"member of a project of 1,000 hosts", member("large@x.io", large)},
	}
	timeIt := func(ctx context.Context, fn func(context.Context) error) time.Duration {
		var ds []time.Duration
		for i := 0; i < 7; i++ {
			s := time.Now()
			if err := fn(ctx); err != nil {
				t.Fatal(err)
			}
			ds = append(ds, time.Since(s))
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[3] // median
	}
	ops := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"findings list (first page and total)", func(c context.Context) error {
			_, _, err := st.ListFindings(c, store.FindingFilter{Page: store.Page{Limit: 50}})
			return err
		}},
		{"findings summary", func(c context.Context) error { _, err := st.SummarizeFindings(c); return err }},
		{"asset list", func(c context.Context) error {
			_, _, err := st.ListAssets(c, store.AssetFilter{Page: store.Page{Limit: 50}})
			return err
		}},
	}
	report := func(label string, list []struct {
		name string
		ctx  context.Context
	}) {
		for _, c := range list {
			for _, op := range ops {
				d := timeIt(c.ctx, op.fn)
				t.Logf("%-16s %-48s %-38s %8.1f ms", label, c.name, op.name, float64(d.Microseconds())/1000)
				if d >= time.Second {
					t.Errorf("%s, %s: %s", c.name, op.name, d)
				}
			}
		}
	}
	report("0.8 policies", callers)
	explain := func(label string, c context.Context) {
		for _, q := range []string{
			`SELECT count(*) FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL WHERE f.status = 'open'`,
			`SELECT f.id FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL JOIN components c ON c.id = f.component_id
			 WHERE f.status = 'open' ORDER BY f.sos DESC, f.priority, COALESCE((f.evidence->>'known_exploited')::boolean, false) DESC,
		  CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'unknown' THEN 1 ELSE 0 END DESC,
		  f.score DESC NULLS LAST, f.first_seen DESC, f.id LIMIT 50`,
		} {
			rows, err := pool.Query(c, `EXPLAIN (ANALYZE, COSTS ON, TIMING OFF) `+q)
			if err != nil {
				t.Fatal(err)
			}
			var plan []string
			for rows.Next() {
				var line string
				_ = rows.Scan(&line)
				plan = append(plan, line)
			}
			rows.Close()
			if os.Getenv("STACKURITY_PERF_EXPLAIN") != "" {
				t.Logf("%s:\n%s", label, strings.Join(plan, "\n"))
			}
		}
	}
	explain("0.8 fast path", ws)
	explain("0.8 member of 100 hosts", callers[2].ctx)

	// The baseline: the 0.6 policies (workspace only) on the narrowed
	// tables, for the organisation-wide caller.
	rows, err := owner.Query(ctx, `SELECT tablename, qual, with_check FROM pg_policies WHERE schemaname = $1 AND policyname = 'ws'
		AND tablename IN ('assets', 'findings', 'inventory', 'components', 'fix_groups')`, schema)
	if err != nil {
		t.Fatal(err)
	}
	type pol struct{ table, qual, check string }
	var saved []pol
	for rows.Next() {
		var p pol
		var check *string
		if err := rows.Scan(&p.table, &p.qual, &check); err != nil {
			t.Fatal(err)
		}
		if check != nil {
			p.check = *check
		}
		saved = append(saved, p)
	}
	rows.Close()
	for _, p := range saved {
		if p.table == "components" {
			continue // unchanged by 0032
		}
		if _, err := owner.Exec(ctx, `DROP POLICY ws ON `+p.table+`; CREATE POLICY ws ON `+p.table+
			` USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws())`); err != nil {
			t.Fatal(err)
		}
	}
	pool.Reset()
	report("0.6 policies", callers[:1])
	explain("0.6", ws)
	for _, p := range saved {
		if p.table == "components" {
			continue
		}
		q := `DROP POLICY ws ON ` + p.table + `; CREATE POLICY ws ON ` + p.table + ` USING (` + p.qual + `)`
		if p.check != "" {
			q += ` WITH CHECK (` + p.check + `)`
		}
		if _, err := owner.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	pool.Reset()

	// The plans, for the record: the fast path never computes the list of
	// visible assets.
	for _, c := range callers {
		if !strings.HasPrefix(c.name, "organisation-wide (") && !strings.Contains(c.name, "1,000") {
			continue
		}
		rows, err := pool.Query(c.ctx, `EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, SUMMARY ON) SELECT count(*) FROM findings f WHERE f.status = 'open'`)
		if err != nil {
			t.Fatal(err)
		}
		var plan []string
		for rows.Next() {
			var line string
			_ = rows.Scan(&line)
			plan = append(plan, line)
		}
		rows.Close()
		t.Logf("plan of count(open findings), %s:\n%s", c.name, strings.Join(plan, "\n"))
	}
}
