package store_test

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// TestPrioritizeEPSSPerformance seeds a workspace the size of production
// (STACKURITY_PERF_FINDINGS open findings, e.g. 130000, on 2,000 hosts, with
// 3,000 distinct CVEs) and times the prioritisation pass the dispatcher runs
// every minute, without EPSS data and with a full EPSS file (400,000 CVEs),
// and the first pass after each daily file, with how many findings it
// rewrote: after the first file the findings that crossed the threshold,
// after days of small moves only those that crossed it for real. It also
// times the findings list with the EPSS join and filter. Run it with -v to
// see the numbers; it fails only when EPSS doubles the pass, or a list
// takes a second or more.
//
//	STACKURITY_PERF_FINDINGS=130000 go test ./internal/store -run TestPrioritizeEPSSPerformance -v
func TestPrioritizeEPSSPerformance(t *testing.T) {
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
	analyze := func() {
		for _, tbl := range []string{"assets", "collections", "components", "inventory", "findings", "epss_scores"} {
			if _, err := owner.Exec(ctx, `VACUUM ANALYZE `+tbl); err != nil {
				t.Fatal(err)
			}
		}
	}
	analyze()
	p := risk.DefaultPolicy()
	median := func(ds []time.Duration) time.Duration {
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[len(ds)/2]
	}
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	// pass runs the dispatcher's full prioritisation once and says how many
	// findings it wrote.
	pass := func() (time.Duration, int) {
		t.Helper()
		var since int64
		if err := owner.QueryRow(ctx, `SELECT txid_current()`).Scan(&since); err != nil {
			t.Fatal(err)
		}
		s := time.Now()
		if _, err := st.Prioritize(ws, p, time.Now()); err != nil {
			t.Fatal(err)
		}
		d := time.Since(s)
		var written int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM findings WHERE xmin::text::bigint > $1`, since).Scan(&written); err != nil {
			t.Fatal(err)
		}
		return d, written
	}
	// steady times passes that change nothing, and the read-and-score part
	// alone (the policy preview reads and scores exactly what a pass does).
	steady := func(label string) (time.Duration, time.Duration) {
		t.Helper()
		var full, read []time.Duration
		for i := 0; i < 5; i++ {
			d, _ := pass()
			full = append(full, d)
			s := time.Now()
			if _, err := st.PreviewRiskPolicy(ws, p, p, time.Now()); err != nil {
				t.Fatal(err)
			}
			read = append(read, time.Since(s))
		}
		t.Logf("%-52s pass %7.0f ms, of which read and score %6.0f ms", label, ms(median(full)), ms(median(read)))
		return median(full), median(read)
	}
	// The scores of one day: 400,000 CVEs. Of the 3,000 in inventory, about
	// one in nine is at 10% or more and one in 200 at 90% or more, as in
	// real EPSS data, moved by shift; the rest are near zero.
	day := func(date string, shift float64) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, owner, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `DELETE FROM epss_scores`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO epss_scores (cve, score, percentile, model_version, score_date)
			SELECT 'CVE-2099-' || g, round(LEAST(1, GREATEST(0, power(g / 3000.0, 20) + $1))::numeric, 5), 0.5, 'v2026.06.15', $2::date FROM generate_series(0, 2999) g
			UNION ALL
			SELECT 'CVE-2000-' || g, 0.001, 0.1, 'v2026.06.15', $2::date FROM generate_series(1, 397000) g`, shift, date)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		analyze()
		d, written := pass()
		t.Logf("%-52s first pass %7.0f ms, %6d findings written", "EPSS of "+date+fmt.Sprintf(" (shift %+.3f)", shift), ms(d), written)
	}
	var total int
	_ = pool.QueryRow(ws, `SELECT count(*) FROM findings WHERE status = 'open'`).Scan(&total)
	t.Logf("%d open findings on %d hosts", total, hosts)

	pass() // the first pass scores the seeded findings
	withoutFull, withoutRead := steady("no EPSS data, steady")
	day("2026-10-28", 0)
	steady("EPSS loaded, steady")
	day("2026-10-29", 0.004)
	day("2026-10-30", -0.004)
	day("2026-10-31", 0.003)
	withFull, withRead := steady("after three days of small moves, steady")
	var counted int
	_ = pool.QueryRow(ws, `SELECT count(*) FROM findings WHERE priority_factors @> '[{"name": "`+risk.FactorEPSS+`"}]'`).Scan(&counted)
	t.Logf("%d findings have the EPSS factor", counted)
	if withRead > 2*withoutRead+100*time.Millisecond || withFull > 2*withoutFull+time.Second {
		t.Errorf("with EPSS: pass %s, read %s; without: pass %s, read %s", withFull, withRead, withoutFull, withoutRead)
	}

	for _, c := range []struct {
		name string
		f    store.FindingFilter
	}{
		{"findings list (first page, EPSS joined)", store.FindingFilter{Page: store.Page{Limit: 50}}},
		{"findings list, epss_min=0.1", store.FindingFilter{EPSSMin: 0.1, Page: store.Page{Limit: 50}}},
		{"findings list, epss_min=0.9", store.FindingFilter{EPSSMin: 0.9, Page: store.Page{Limit: 50}}},
	} {
		var ds []time.Duration
		for i := 0; i < 7; i++ {
			s := time.Now()
			if _, _, err := st.ListFindings(ws, c.f); err != nil {
				t.Fatal(err)
			}
			ds = append(ds, time.Since(s))
		}
		d := median(ds)
		t.Logf("%-52s %7.1f ms", c.name, ms(d))
		if os.Getenv("STACKURITY_PERF_EXPLAIN") != "" && c.f.EPSSMin > 0 {
			for _, q := range []string{
				`SELECT count(*) FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL WHERE f.status = 'open'
				 AND f.kind = 'vulnerability' AND EXISTS (SELECT 1 FROM epss_scores e WHERE e.cve = f.key AND e.score >= $1::real)`,
			} {
				rows, err := pool.Query(ws, `EXPLAIN (ANALYZE, TIMING OFF) `+q, c.f.EPSSMin)
				if err != nil {
					t.Fatal(err)
				}
				for rows.Next() {
					var line string
					_ = rows.Scan(&line)
					t.Log(line)
				}
				rows.Close()
			}
		}
		if d >= time.Second {
			t.Errorf("%s: %s", c.name, d)
		}
	}
}
