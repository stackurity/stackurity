package store_test

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// perfDB is a workspace the size of production for the prioritisation
// benchmarks: n open findings on 2,000 hosts, with 3,000 distinct CVEs
// (CVE-2099-0..2999), each finding's advisory (GHSA-perf-<k>) listing a
// second CVE as an alias (CVE-2098-<k>).
type perfDB struct {
	pool  *pgxpool.Pool
	st    *store.Store
	ws    context.Context
	owner *pgx.Conn // the database owner, for statistics and checks
	url   string
	path  string // the test schema
}

// perfFindings is STACKURITY_PERF_FINDINGS; the benchmarks skip without it.
func perfFindings(t *testing.T) int {
	n, _ := strconv.Atoi(os.Getenv("STACKURITY_PERF_FINDINGS"))
	if n <= 0 {
		t.Skip("set STACKURITY_PERF_FINDINGS (e.g. 130000) to run")
	}
	return n
}

func seedPerf(t *testing.T, n int) *perfDB {
	t.Helper()
	pool := testdb.New(t)
	ctx := context.Background()
	d := &perfDB{pool: pool, st: store.New(pool), ws: tenant.WithWorkspace(ctx, tenant.DefaultWorkspace),
		url: os.Getenv("STACKURITY_TEST_DATABASE_URL")}
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
			`INSERT INTO feeds (name, kind) VALUES ('osv:npm', 'vulnerability') ON CONFLICT DO NOTHING`,
			`INSERT INTO advisories (id, feed, group_key, aliases, modified)
			 SELECT 'GHSA-perf-' || g, 'osv:npm', 'CVE-2099-' || g, ARRAY['CVE-2099-' || g, 'CVE-2098-' || g], now()
			 FROM generate_series(0, 2999) g`,
			`INSERT INTO findings (workspace_id, kind, key, inventory_id, asset_id, component_id, status, verification, severity, score,
			   title, fixed_version, priority, priority_score, sos, state, first_seen, evidence, sources)
			 SELECT 1, 'vulnerability', 'CVE-2099-' || (i.id % 3000), i.id, i.asset_id, i.component_id, 'open', 'confirmed',
			   (ARRAY['critical','high','medium','low'])[1 + i.id % 4], (i.id % 100) / 10.0, 'Perf finding ' || i.id, '9.9.9',
			   (ARRAY['P1','P2','P3','P4'])[1 + i.id % 4], i.id % 100, i.id % 997 = 0, 'new', now() - (i.id % 400) * interval '1 day',
			   CASE WHEN i.id % 50 = 0 THEN '{"known_exploited": true}'::jsonb ELSE '{}'::jsonb END,
			   ARRAY['GHSA-perf-' || (i.id % 3000)]
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
	if err := pool.QueryRow(d.ws, `SELECT current_schema()`).Scan(&d.path); err != nil {
		t.Fatal(err)
	}
	d.owner = d.connect(t)
	d.analyze(t)
	return d
}

// connect opens another connection as the database owner, in the test schema.
func (d *perfDB) connect(t *testing.T) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, d.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	if _, err := c.Exec(ctx, `SET search_path = `+d.path); err != nil {
		t.Fatal(err)
	}
	return c
}

func (d *perfDB) analyze(t *testing.T) {
	t.Helper()
	for _, tbl := range []string{"assets", "collections", "components", "inventory", "findings", "advisories", "epss_scores"} {
		if _, err := d.owner.Exec(context.Background(), `VACUUM ANALYZE `+tbl); err != nil {
			t.Fatal(err)
		}
	}
}

// loadEPSS stores the scores of one day: 400,000 CVEs. Of the 3,000 keys,
// about one in nine is at 10% or more and one in 200 at 90% or more, as in
// real EPSS data, moved by shift; their aliases are scored the same way in
// another order, so for some findings the alias scores higher than the key.
// The rest are near zero.
func (d *perfDB) loadEPSS(t *testing.T, date string, shift float64) {
	t.Helper()
	ctx := context.Background()
	if err := pgx.BeginFunc(ctx, d.owner, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM epss_scores`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO epss_scores (cve, score, percentile, model_version, score_date)
		SELECT 'CVE-2099-' || g, round(LEAST(1, GREATEST(0, power(g / 3000.0, 20) + $1))::numeric, 5), 0.5, 'v2026.06.15', $2::date FROM generate_series(0, 2999) g
		UNION ALL
		SELECT 'CVE-2098-' || g, round(LEAST(1, GREATEST(0, power(((g * 7) % 3000) / 3000.0, 20) + $1))::numeric, 5), 0.5, 'v2026.06.15', $2::date FROM generate_series(0, 2999) g
		UNION ALL
		SELECT 'CVE-2000-' || g, 0.001, 0.1, 'v2026.06.15', $2::date FROM generate_series(1, 394000) g`, shift, date)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	d.analyze(t)
}

// written runs f and returns how many findings it wrote.
func (d *perfDB) written(t *testing.T, f func()) int {
	t.Helper()
	ctx := context.Background()
	var since int64
	if err := d.owner.QueryRow(ctx, `SELECT txid_current()`).Scan(&since); err != nil {
		t.Fatal(err)
	}
	f()
	var n int
	if err := d.owner.QueryRow(ctx, `SELECT count(*) FROM findings WHERE xmin::text::bigint > $1`, since).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func median(ds []time.Duration) time.Duration {
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func quantile(ds []time.Duration, q float64) time.Duration {
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[int(q*float64(len(s)-1))]
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// TestPrioritizeRewritePerformance times the pass that rewrites every open
// finding, as the first prioritisation after an upgrade that changes the
// risk policy's version does, and what it does to everything else meanwhile:
//
//   - the longest transaction the pass held open, and how many it used
//     (sampled from pg_stat_activity every few milliseconds);
//   - how long a workflow action on a random open finding waited for its row
//     lock (SELECT ... FOR NO KEY UPDATE, the lock an UPDATE takes), tried
//     every 20 ms throughout the pass;
//   - the steady pass that runs every minute and writes nothing.
//
// Run it with -v to see the numbers; it fails only when the rewrite leaves a
// finding with the old policy version.
//
//	STACKURITY_PERF_FINDINGS=130000 go test ./internal/store -run TestPrioritizeRewritePerformance -v
func TestPrioritizeRewritePerformance(t *testing.T) {
	n := perfFindings(t)
	d := seedPerf(t, n)
	d.loadEPSS(t, "2026-10-28", 0)
	ctx := context.Background()
	var open int
	_ = d.owner.QueryRow(ctx, `SELECT count(*) FROM findings WHERE status = 'open'`).Scan(&open)
	t.Logf("%d open findings", open)

	p1 := risk.DefaultPolicy()
	if _, err := d.st.Prioritize(d.ws, p1, time.Now()); err != nil {
		t.Fatal(err)
	}
	d.analyze(t)
	var steady []time.Duration
	for i := 0; i < 5; i++ {
		s := time.Now()
		if _, err := d.st.Prioritize(d.ws, p1, time.Now()); err != nil {
			t.Fatal(err)
		}
		steady = append(steady, time.Since(s))
	}
	t.Logf("%-44s %8.0f ms (median of 5)", "steady pass, nothing written", ms(median(steady)))

	for round, p := range []risk.Policy{withThreshold(p1, 0.2), withThreshold(p1, 0.3)} {
		// The pass's own backends are the pool's; the monitor and the
		// prober use connections of their own.
		mon, probe := d.connect(t), d.connect(t)
		var ids []int64
		rows, err := d.owner.Query(ctx, `SELECT id FROM findings WHERE status = 'open'`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var id int64
			_ = rows.Scan(&id)
			ids = append(ids, id)
		}
		rows.Close()

		var stop atomic.Bool
		var wg sync.WaitGroup
		// Monitor: every transaction the pass opens that writes findings.
		xacts := map[string]time.Duration{} // xact_start -> longest age seen
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				r, err := mon.Query(ctx, `SELECT xact_start::text, (EXTRACT(EPOCH FROM clock_timestamp() - xact_start) * 1e6)::bigint
					FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND xact_start IS NOT NULL
					  AND state <> 'idle' AND query LIKE 'UPDATE findings SET priority%'`)
				if err != nil {
					return
				}
				for r.Next() {
					var start string
					var us int64
					_ = r.Scan(&start, &us)
					if age := time.Duration(us) * time.Microsecond; age > xacts[start] {
						xacts[start] = age
					}
				}
				r.Close()
				time.Sleep(2 * time.Millisecond)
			}
		}()
		// Prober: a workflow action on a random open finding every 20 ms.
		var waits []time.Duration
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(round)))
			for !stop.Load() {
				id := ids[rng.Intn(len(ids))]
				s := time.Now()
				err := pgx.BeginFunc(ctx, probe, func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx, `SELECT 1 FROM findings WHERE id = $1 FOR NO KEY UPDATE`, id)
					return err
				})
				if err != nil {
					return
				}
				waits = append(waits, time.Since(s))
				time.Sleep(20 * time.Millisecond)
			}
		}()

		var took time.Duration
		w := d.written(t, func() {
			s := time.Now()
			if _, err := d.st.Prioritize(d.ws, p, time.Now()); err != nil {
				t.Error(err)
			}
			took = time.Since(s)
		})
		stop.Store(true)
		wg.Wait()

		var longest time.Duration
		for _, x := range xacts {
			longest = max(longest, x)
		}
		t.Logf("rewrite %d (new policy version):", round+1)
		t.Logf("  %-42s %8.0f ms, %d findings written", "pass", ms(took), w)
		t.Logf("  %-42s %8.1f ms, %d transactions seen", "longest write transaction", ms(longest), len(xacts))
		if len(waits) > 0 {
			t.Logf("  %-42s median %.1f ms, p99 %.1f ms, max %.1f ms (%d tries)", "row lock wait of a workflow action",
				ms(median(waits)), ms(quantile(waits, 0.99)), ms(quantile(waits, 1)), len(waits))
		}
		var stale int
		if err := d.owner.QueryRow(ctx, `SELECT count(*) FROM findings WHERE status = 'open' AND priority_policy <> $1`, p.Version()).Scan(&stale); err != nil {
			t.Fatal(err)
		}
		if stale > 0 {
			t.Errorf("%d open findings kept an old policy version", stale)
		}
		d.analyze(t)
	}
}

func withThreshold(p risk.Policy, v float64) risk.Policy {
	p.EPSSThreshold = v
	return p
}
