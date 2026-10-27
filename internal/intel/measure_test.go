//go:build measure

package intel

// TestMeasureFeedSync measures what a feed sync writes, on real OSV
// archives. It is not part of the normal test run:
//
//	STACKURITY_MEASURE_OSV=/path/to/osv STACKURITY_MEASURE_OUT=/tmp/out \
//	  go test -tags measure -run TestMeasureFeedSync -timeout 4h -v ./internal/intel
//
// /path/to/osv holds <Ecosystem>/all.zip as published at
// https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip
// (STACKURITY_MEASURE_ECOSYSTEMS, default Debian,Ubuntu,npm,PyPI). It syncs
// each feed in full, evaluates an inventory drawn from the archives, then
// syncs the same archives in full again and evaluates again. It logs the
// table size, the rows inserted, deleted and updated and the time of each
// step, and writes the findings and coverage after each evaluation to
// $STACKURITY_MEASURE_OUT.{initial,resync} to compare between versions.

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/tenant"
)

type tableStats struct {
	heap, toast, index  int64
	ins, upd, del, dead int64
	rows                int64
}

func (s tableStats) String() string {
	return fmt.Sprintf("heap %s, toast %s, indexes %s, total %s; live rows %d, dead %d; inserted %d, updated %d, deleted %d",
		mb(s.heap), mb(s.toast), mb(s.index), mb(s.heap+s.toast+s.index), s.rows, s.dead, s.ins, s.upd, s.del)
}

func mb(n int64) string { return fmt.Sprintf("%.1f MB", float64(n)/(1<<20)) }

func TestMeasureFeedSync(t *testing.T) {
	dir := os.Getenv("STACKURITY_MEASURE_OSV")
	out := os.Getenv("STACKURITY_MEASURE_OUT")
	if dir == "" || out == "" {
		t.Skip("STACKURITY_MEASURE_OSV and STACKURITY_MEASURE_OUT not set")
	}
	ecos := strings.Split(envOr("STACKURITY_MEASURE_ECOSYSTEMS", "Debian,Ubuntu,npm,PyPI"), ",")
	sys := tenant.System(context.Background())
	ws := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, _ := setup(t)
	files := httptest.NewServer(http.StripPrefix("/osv/", http.FileServer(http.Dir(dir))))
	t.Cleanup(files.Close)
	sy.f.cfg.OSVBaseURL = files.URL + "/osv"

	// An administrative connection (the application role may not vacuum).
	var schema string
	if err := st.Pool.QueryRow(sys, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(os.Getenv("STACKURITY_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	admin, err := pgxpool.NewWithConfig(sys, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()

	read := func() tableStats {
		var s tableStats
		if err := admin.QueryRow(sys, `SELECT pg_relation_size(c.oid), COALESCE(pg_total_relation_size(NULLIF(c.reltoastrelid, 0)), 0),
			pg_indexes_size(c.oid), s.n_tup_ins, s.n_tup_upd, s.n_tup_del, s.n_dead_tup, s.n_live_tup
			FROM pg_class c JOIN pg_stat_user_tables s ON s.relid = c.oid WHERE c.oid = 'advisory_packages'::regclass`).
			Scan(&s.heap, &s.toast, &s.index, &s.ins, &s.upd, &s.del, &s.dead, &s.rows); err != nil {
			t.Fatal(err)
		}
		return s
	}
	// Other connections report their counts when idle, about a second
	// after their last transaction: wait until the counts settle.
	stats := func() tableStats {
		prev := read()
		for {
			time.Sleep(1500 * time.Millisecond)
			s := read()
			if s.ins == prev.ins && s.del == prev.del && s.upd == prev.upd {
				return s
			}
			prev = s
		}
	}
	diff := func(a, b tableStats) string {
		return fmt.Sprintf("inserted %d, updated %d, deleted %d", b.ins-a.ins, b.upd-a.upd, b.del-a.del)
	}

	syncAll := func(step string) {
		for _, e := range ecos {
			feed := OSVFeed(e)
			before := stats()
			start := time.Now()
			res, err := sy.Sync(sys, feed)
			if err != nil {
				t.Fatalf("%s %s: %v", step, feed, err)
			}
			took := time.Since(start)
			after := stats()
			comps, err := ComponentsToEvaluate(sys, st, feed, res)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s %s: %s, %d records changed, %d components to re-evaluate; advisory_packages %s",
				step, feed, took.Round(time.Millisecond), res.Changed, len(comps), diff(before, after))
		}
		t.Logf("%s done: advisory_packages %s", step, stats())
	}

	for _, e := range ecos {
		if err := st.EnsureFeed(sys, OSVFeed(e), "vulnerability", time.Hour, 6*time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	host := measureInventory(t, dir, ecos)
	for kind, obs := range host {
		ingest(t, st, kind.k, kind.name, true, obs...)
	}

	syncAll("initial sync")
	evalAndDump(t, ws, ev, st.Pool, out+".initial")

	// The same data again, read in full as a full sync does.
	if _, err := st.Pool.Exec(sys, `UPDATE feeds SET cursor = '' WHERE name LIKE 'osv:%'`); err != nil {
		t.Fatal(err)
	}
	syncAll("full re-sync, unchanged")
	evalAndDump(t, ws, ev, st.Pool, out+".resync")

	// Where the affected entries are: in the rows (before 0036), or once
	// each in affected_values.
	var values bool
	if err := admin.QueryRow(sys, `SELECT to_regclass('affected_values') IS NOT NULL`).Scan(&values); err != nil {
		t.Fatal(err)
	}
	expr, from := `affected`, `advisory_packages`
	if values {
		expr, from = `v.affected`, `advisory_packages p JOIN affected_values v ON v.hash = p.affected_hash`
	}
	var n, distinct, bytes, distinctBytes int64
	if err := admin.QueryRow(sys, `SELECT count(*), count(DISTINCT `+expr+`), sum(pg_column_size(`+expr+`)),
		(SELECT sum(pg_column_size(a)) FROM (SELECT DISTINCT `+expr+` AS a FROM `+from+`) d) FROM `+from).
		Scan(&n, &distinct, &bytes, &distinctBytes); err != nil {
		t.Fatal(err)
	}
	t.Logf("affected: %d rows, %d distinct values; %s if stored in each row (%.0f bytes per row), distinct values %s",
		n, distinct, mb(bytes), float64(bytes)/float64(n), mb(distinctBytes))
	tables := []string{"advisory_packages"}
	if values {
		tables = append(tables, "affected_values")
	}
	var total int64
	for _, tbl := range tables {
		vacuum := time.Now()
		if _, err := admin.Exec(sys, `VACUUM FULL `+tbl); err != nil {
			t.Fatal(err)
		}
		var size int64
		if err := admin.QueryRow(sys, `SELECT pg_total_relation_size($1::regclass)`, tbl).Scan(&size); err != nil {
			t.Fatal(err)
		}
		total += size
		t.Logf("VACUUM FULL %s took %s; table, TOAST and indexes %s", tbl, time.Since(vacuum).Round(time.Millisecond), mb(size))
	}
	if _, err := admin.Exec(sys, `ANALYZE advisory_packages`); err != nil {
		t.Fatal(err)
	}
	t.Logf("after VACUUM FULL: advisory_packages %s; with affected_values %s, %.0f bytes per row",
		stats(), mb(total), float64(total)/float64(n))
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

type measureAsset struct {
	k    model.AssetKind
	name string
}

// measureInventory picks packages from the archives: for every 7th package
// of Debian 12, Ubuntu 22.04, npm and PyPI (up to 400 each), one version at
// a fix listed for it and one very old version.
func measureInventory(t *testing.T, dir string, ecos []string) map[measureAsset][]model.Observation {
	out := map[measureAsset][]model.Observation{}
	for _, e := range ecos {
		zr, err := zip.OpenReader(dir + "/" + e + "/all.zip")
		if err != nil {
			t.Fatal(err)
		}
		fixes := map[string]string{}
		for _, zf := range zr.File {
			v, err := readZipVuln(zf)
			if err != nil {
				continue
			}
			for _, a := range v.Affected {
				eco := a.Package.Ecosystem
				if eco != map[string]string{"Debian": "Debian:12", "Ubuntu": "Ubuntu:22.04:LTS", "npm": "npm", "PyPI": "PyPI"}[e] {
					continue
				}
				for _, r := range a.Ranges {
					for _, ev := range r.Events {
						if ev.Fixed != "" && r.Type != "GIT" {
							fixes[a.Package.Name] = ev.Fixed
						}
					}
				}
			}
		}
		zr.Close()
		names := make([]string, 0, len(fixes))
		for n := range fixes {
			names = append(names, n)
		}
		sort.Strings(names)
		var obs []model.Observation
		for i, n := range names {
			if i%7 != 0 || len(obs) >= 800 {
				continue
			}
			for _, ver := range []string{fixes[n], "old"} {
				var purl string
				switch e {
				case "Debian":
					if ver == "old" {
						ver = "0.1-1"
					}
					purl = fmt.Sprintf("pkg:deb/debian/%s@%s?distro=debian-12", n, ver)
				case "Ubuntu":
					if ver == "old" {
						ver = "0.1-1"
					}
					purl = fmt.Sprintf("pkg:deb/ubuntu/%s@%s?distro=ubuntu-22.04", n, ver)
				case "npm":
					if ver == "old" {
						ver = "0.0.1"
					}
					ns, name := "", n
					if i := strings.LastIndex(n, "/"); i > 0 {
						ns, name = strings.ReplaceAll(n[:i], "@", "%40"), n[i+1:]
					}
					if ns != "" {
						purl = fmt.Sprintf("pkg:npm/%s/%s@%s", ns, name, ver)
					} else {
						purl = fmt.Sprintf("pkg:npm/%s@%s", name, ver)
					}
				case "PyPI":
					if ver == "old" {
						ver = "0.0.1"
					}
					purl = fmt.Sprintf("pkg:pypi/%s@%s", n, ver)
				default:
					continue
				}
				obs = append(obs, confirmed(purl, nil))
			}
		}
		// One asset per version so an asset never has a package twice.
		var a, b []model.Observation
		for i, o := range obs {
			if i%2 == 0 {
				a = append(a, o)
			} else {
				b = append(b, o)
			}
		}
		kind := model.AssetHost
		if e == "npm" || e == "PyPI" {
			kind = model.AssetRepository
		}
		out[measureAsset{kind, "measure-" + e + "-fixed"}] = a
		out[measureAsset{kind, "measure-" + e + "-old"}] = b
		t.Logf("inventory %s: %d packages", e, len(obs))
	}
	return out
}

// evalAndDump evaluates everything and writes the findings and coverage,
// without times, sorted.
func evalAndDump(t *testing.T, ctx context.Context, ev *Evaluator, pool *pgxpool.Pool, path string) {
	start := time.Now()
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	t.Logf("evaluated in %s", time.Since(start).Round(time.Millisecond))
	rows, err := pool.Query(ctx, `SELECT i.purl, f.kind, f.key, f.status, f.severity, COALESCE(f.fixed_version, ''),
		COALESCE(array_to_string(f.sources, ','), ''), f.verification, f.priority,
		(f.evidence - 'feed_last_success' - 'feed_stale')::text
		FROM findings f JOIN inventory i ON i.id = f.inventory_id`)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for rows.Next() {
		vals := make([]string, 10)
		ptrs := make([]any, 10)
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, strings.Join(vals, " | "))
	}
	rows.Close()
	findings := len(lines)
	rows, err = pool.Query(ctx, `SELECT jsonb_build_array(i.coverage, i.coverage_reason, i.coverage_feed), i.purl
		FROM inventory i WHERE i.removed_at IS NULL`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var c json.RawMessage
		var purl string
		if err := rows.Scan(&c, &purl); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, "coverage "+purl+" "+string(c))
	}
	rows.Close()
	sort.Strings(lines)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	open := 0
	for _, l := range lines {
		if strings.Contains(l, " | open | ") {
			open++
		}
	}
	t.Logf("%d findings (%d open), %d coverage rows written to %s", findings, open, len(lines)-findings, path)
}
