package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Feed syncs write only what changed: an unchanged record writes nothing, a
// changed one writes only the package rows that differ, and the findings are
// the same as when every record was rewritten.

// changeRecords builds the Debian records used below. OpenSSL lists two
// releases; libxml2's advisory also lists zlib.
type changeRecords struct {
	opensslFix12, opensslFix11, curlFix string
	opensslWithdrawn                    bool
	withZlib                            bool
	modified                            string
}

func (c changeRecords) files() map[string]string {
	withdrawn := ""
	if c.opensslWithdrawn {
		withdrawn = `"withdrawn":"2024-03-01T00:00:00Z",`
	}
	zlib := ""
	if c.withZlib {
		zlib = `,{"package":{"ecosystem":"Debian:12","name":"zlib"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:1.2.13.dfsg-1+deb12u1"}]}]}`
	}
	return map[string]string{
		"DSA-0001-1.json": fmt.Sprintf(`{"id":"DSA-0001-1",%s"modified":"%s","upstream":["CVE-2024-0001"],"summary":"openssl security update",
		 "affected":[{"package":{"ecosystem":"Debian:12","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"%s"}]}],
		   "database_specific":{"source":"https://security-tracker.debian.org/tracker/DSA-0001-1"}},
		  {"package":{"ecosystem":"Debian:11","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"%s"}]}]}]}`,
			withdrawn, c.modified, c.opensslFix12, c.opensslFix11),
		"DSA-0002-1.json": fmt.Sprintf(`{"id":"DSA-0002-1","modified":"%s","upstream":["CVE-2024-0002"],"summary":"curl security update",
		 "affected":[{"package":{"ecosystem":"Debian:12","name":"curl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"%s"}]}]}]}`,
			c.modified, c.curlFix),
		"DSA-0003-1.json": fmt.Sprintf(`{"id":"DSA-0003-1","modified":"%s","upstream":["CVE-2024-0003"],"summary":"libxml2 security update",
		 "affected":[{"package":{"ecosystem":"Debian:12","name":"libxml2"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.9.14+dfsg-1.3~deb12u2"}]}]}%s]}`,
			c.modified, zlib),
	}
}

var baseRecords = changeRecords{opensslFix12: "3.0.11-1~deb12u2", opensslFix11: "1.1.1w-0+deb11u1", curlFix: "7.88.1-10+deb12u6",
	withZlib: true, modified: "2024-02-01T00:00:00Z"}

type changeEnv struct {
	t    *testing.T
	ctx  context.Context
	st   *store.Store
	sy   *Syncer
	ev   *Evaluator
	up   *upstream
	host int64
}

func newChangeEnv(t *testing.T) *changeEnv {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	e := &changeEnv{t: t, ctx: ctx, st: st, sy: sy, ev: ev, up: up}
	e.host = ingest(t, st, model.AssetHost, "web-1", true,
		confirmed("pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=debian-12", nil),
		confirmed("pkg:deb/debian/curl@7.88.1-10+deb12u5?distro=debian-12", nil),
		confirmed("pkg:deb/debian/libxml2@2.9.14+dfsg-1.3~deb12u1?distro=debian-12", nil),
		confirmed("pkg:deb/debian/zlib@1:1.2.13.dfsg-1?distro=debian-12", nil),
	)
	if err := st.EnsureFeed(ctx, "osv:Debian", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	return e
}

// sync serves recs as the full archive and syncs it in full.
func (e *changeEnv) sync(recs changeRecords) *SyncResult {
	e.t.Helper()
	e.up.set("/osv/Debian/all.zip", zipOf(e.t, recs.files()))
	if _, err := e.st.Pool.Exec(e.ctx, `UPDATE feeds SET cursor = '' WHERE name = 'osv:Debian'`); err != nil {
		e.t.Fatal(err)
	}
	res, err := e.sy.Sync(e.ctx, "osv:Debian")
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

// evaluate re-evaluates what the sync result asks for, as the server does.
func (e *changeEnv) evaluate(res *SyncResult) []int64 {
	e.t.Helper()
	ids, err := ComponentsToEvaluate(e.ctx, e.st, "osv:Debian", res)
	if err != nil {
		e.t.Fatal(err)
	}
	if ids != nil {
		if _, err := e.ev.Evaluate(e.ctx, ids, 0); err != nil {
			e.t.Fatal(err)
		}
	}
	return ids
}

// findings returns every finding's state by issue and package, without the
// feed's sync time.
func (e *changeEnv) findings() map[string]string {
	e.t.Helper()
	rows, err := e.st.Pool.Query(e.ctx, `SELECT f.key || ' ' || split_part(split_part(i.purl, '@', 1), '/', 3), f.status, f.severity, COALESCE(f.fixed_version, ''), f.verification, f.priority,
		COALESCE(array_to_string(f.sources, ','), ''), (f.evidence - 'feed_last_success' - 'feed_stale')::text
		FROM findings f JOIN inventory i ON i.id = f.inventory_id WHERE f.asset_id = $1`, e.host)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var key string
		v := make([]string, 7)
		if err := rows.Scan(&key, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6]); err != nil {
			e.t.Fatal(err)
		}
		out[key] = strings.Join(v, " | ")
	}
	return out
}

// rows returns every stored package row with its physical identity: the
// row version (ctid) and the transaction that wrote it (xmin). An update,
// delete or insert changes the set.
func (e *changeEnv) rows(table string) map[string]string {
	e.t.Helper()
	q := `SELECT advisory_id || ' ' || ecosystem || ' ' || name, ctid::text || '/' || xmin::text || ' ' || encode(affected_hash, 'hex') FROM advisory_packages`
	if table == "advisories" {
		q = `SELECT id, ctid::text || '/' || xmin::text FROM advisories`
	}
	rows, err := e.st.Pool.Query(e.ctx, q)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			e.t.Fatal(err)
		}
		if _, dup := out[k]; dup {
			e.t.Errorf("%s stored twice", k)
		}
		out[k] = v
	}
	return out
}

func diffKeys(before, after map[string]string) []string {
	var d []string
	for k, v := range before {
		if after[k] != v {
			d = append(d, k)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			d = append(d, k)
		}
	}
	sort.Strings(d)
	return d
}

func packages(m map[store.PackageRef]bool) string {
	var out []string
	for p := range m {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestResyncUnchangedWritesNothing(t *testing.T) {
	e := newChangeEnv(t)
	res := e.sync(baseRecords)
	if res.Changed != 3 || !res.All {
		t.Errorf("first sync: %+v; want 3 records changed and everything evaluated", res)
	}
	e.evaluate(res)
	before := e.findings()
	if len(before) != 4 {
		t.Fatalf("findings = %v; want openssl, curl, libxml2 and zlib", before)
	}
	pkgs, advs := e.rows("advisory_packages"), e.rows("advisories")
	if len(pkgs) != 5 {
		t.Fatalf("package rows = %v", pkgs)
	}

	// The same archive again, read in full.
	res = e.sync(baseRecords)
	if res.Changed != 0 || res.All || len(res.Packages) != 0 {
		t.Errorf("unchanged full re-sync: %+v; want nothing changed", res)
	}
	if ids := e.evaluate(res); ids != nil {
		t.Errorf("unchanged re-sync re-evaluates %v; want nothing", ids)
	}
	if d := diffKeys(pkgs, e.rows("advisory_packages")); d != nil {
		t.Errorf("advisory_packages rows written by an unchanged re-sync: %v", d)
	}
	if d := diffKeys(advs, e.rows("advisories")); d != nil {
		t.Errorf("advisories rows written by an unchanged re-sync: %v", d)
	}

	// The same records again, fetched one by one by an incremental sync.
	f, _ := e.st.GetFeed(e.ctx, "osv:Debian")
	var csv []string
	for name, body := range baseRecords.files() {
		id := strings.TrimSuffix(name, ".json")
		e.up.set("/osv/Debian/"+id+".json", body)
		csv = append(csv, time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)+","+id)
	}
	e.up.set("/osv/Debian/modified_id.csv", strings.Join(csv, "\n")+"\n")
	res, err := e.sy.Sync(e.ctx, "osv:Debian")
	if err != nil {
		t.Fatal(err)
	}
	if res.Full || res.Changed != 0 || len(res.Packages) != 0 {
		t.Errorf("incremental re-fetch of unchanged records: %+v (cursor was %q)", res, f.Cursor)
	}
	if d := diffKeys(pkgs, e.rows("advisory_packages")); d != nil {
		t.Errorf("advisory_packages rows written by an unchanged incremental sync: %v", d)
	}

	// Evaluating everything gives the same findings.
	if _, err := e.ev.Evaluate(e.ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	if d := diffKeys(before, e.findings()); d != nil {
		t.Errorf("findings changed: %v\nbefore %v\nafter  %v", d, before, e.findings())
	}
}

func TestChangedRangeRewritesOnlyItsRow(t *testing.T) {
	e := newChangeEnv(t)
	e.evaluate(e.sync(baseRecords))
	pkgs := e.rows("advisory_packages")
	before := e.findings()

	// curl's fix moves; OpenSSL's Debian 11 fix moves (its Debian 12 entry
	// stays the same).
	recs := baseRecords
	recs.curlFix, recs.opensslFix11, recs.modified = "7.88.1-10+deb12u7", "1.1.1w-0+deb11u2", "2024-03-01T00:00:00Z"
	res := e.sync(recs)
	if res.Changed != 3 { // every record's modified time moved
		t.Errorf("changed = %d", res.Changed)
	}
	want := []string{"DSA-0001-1 Debian:11 openssl", "DSA-0002-1 Debian:12 curl"}
	if d := diffKeys(pkgs, e.rows("advisory_packages")); strings.Join(d, ";") != strings.Join(want, ";") {
		t.Errorf("rows rewritten = %v; want only %v", d, want)
	}
	if got := packages(res.Packages); got != "curl,libxml2,openssl,zlib" {
		t.Errorf("packages to re-evaluate = %s", got)
	}
	e.evaluate(res)
	after := e.findings()
	if d := diffKeys(before, after); strings.Join(d, ",") != "CVE-2024-0002 curl" {
		t.Errorf("findings changed: %v", d)
	}
	if !strings.Contains(after["CVE-2024-0002 curl"], "7.88.1-10+deb12u7") {
		t.Errorf("curl finding = %s; want the new fix", after["CVE-2024-0002 curl"])
	}

	// Only curl's range changes; the others keep their modified time too.
	recs2 := recs
	recs2.curlFix = "7.88.1-10+deb12u8"
	pkgs = e.rows("advisory_packages")
	res = e.sync(recs2)
	if res.Changed != 1 || packages(res.Packages) != "curl" {
		t.Errorf("one record changed: changed %d, packages %s", res.Changed, packages(res.Packages))
	}
	if d := diffKeys(pkgs, e.rows("advisory_packages")); strings.Join(d, ";") != "DSA-0002-1 Debian:12 curl" {
		t.Errorf("rows rewritten = %v", d)
	}
}

func TestWithdrawnAdvisoryRemovesItsRows(t *testing.T) {
	e := newChangeEnv(t)
	e.evaluate(e.sync(baseRecords))
	if !strings.HasPrefix(e.findings()["CVE-2024-0001 openssl"], "open") {
		t.Fatalf("openssl finding = %q", e.findings()["CVE-2024-0001 openssl"])
	}
	pkgs := e.rows("advisory_packages")
	recs := baseRecords
	recs.opensslWithdrawn = true
	res := e.sync(recs)
	if res.Changed != 1 || packages(res.Packages) != "openssl" {
		t.Errorf("withdrawal: changed %d, packages %s", res.Changed, packages(res.Packages))
	}
	want := []string{"DSA-0001-1 Debian:11 openssl", "DSA-0001-1 Debian:12 openssl"}
	if d := diffKeys(pkgs, e.rows("advisory_packages")); strings.Join(d, ";") != strings.Join(want, ";") {
		t.Errorf("rows changed = %v; want the withdrawn advisory's rows removed", d)
	}
	var withdrawn *time.Time
	if err := e.st.Pool.QueryRow(e.ctx, `SELECT withdrawn FROM advisories WHERE id = 'DSA-0001-1'`).Scan(&withdrawn); err != nil || withdrawn == nil {
		t.Errorf("advisory withdrawn = %v %v", withdrawn, err)
	}
	e.evaluate(res)
	f := e.findings()
	if !strings.HasPrefix(f["CVE-2024-0001 openssl"], "resolved") {
		t.Errorf("openssl finding after withdrawal = %q; want resolved", f["CVE-2024-0001 openssl"])
	}
	for _, k := range []string{"CVE-2024-0002 curl", "CVE-2024-0003 libxml2", "CVE-2024-0003 zlib"} {
		if !strings.HasPrefix(f[k], "open") {
			t.Errorf("%s = %q; want open", k, f[k])
		}
	}
}

func TestShrinkingPackageList(t *testing.T) {
	e := newChangeEnv(t)
	e.evaluate(e.sync(baseRecords))
	pkgs := e.rows("advisory_packages")
	recs := baseRecords
	recs.withZlib = false
	res := e.sync(recs)
	if res.Changed != 1 || packages(res.Packages) != "libxml2,zlib" {
		t.Errorf("shrink: changed %d, packages %s", res.Changed, packages(res.Packages))
	}
	if d := diffKeys(pkgs, e.rows("advisory_packages")); strings.Join(d, ";") != "DSA-0003-1 Debian:12 zlib" {
		t.Errorf("rows changed = %v; want only zlib's row deleted", d)
	}
	e.evaluate(res)
	// One group (CVE-2024-0003) covers both packages; libxml2 still has it.
	rows, err := e.st.Pool.Query(e.ctx, `SELECT i.purl, f.status FROM findings f JOIN inventory i ON i.id = f.inventory_id WHERE f.key = 'CVE-2024-0003'`)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for rows.Next() {
		var purl, status string
		_ = rows.Scan(&purl, &status)
		got[strings.SplitN(purl, "@", 2)[0]] = status
	}
	rows.Close()
	if got["pkg:deb/debian/libxml2"] != "open" || got["pkg:deb/debian/zlib"] != "resolved" {
		t.Errorf("CVE-2024-0003 findings = %v; want libxml2 open, zlib resolved", got)
	}
	// zlib's entry is referenced by no row now; pruning removes only it.
	if n, err := e.st.PruneAffectedValues(e.ctx); err != nil || n != 1 {
		t.Errorf("pruned %d (%v); want zlib's entry", n, err)
	}
	if _, err := e.ev.Evaluate(e.ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	if f := e.findings(); !strings.HasPrefix(f["CVE-2024-0003 libxml2"], "open") || !strings.HasPrefix(f["CVE-2024-0001 openssl"], "open") {
		t.Errorf("after pruning: %v", f)
	}
}

// A sync that stored records and was interrupted before it queued their
// re-evaluation: the next sync finds them unchanged and still re-evaluates
// their packages.
func TestInterruptedSyncStillReevaluates(t *testing.T) {
	e := newChangeEnv(t)
	e.evaluate(e.sync(baseRecords))
	recs := baseRecords
	recs.curlFix = "7.88.1-10+deb12u9"
	var vulns []*osv.Vulnerability
	for _, body := range recs.files() {
		var v osv.Vulnerability
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			t.Fatal(err)
		}
		vulns = append(vulns, &v)
	}
	// What the interrupted attempt stored before the server died.
	if err := e.st.FeedAttempt(e.ctx, "osv:Debian"); err != nil {
		t.Fatal(err)
	}
	if n, err := e.st.UpsertAdvisories(e.ctx, "osv:Debian", vulns); err != nil || n != 1 {
		t.Fatalf("stored %d, %v", n, err)
	}
	res := e.sync(recs)
	if res.Changed != 0 || packages(res.Packages) != "curl" {
		t.Errorf("retry: changed %d, packages %s; want curl from the interrupted attempt", res.Changed, packages(res.Packages))
	}
	e.evaluate(res)
	if f := e.findings()["CVE-2024-0002 curl"]; !strings.Contains(f, "7.88.1-10+deb12u9") {
		t.Errorf("curl finding = %q; want the fix stored by the interrupted attempt", f)
	}
	// The successful sync cleared what it handed over.
	if res := e.sync(recs); len(res.Packages) != 0 {
		t.Errorf("next sync re-evaluates %s again", packages(res.Packages))
	}
}

// Rows stored before change detection (no hash; affected with the package,
// severities and database_specific) are rewritten once in the compact form,
// with the same findings, and then left alone.
func TestOlderRowsRewrittenOnce(t *testing.T) {
	e := newChangeEnv(t)
	e.evaluate(e.sync(baseRecords))
	before := e.findings()
	if _, err := e.st.Pool.Exec(e.ctx, `UPDATE advisories SET content_hash = NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool.Exec(e.ctx, `UPDATE advisory_packages p SET affected_hash = NULL, affected = v.affected ||
		jsonb_build_object('package', jsonb_build_object('ecosystem', p.ecosystem, 'name', p.name, 'purl', ''),
		  'severity', NULL, 'ecosystem_specific', NULL, 'database_specific', '{"source":"x"}'::jsonb)
		FROM affected_values v WHERE v.hash = p.affected_hash`); err != nil {
		t.Fatal(err)
	}
	if n, err := e.st.PruneAffectedValues(e.ctx); err != nil || n != 5 {
		t.Fatalf("pruned %d values (%v); want the 5 no row refers to now", n, err)
	}
	if _, err := e.ev.Evaluate(e.ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	if d := diffKeys(before, e.findings()); d != nil {
		t.Errorf("findings from the older row form differ: %v", d)
	}
	res := e.sync(baseRecords)
	if res.Changed != 3 {
		t.Errorf("changed = %d; want every record rewritten once", res.Changed)
	}
	var old int
	if err := e.st.Pool.QueryRow(e.ctx, `SELECT count(*) FROM advisory_packages WHERE affected IS NOT NULL OR affected_hash IS NULL`).Scan(&old); err != nil || old != 0 {
		t.Errorf("%d rows still in the older form (%v)", old, err)
	}
	var stray int
	if err := e.st.Pool.QueryRow(e.ctx, `SELECT count(*) FROM affected_values v WHERE v.affected ? 'package'`).Scan(&stray); err != nil || stray != 0 {
		t.Errorf("%d stored values keep the package (%v)", stray, err)
	}
	if _, err := e.ev.Evaluate(e.ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	if d := diffKeys(before, e.findings()); d != nil {
		t.Errorf("findings changed: %v", d)
	}
	if res := e.sync(baseRecords); res.Changed != 0 {
		t.Errorf("then unchanged: changed = %d", res.Changed)
	}
}

// An advisory that covers npm and PyPI packages is in both archives. The
// two feeds' syncs do not rewrite it in turn.
func TestAdvisoryInTwoFeedsWrittenOnce(t *testing.T) {
	e := newChangeEnv(t)
	shared := `{"id":"GHSA-both","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2024-0100"],"summary":"bundled library",
	 "affected":[{"package":{"ecosystem":"npm","name":"bundle"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]},
	             {"package":{"ecosystem":"PyPI","name":"bundle"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`
	e.up.set("/osv/npm/all.zip", zipOf(t, map[string]string{"GHSA-both.json": shared}))
	e.up.set("/osv/PyPI/all.zip", zipOf(t, map[string]string{"GHSA-both.json": shared}))
	for _, f := range []string{"osv:npm", "osv:PyPI"} {
		if err := e.st.EnsureFeed(e.ctx, f, "vulnerability", time.Hour, 6*time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	syncFull := func(feed string) *SyncResult {
		if _, err := e.st.Pool.Exec(e.ctx, `UPDATE feeds SET cursor = '' WHERE name = $1`, feed); err != nil {
			t.Fatal(err)
		}
		res, err := e.sy.Sync(e.ctx, feed)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := syncFull("osv:npm"); res.Changed != 1 {
		t.Errorf("npm first sync changed %d", res.Changed)
	}
	if res := syncFull("osv:PyPI"); res.Changed != 0 {
		t.Errorf("PyPI sync of the same advisory changed %d", res.Changed)
	}
	pkgs, advs := e.rows("advisory_packages"), e.rows("advisories")
	for _, f := range []string{"osv:npm", "osv:PyPI", "osv:npm"} {
		if res := syncFull(f); res.Changed != 0 {
			t.Errorf("%s re-sync changed %d", f, res.Changed)
		}
	}
	if d := diffKeys(pkgs, e.rows("advisory_packages")); d != nil {
		t.Errorf("package rows rewritten: %v", d)
	}
	if d := diffKeys(advs, e.rows("advisories")); d != nil {
		t.Errorf("advisory rewritten: %v", d)
	}

	// The fix changes. The npm sync reads it first and stores it; the PyPI
	// sync finds it unchanged and still re-evaluates the PyPI package.
	repo := ingest(t, e.st, model.AssetRepository, "app", true, confirmed("pkg:pypi/bundle@1.0", nil))
	if _, err := e.ev.Evaluate(e.ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	moved := strings.ReplaceAll(shared, `"fixed":"2.0.0"`, `"fixed":"2.0.1"`)
	e.up.set("/osv/npm/all.zip", zipOf(t, map[string]string{"GHSA-both.json": moved}))
	e.up.set("/osv/PyPI/all.zip", zipOf(t, map[string]string{"GHSA-both.json": moved}))
	if res := syncFull("osv:npm"); res.Changed != 1 || packages(res.Packages) != "bundle" {
		t.Errorf("npm sync of the change: %+v", res)
	}
	res := syncFull("osv:PyPI")
	if res.Changed != 0 || packages(res.Packages) != "bundle" {
		t.Errorf("PyPI sync after npm stored the change: changed %d, packages %s; want bundle", res.Changed, packages(res.Packages))
	}
	ids, err := ComponentsToEvaluate(e.ctx, e.st, "osv:PyPI", res)
	if err != nil || len(ids) != 1 {
		t.Fatalf("PyPI components to evaluate = %v %v", ids, err)
	}
	if _, err := e.ev.Evaluate(e.ctx, ids, 0); err != nil {
		t.Fatal(err)
	}
	fs, _, _ := e.st.ListFindings(e.ctx, store.FindingFilter{AssetID: repo})
	if len(fs) != 1 || fs[0].FixedVersion != "2.0.1" {
		t.Errorf("PyPI finding = %+v; want fixed in 2.0.1", fs)
	}
	if res := syncFull("osv:PyPI"); len(res.Packages) != 0 {
		t.Errorf("handed over twice: %s", packages(res.Packages))
	}
}
