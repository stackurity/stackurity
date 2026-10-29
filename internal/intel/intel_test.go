package intel

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"github.com/stackurity/stackurity/internal/tenant"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/testdb"
)

// upstream fakes OSV, KEV and endoflife.date.
type upstream struct {
	mu       sync.Mutex
	files    map[string][]byte
	requests []string
}

func (u *upstream) set(path string, body string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.files[path] = []byte(body)
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.requests = append(u.requests, r.URL.EscapedPath())
	b, ok := u.files[r.URL.EscapedPath()]
	if !ok {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(b)
}

func zipOf(t *testing.T, files map[string]string) string {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		f, _ := zw.Create(name)
		_, _ = io.WriteString(f, body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

const ghsaLodash = `{"id":"GHSA-p6mc","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2021-23337"],"summary":"Command injection in lodash",
 "database_specific":{"severity":"HIGH"},
 "affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`

// A second source for the same CVE must collapse into the same finding.
const osvLodashDup = `{"id":"OSV-LODASH-1","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2021-23337"],"summary":"",
 "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
 "affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"4.0.0"},{"fixed":"4.17.21"}]}]}]}`

const debOpenssl = `{"id":"DSA-5532-1","modified":"2024-01-01T00:00:00Z","upstream":["CVE-2023-5678"],"summary":"openssl security update",
 "affected":[{"package":{"ecosystem":"Debian:12","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.11-1~deb12u2"}]}]},
             {"package":{"ecosystem":"Debian:11","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.1.1w-0+deb11u1"}]}]}]}`

const kev = `{"vulnerabilities":[{"cveID":"CVE-2021-23337","vendorProject":"lodash","product":"lodash","vulnerabilityName":"x","shortDescription":"lodash contains a prototype pollution vulnerability.","dateAdded":"2024-02-01","dueDate":"2024-02-22","knownRansomwareCampaignUse":"Unknown"}]}`

const eol = `{"result":[
 {"name":"debian","label":"Debian","links":{"html":"https://endoflife.date/debian"},"identifiers":[],
  "releases":[{"name":"12","label":"12","releaseDate":"2023-06-10","isLts":false,"isEol":false,"eolFrom":"2028-06-10"},
              {"name":"10","label":"10","releaseDate":"2019-07-06","isLts":false,"isEol":true,"eolFrom":"2024-06-30"}]},
 {"name":"amazon-eks","label":"Amazon EKS","links":{"html":"https://endoflife.date/amazon-eks"},"identifiers":[],
  "releases":[{"name":"1.27","label":"1.27","releaseDate":"2023-05-24","isEol":true,"eolFrom":"2024-07-24"}]},
 {"name":"express","label":"Express","links":{"html":"https://endoflife.date/express"},"identifiers":[{"type":"purl","id":"pkg:npm/express"}],
  "releases":[{"name":"3","label":"3","releaseDate":"2012-10-23","isEol":true,"eolFrom":"2015-07-01"},
              {"name":"4","label":"4","releaseDate":"2014-04-09","isEol":false,"eolFrom":null}]}]}`

func setup(t *testing.T) (*store.Store, *Syncer, *Evaluator, *upstream) {
	t.Helper()
	st := store.New(testdb.New(t))
	up := &upstream{files: map[string][]byte{}}
	srv := httptest.NewServer(up)
	t.Cleanup(srv.Close)
	cfg := DefaultConfig()
	cfg.OSVBaseURL, cfg.KEVURL, cfg.EndOfLifeURL = srv.URL+"/osv", srv.URL+"/kev.json", srv.URL+"/eol.json"
	cfg.NpmRegistry, cfg.PackagistURL = srv.URL+"/npm", srv.URL+"/packagist"
	cfg.AmazonLinuxURL = srv.URL + "/al"
	cfg.MSRCURL = srv.URL + "/msrc"
	cfg.EPSSURL = srv.URL + "/epss_scores-current.csv.gz"
	cfg.WorkDir = t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return st, NewSyncer(st, log, cfg), &Evaluator{Store: st}, up
}

func ingest(t *testing.T, st *store.Store, kind model.AssetKind, id string, complete bool, obs ...model.Observation) int64 {
	t.Helper()
	b := model.NewBatch(model.Collector{ID: "t-" + string(kind), Method: "test"},
		model.AssetRef{Kind: kind, Name: id, Identifiers: []model.Identifier{{Scheme: "test", Value: id}}})
	b.Observations, b.Complete = obs, complete
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	r, err := st.Ingest(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), b, 0)
	if err != nil {
		t.Fatal(err)
	}
	return r.AssetID
}

func confirmed(purl string, ev map[string]string) model.Observation {
	return model.Observation{Purl: purl, Confidence: model.ConfidenceConfirmed, Evidence: ev}
}

func TestEndToEnd(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)

	app := ingest(t, st, model.AssetRepository, "shop", true,
		confirmed("pkg:npm/lodash@4.17.15", nil),
		confirmed("pkg:npm/express@3.21.2", nil),
		model.Observation{Purl: "pkg:npm/left-pad@1.0.0", Confidence: model.ConfidenceInferred},
		confirmed("pkg:pypi/django@1.0", nil), // no feed yet -> gap
	)
	host := ingest(t, st, model.AssetHost, "web-1", true,
		confirmed("pkg:generic/debian@10", map[string]string{"kind": "operating-system"}),
		confirmed("pkg:deb/debian/libssl3@3.0.11-1~deb12u1?distro=debian-12&upstream=openssl", nil),
		confirmed("pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12", nil),
	)
	eks := ingest(t, st, model.AssetManagedService, "eks-main", true,
		confirmed("pkg:generic/amazon-eks@1.27", map[string]string{"kind": "managed-service"}))

	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	feeds, _ := st.ListFeeds(ctx)
	names := map[string]bool{}
	for _, f := range feeds {
		names[f.Name] = true
	}
	for _, want := range []string{"osv:npm", "osv:Debian", "osv:PyPI", FeedKEV, FeedEPSS, FeedEndOfLife, FeedNpm, FeedPyPI} {
		if !names[want] {
			t.Errorf("feed %s not created: %v", want, names)
		}
	}
	if names["osv:Packagist"] {
		t.Error("no composer inventory, so no Packagist feed")
	}

	// Before any sync, nothing can be called clean.
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	gaps, n, _ := st.ListEvaluationGaps(ctx, store.Page{})
	if n != 7 { // lodash, express, left-pad, django, libssl3, openssl, managed EKS
		t.Errorf("gaps before sync = %d %+v", n, gaps)
	}

	up.set("/osv/npm/all.zip", zipOf(t, map[string]string{"GHSA-p6mc.json": ghsaLodash, "OSV-LODASH-1.json": osvLodashDup}))
	up.set("/osv/Debian/all.zip", zipOf(t, map[string]string{"DSA-5532-1.json": debOpenssl}))
	up.set("/kev.json", kev)
	up.set("/eol.json", eol)
	up.set("/epss_scores-current.csv.gz", gz(t, epssDay1))
	for _, f := range []string{FeedKEV, FeedEPSS, FeedEndOfLife, "osv:npm", "osv:Debian"} {
		if _, err := sy.Sync(ctx, f); err != nil {
			t.Fatalf("sync %s: %v", f, err)
		}
	}
	// The KEV sync keeps CISA's short description (digests show it).
	if adds, err := st.KEVAddedBetween(ctx, time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC), time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)); err != nil ||
		len(adds) != 1 || adds[0].ShortDescription != "lodash contains a prototype pollution vulnerability." {
		t.Errorf("KEV additions: %v %+v", err, adds)
	}
	if _, err := sy.Sync(ctx, "osv:PyPI"); err == nil {
		t.Error("PyPI archive is missing upstream; sync must report an error")
	}
	if f, _ := st.GetFeed(ctx, "osv:PyPI"); f.LastError == "" || !f.Stale {
		t.Errorf("failed feed must show its error and be stale: %+v", f)
	}

	stats, err := ev.Evaluate(ctx, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("stats %+v", stats)

	fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: app})
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]store.Finding{}
	for _, f := range fs {
		byKey[f.ComponentName+" "+f.Key] = f
	}
	lod, ok := byKey["lodash CVE-2021-23337"]
	if !ok {
		t.Fatalf("lodash finding missing: %+v", fs)
	}
	if len(lod.Sources) != 2 || lod.Severity != "high" || lod.FixedVersion != "4.17.21" || !lod.KnownExploited || lod.Verification != "confirmed" {
		t.Errorf("lodash = %+v", lod)
	}
	if e, ok := byKey["express express:3"]; !ok || e.Kind != "end_of_life" {
		t.Errorf("express 3 EOL finding missing: %+v", byKey)
	}
	if len(fs) != 2 {
		t.Errorf("app findings = %d: %+v", len(fs), byKey)
	}

	hf, _, _ := st.ListFindings(ctx, store.FindingFilter{AssetID: host})
	hk := map[string]store.Finding{}
	for _, f := range hf {
		hk[f.ComponentName+" "+f.Key] = f
	}
	if _, ok := hk["debian/libssl3 CVE-2023-5678"]; !ok {
		t.Errorf("libssl3 (source openssl) should match Debian:12 advisory: %+v", hk)
	}
	if _, ok := hk["debian/openssl CVE-2023-5678"]; ok {
		t.Error("openssl at the fixed backport version must not match")
	}
	if _, ok := hk["debian debian:10"]; !ok {
		t.Errorf("Debian 10 EOL finding missing: %+v", hk)
	}

	gaps, _, _ = st.ListEvaluationGaps(ctx, store.Page{})
	if len(gaps) != 2 {
		t.Errorf("django and the managed EKS engine should be gaps: %+v", gaps)
	}
	for _, g := range gaps {
		if strings.Contains(g.PurlKey, "amazon-eks") && !strings.Contains(g.Reason, "managed service") {
			t.Errorf("managed service gap reason = %q", g.Reason)
		}
	}
	if ef, _, _ := st.ListFindings(ctx, store.FindingFilter{AssetID: eks}); len(ef) != 1 || ef[0].Key != "amazon-eks:1.27" {
		t.Errorf("EKS 1.27 should be end-of-life by product name: %+v", ef)
	}

	// Upgrading lodash resolves its finding.
	ingest(t, st, model.AssetRepository, "shop", true,
		confirmed("pkg:npm/lodash@4.17.21", nil),
		confirmed("pkg:npm/express@3.21.2", nil),
	)
	if _, err := ev.Evaluate(ctx, nil, app); err != nil {
		t.Fatal(err)
	}
	all, _, _ := st.ListFindings(ctx, store.FindingFilter{Key: "CVE-2021-23337", Status: "all"})
	if len(all) != 1 || all[0].Status != "resolved" {
		t.Errorf("lodash finding should be resolved after upgrade: %+v", all)
	}

	// Incremental sync: a new advisory for express arrives.
	up.set("/osv/npm/modified_id.csv", time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)+",GHSA-expr\n2000-01-01T00:00:00Z,OLD\n")
	up.set("/osv/npm/GHSA-expr.json", `{"id":"GHSA-expr","modified":"2025-01-01T00:00:00Z","summary":"express open redirect",
	 "affected":[{"package":{"ecosystem":"npm","name":"express"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.19.2"}]}]}]}`)
	res, err := sy.Sync(ctx, "osv:npm")
	if err != nil {
		t.Fatal(err)
	}
	if res.Full || res.Changed != 1 {
		t.Errorf("expected incremental sync of 1 record, got %+v", res)
	}
	ids, err := ComponentsToEvaluate(ctx, st, "osv:npm", res)
	if err != nil || len(ids) != 1 {
		t.Fatalf("components to evaluate = %v %v", ids, err)
	}
	if _, err := ev.Evaluate(ctx, ids, 0); err != nil {
		t.Fatal(err)
	}
	if fs, _, _ := st.ListFindings(ctx, store.FindingFilter{Key: "GHSA-expr"}); len(fs) != 1 || fs[0].Severity != "unknown" {
		t.Errorf("express advisory: %+v", fs)
	}
	sum, _ := st.SummarizeFindings(ctx)
	if sum.StaleFeeds != 3 { // PyPI failed; releases:npm and releases:pypi never ran
		t.Errorf("summary = %+v", sum)
	}
}

func TestNeedsValidationHasNoSeverity(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	ingest(t, st, model.AssetSBOM, "vendor-sbom", true,
		model.Observation{Purl: "pkg:npm/lodash@4.17.15", Confidence: model.ConfidenceLow})
	_ = EnsureFeeds(ctx, st)
	up.set("/osv/npm/all.zip", zipOf(t, map[string]string{"a.json": ghsaLodash}))
	if _, err := sy.Sync(ctx, "osv:npm"); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	fs, _, _ := st.ListFindings(ctx, store.FindingFilter{})
	if len(fs) != 1 || fs[0].Verification != "needs_validation" || fs[0].Severity != "unknown" {
		t.Errorf("low-confidence finding = %+v", fs)
	}
}

func TestReleases(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, _, up := setup(t)
	ingest(t, st, model.AssetRepository, "r", true, confirmed("pkg:npm/%40babel/core@7.23.0", nil), confirmed("pkg:composer/laravel/framework@10.48.4", nil))
	_ = EnsureFeeds(ctx, st)
	up.set("/npm/@babel%2Fcore", `{"dist-tags":{"latest":"7.26.0","next":"8.0.0-beta.1"},
	  "time":{"created":"x","7.23.0":"2023-09-25T00:00:00Z","7.26.0":"2024-10-25T00:00:00Z","8.0.0-beta.1":"2025-01-01T00:00:00Z"},
	  "versions":{"7.23.0":{},"7.26.0":{},"8.0.0-beta.1":{}}}`)
	up.set("/packagist/p2/laravel/framework.json", `{"packages":{"laravel/framework":[
	  {"version":"v12.0.0-beta1","time":"2025-01-01T00:00:00+00:00"},{"version":"v11.9.2","time":"2024-06-01T00:00:00+00:00"},
	  {"version":"v10.48.4","time":"2024-03-01T00:00:00+00:00"}]}}`)
	for _, f := range []string{FeedNpm, FeedPackagist} {
		if _, err := sy.Sync(ctx, f); err != nil {
			t.Fatalf("%s: %v (requests %v)", f, err, up.requests)
		}
	}
	comps, _, _ := st.ListComponents(ctx, store.ComponentFilter{})
	for _, c := range comps {
		r, err := st.GetRelease(ctx, c.ID)
		if err != nil {
			t.Fatalf("%s: %v", c.PurlKey, err)
		}
		switch c.Type {
		case "npm":
			if r.LatestStable != "7.26.0" || r.LatestPublished == nil || r.LastError != "" {
				t.Errorf("npm release = %+v", r)
			}
		case "composer":
			if r.LatestStable != "11.9.2" || r.Latest != "12.0.0-beta1" {
				t.Errorf("composer release = %+v", r)
			}
		}
	}
}

// Field findings: Ubuntu Pro advisories and kernels that are not running.
func TestUbuntuProAndIdleKernels(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	b := model.NewBatch(model.Collector{ID: "linux-agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "help",
		Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "h"}}, Attributes: map[string]string{"kernel_running": "5.4.0-216-generic"}})
	for _, p := range []string{
		"pkg:deb/ubuntu/php7.4-cli@7.4.3-4ubuntu2.29?distro=ubuntu-20.04&upstream=php7.4",
		"pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.24?distro=ubuntu-20.04",
		"pkg:deb/ubuntu/linux-image-5.4.0-190-generic@5.4.0-190.210?distro=ubuntu-20.04&upstream=linux",
		"pkg:deb/ubuntu/linux-image-5.4.0-216-generic@5.4.0-216.236?distro=ubuntu-20.04&upstream=linux",
	} {
		b.Observations = append(b.Observations, model.Observation{Purl: p, Confidence: model.ConfidenceConfirmed, Scope: "os"})
	}
	b.Complete = true
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Ingest(ctx, b, 0); err != nil {
		t.Fatal(err)
	}
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	up.set("/osv/Ubuntu/all.zip", zipOf(t, map[string]string{
		// Fixed only in ESM: free channel has no record for this CVE.
		"pro-php.json": `{"id":"UBUNTU-CVE-2026-1","modified":"2026-01-01T00:00:00Z","upstream":["CVE-2026-1"],
		  "affected":[{"package":{"ecosystem":"Ubuntu:Pro:20.04:LTS","name":"php7.4"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"7.4.3-4ubuntu2.29+esm1"}]}]}]}`,
		// Free channel fixed it (installed is at the fix); the Pro record must not override that.
		"free-ssl.json": `{"id":"UBUNTU-CVE-2026-2","modified":"2026-01-01T00:00:00Z","upstream":["CVE-2026-2"],
		  "affected":[{"package":{"ecosystem":"Ubuntu:20.04:LTS","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.1.1f-1ubuntu2.24"}]}]}]}`,
		"pro-ssl.json": `{"id":"UBUNTU-PRO-CVE-2026-2","modified":"2026-01-01T00:00:00Z","upstream":["CVE-2026-2"],
		  "affected":[{"package":{"ecosystem":"Ubuntu:Pro:20.04:LTS","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.1.1f-1ubuntu2.24+esm1"}]}]}]}`,
		"kernel.json": `{"id":"UBUNTU-CVE-2024-36971","modified":"2026-01-01T00:00:00Z","upstream":["CVE-2024-36971"],
		  "affected":[{"package":{"ecosystem":"Ubuntu:20.04:LTS","name":"linux"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.4.0-192.212"}]}]}]}`,
	}))
	if _, err := sy.Sync(ctx, "osv:Ubuntu"); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	fs, _, err := st.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]store.Finding{}
	for _, f := range fs {
		got[f.ComponentName+" "+f.Key] = f
	}
	php, ok := got["ubuntu/php7.4-cli CVE-2026-1"]
	if !ok || php.FixedVersion != "7.4.3-4ubuntu2.29+esm1" || !strings.Contains(string(php.Evidence), `"requires_ubuntu_pro": true`) {
		t.Errorf("Pro-only PHP finding = %+v", php)
	}
	if _, ok := got["ubuntu/openssl CVE-2026-2"]; ok {
		t.Error("a Pro record must not contradict a fix the free channel provides")
	}
	old, ok := got["ubuntu/linux-image-5.4.0-190-generic CVE-2024-36971"]
	if !ok || !strings.Contains(string(old.Evidence), `"not_running_kernel": true`) {
		t.Errorf("old kernel finding = %+v", old)
	}
	// The evidence names what produced the verdict: the feed, the version
	// rules, the advisory ecosystem and the range that matched.
	var prov struct {
		Feed       string   `json:"feed"`
		Comparator string   `json:"comparator"`
		Ecosystems []string `json:"osv_ecosystems"`
		Ranges     []string `json:"matched_ranges"`
	}
	if err := json.Unmarshal(old.Evidence, &prov); err != nil || prov.Feed != "osv:Ubuntu" || prov.Comparator != "debian" ||
		len(prov.Ecosystems) != 1 || prov.Ecosystems[0] != "Ubuntu:20.04:LTS" || len(prov.Ranges) != 1 ||
		!strings.HasPrefix(prov.Ranges[0], "UBUNTU-CVE-2024-36971: ") || old.Verification != "confirmed" {
		t.Errorf("provenance = %+v (%v), verification %s", prov, err, old.Verification)
	}
	if _, ok := got["ubuntu/linux-image-5.4.0-216-generic CVE-2024-36971"]; ok {
		t.Error("the running, patched kernel must not be affected")
	}
}

// A runtime the agent found outside the package manager gets lifecycle
// findings by product name, and is listed as a vulnerability gap.
func TestUnmanagedRuntimeLifecycle(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	host := ingest(t, st, model.AssetHost, "web-1", true,
		confirmed("pkg:generic/nodejs@16.20.2", map[string]string{"kind": "runtime", "install": "unmanaged"}),
		confirmed("pkg:generic/nodejs@20.11.1", map[string]string{"kind": "runtime", "install": "unmanaged"}),
	)
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	up.set("/eol.json", `{"result":[{"name":"nodejs","label":"Node.js","links":{"html":"https://endoflife.date/nodejs"},"identifiers":[],
	  "releases":[{"name":"16","label":"16","releaseDate":"2021-04-20","isEol":true,"eolFrom":"2023-09-11"},
	              {"name":"20","label":"20","releaseDate":"2023-04-18","isEol":false,"eolFrom":"2026-04-30"}]}]}`)
	if _, err := sy.Sync(ctx, FeedEndOfLife); err != nil {
		t.Fatal(err)
	}
	ev.Now = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := ev.Evaluate(ctx, nil, host); err != nil {
		t.Fatal(err)
	}
	fs, _, _ := st.ListFindings(ctx, store.FindingFilter{AssetID: host})
	if len(fs) != 1 || fs[0].Key != "nodejs:16" || fs[0].Kind != "end_of_life" {
		t.Errorf("findings = %+v", fs)
	}
	gaps, _, _ := st.ListEvaluationGaps(ctx, store.Page{})
	if len(gaps) != 1 || !strings.Contains(gaps[0].Reason, "outside a package manager") {
		t.Errorf("gaps = %+v", gaps)
	}
}

func TestVersionedDebProduct(t *testing.T) {
	for key, want := range map[string]string{
		"pkg:deb/ubuntu/php7.4-common": "php 7.4",
		"pkg:deb/debian/php8.2-common": "php 8.2",
		"pkg:deb/ubuntu/ruby2.7":       "ruby 2.7",
		"pkg:deb/ubuntu/php7.4-fpm":    "",
		"pkg:deb/ubuntu/php-common":    "",
		"pkg:npm/php7.4-common":        "",
	} {
		p, c, ok := versionedDebProduct(key)
		got := ""
		if ok {
			got = p + " " + c
		}
		if got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}
