package intel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/collect/windows"
	"github.com/stackurity/stackurity/internal/fixplan"
	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/secondcheck"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// fakeNVD answers NVD's CVE API from testdata/winprograms/nvd, by
// virtualMatchString; a CPE without a file has no CVEs. broken makes a CPE's
// answer fail in the given way.
type fakeNVD struct {
	mu       sync.Mutex
	broken   map[string]string       // cpe -> "truncated", "error", "shrunk" or "drop:<CVE>"
	extra    map[string][]nvdWrapped // cpe -> CVEs served after the fixture's
	requests []nvdRequest
}

type nvdRequest struct{ cpe, since string }

var fixtureName = regexp.MustCompile(`[^a-z0-9.]+`)

func (n *fakeNVD) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	cpe := r.URL.Query().Get("virtualMatchString")
	n.requests = append(n.requests, nvdRequest{cpe, r.URL.Query().Get("lastModStartDate")})
	start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	page := nvdResponse{StartIndex: start}
	name := strings.Trim(fixtureName.ReplaceAllString(strings.ReplaceAll(strings.TrimPrefix(cpe, "cpe:2.3:a:"), ":*", ""), "_"), "_") + ".json"
	if b, err := os.ReadFile(filepath.Join("testdata", "winprograms", "nvd", name)); err == nil {
		if err := json.Unmarshal(b, &page); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	page.Vulnerabilities = append(page.Vulnerabilities, n.extra[cpe]...)
	all := len(page.Vulnerabilities)
	if start > 0 {
		page.Vulnerabilities = nil // the fixtures fit one page
	}
	page.StartIndex = start
	if drop, ok := strings.CutPrefix(n.broken[cpe], "drop:"); ok {
		page.Vulnerabilities = slices.DeleteFunc(page.Vulnerabilities, func(w nvdWrapped) bool { return w.CVE.ID == drop })
	}
	page.TotalResults = all
	if strings.HasPrefix(n.broken[cpe], "drop:") {
		page.TotalResults = len(page.Vulnerabilities)
	}
	switch n.broken[cpe] {
	case "error":
		// NVD refuses requests over its rate with 403.
		http.Error(w, "rate limited", 403)
		return
	case "truncated":
		page.TotalResults += 3 // NVD says there are more than it returned
	case "shrunk":
		page.Vulnerabilities, page.TotalResults = page.Vulnerabilities[:0], 0
	}
	_ = json.NewEncoder(w).Encode(page)
}

// fakeRegistry is a Windows registry as the agent reads it.
type fakeRegistry struct {
	os            map[string]string
	native, wow64 []map[string]string
}

func (f fakeRegistry) OSInfo() (map[string]string, error) { return f.os, nil }
func (f fakeRegistry) Uninstall(view string) ([]map[string]string, error) {
	if view == "wow64" {
		return f.wow64, nil
	}
	return f.native, nil
}
func (f fakeRegistry) MachineGUID() string { return "" }

// ingestRegistry runs the Windows agent's collector on a registry and
// ingests what it reports.
func ingestRegistry(t *testing.T, st *store.Store, host string, reg fakeRegistry) int64 {
	t.Helper()
	b, err := (&windows.Collector{Reg: reg, Version: "test"}).Collect(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	r, err := st.Ingest(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), b, 0)
	if err != nil {
		t.Fatal(err)
	}
	return r.AssetID
}

// programKeys returns an asset's open vulnerability findings on its
// installed programs (not on the Windows row itself), by key.
func programKeys(t *testing.T, st *store.Store, ctx context.Context, asset int64) map[string]store.Finding {
	t.Helper()
	out := map[string]store.Finding{}
	for _, f := range allFindings(t, st, ctx, asset) {
		if f.ComponentName != "windows" {
			out[f.Key] = f
		}
	}
	return out
}

// allFindings pages through an asset's open vulnerability findings.
func allFindings(t *testing.T, st *store.Store, ctx context.Context, asset int64) []store.Finding {
	t.Helper()
	var all []store.Finding
	for off := 0; ; off += 500 {
		fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: asset, Kind: "vulnerability", Page: store.Page{Limit: 500, Offset: off}})
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, fs...)
		if len(fs) < 500 {
			return all
		}
	}
}

func prog(name, publisher, version string) map[string]string {
	m := map[string]string{"DisplayName": name, "DisplayVersion": version}
	if publisher != "" {
		m["Publisher"] = publisher
	}
	return m
}

// setupPrograms serves every source the Windows program feeds read.
func setupPrograms(t *testing.T) (*store.Store, *Syncer, *Evaluator, *upstream, *fakeNVD) {
	t.Helper()
	st, sy, ev, up := setup(t)
	nvd := &fakeNVD{broken: map[string]string{}, extra: map[string][]nvdWrapped{}}
	srv := httptest.NewServer(nvd)
	t.Cleanup(srv.Close)
	sy.f.cfg.NVDURL, sy.f.cfg.NVDDelay, sy.f.cfg.NVDBackoff = srv.URL+"/rest/json/cves/2.0", 0, 0
	sy.f.cfg.MozillaURL = strings.TrimSuffix(sy.f.cfg.KEVURL, "/kev.json") + "/mfsa.tar.gz"
	for path, file := range map[string]string{"/mfsa.tar.gz": "mfsa.tar.gz", "/msrc/updates": "msrc-updates.json", "/msrc/cvrf/2026-Oct": "msrc-2026-Oct.json"} {
		b, err := os.ReadFile(filepath.Join("testdata", "winprograms", file))
		if err != nil {
			t.Fatal(err)
		}
		up.set(path, string(b))
	}
	sy.now = func() time.Time { return msrcNow }
	return st, sy, ev, up, nvd
}

var server2022 = map[string]string{"ProductName": "Windows Server 2022 Datacenter", "CurrentBuild": "20348", "UBR": "4294",
	"DisplayVersion": "21H2", "EditionID": "ServerDatacenter"}

func TestWindowsPrograms(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up, nvd := setupPrograms(t)

	// Registry entries as real installs write them (see
	// internal/winprograms/testdata/registry.json for their sources).
	hostA := ingestRegistry(t, st, "WIN-A", fakeRegistry{os: server2022,
		native: []map[string]string{
			prog("Google Chrome", "Google LLC", "138.0.7204.93"),
			prog("7-Zip 24.08 (x64)", "Igor Pavlov", "24.08"),
			prog("Microsoft Edge", "Microsoft Corporation", "154.0.4258.50"),
			prog("Mozilla Firefox ESR (x64 en-US)", "Mozilla", "128.3.0"),
			prog("Java 8 Update 491 (64-bit)", "Oracle Corporation", "8.0.4910.10"),
			prog("Contoso Line of Business App", "Contoso", "4.2"),
			prog("Zoom Workplace (64-bit)", "Zoom", "7.0.33767"),
			prog("Microsoft .NET Runtime - 8.0.20 (x64)", "Microsoft Corporation", "64.80.25123"),
			// A second .NET line installed side by side.
			prog("Microsoft .NET Runtime - 9.0.10 (x64)", "Microsoft Corporation", "72.40.25123"),
			prog("Adobe Acrobat (64-bit)", "Adobe", "24.001.30264"),
		},
		// 32-bit installs: the same 7-Zip and .NET runtime seen again.
		wow64: []map[string]string{
			prog("7-Zip 24.08", "Igor Pavlov", "24.08"),
			prog("Microsoft .NET Runtime - 8.0.20 (x86)", "Microsoft Corporation", "64.80.25123"),
			prog("Java Auto Updater", "Oracle Corporation", "2.8.491.10"),
		}})
	hostB := ingestRegistry(t, st, "WIN-B", fakeRegistry{os: server2022,
		native: []map[string]string{
			prog("Google Chrome", "", "151.0.7922.108"), // no publisher recorded
			prog("Mozilla Firefox (x64 en-US)", "Mozilla", "131.0.1"),
			prog("7-Zip 24.08 (x64)", "Igor Pavlov", "24.08"),
		}})

	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	if f, err := st.GetFeed(ctx, FeedWindowsPrograms); err != nil || f.Kind != "vulnerability" || f.RefreshMin != 360 {
		t.Fatalf("Windows hosts must create the %s feed: %+v %v", FeedWindowsPrograms, f, err)
	}
	up.set("/kev.json", `{"vulnerabilities":[{"cveID":"CVE-2025-6554","vendorProject":"Google","product":"Chromium V8","dateAdded":"2025-07-02"},
		{"cveID":"CVE-2024-9680","vendorProject":"Mozilla","product":"Firefox","dateAdded":"2024-10-15"},
		{"cveID":"CVE-2025-0411","vendorProject":"7-Zip","product":"7-Zip","dateAdded":"2025-02-06"}]}`)
	if _, err := sy.Sync(ctx, FeedKEV); err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureFeed(ctx, FeedEPSS, "prediction", 24*time.Hour, 72*time.Hour); err != nil {
		t.Fatal(err)
	}
	up.set("/epss_scores-current.csv.gz", gz(t, "#model_version:v2026.06.15,score_date:2026-10-28T00:00:00Z\ncve,epss,percentile\nCVE-2025-6554,0.61,0.99\n"))
	if _, err := sy.Sync(ctx, FeedEPSS); err != nil {
		t.Fatal(err)
	}
	// NVD names 7-Zip in a CVE it gives no fixed version: not matched,
	// and said so on the row.
	nvd.extra["cpe:2.3:a:7-zip:7-zip"] = []nvdWrapped{{CVE: nvdCVE{ID: "CVE-2026-99999", VulnStatus: "Analyzed",
		Configurations: []nvdConfig{{Nodes: []nvdNode{{Operator: "OR", CPEMatch: []nvdCPEMatch{{Vulnerable: true,
			Criteria: "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*", VersionStartIncluding: "24.00"}}}}}}}}}
	var reevaluate []int64
	sy.Changed = func(ctx context.Context, feed string, res *SyncResult) error {
		ids, err := ComponentsToEvaluate(ctx, st, feed, res)
		reevaluate = append(reevaluate, ids...)
		return err
	}
	if _, err := sy.Sync(ctx, FeedMSRC); err != nil {
		t.Fatal(err)
	}
	res, err := sy.Sync(ctx, FeedWindowsPrograms)
	if err != nil || res.Warning != "" {
		t.Fatalf("sync: %+v %v", res, err)
	}
	// Only the installed programs' sources are read: Chrome, 7-Zip and
	// Adobe (NVD), Firefox (Mozilla); never Zoom, whose version is unread
	// but whose source is still read, or programs nobody has.
	asked := map[string]bool{}
	for _, r := range nvd.requests {
		asked[r.cpe] = true
	}
	for _, cpe := range []string{"cpe:2.3:a:google:chrome", "cpe:2.3:a:7-zip:7-zip", "cpe:2.3:a:adobe:acrobat:*:*:*:*:classic"} {
		if !asked[cpe] {
			t.Errorf("%s was not read: %v", cpe, nvd.requests)
		}
	}
	if asked["cpe:2.3:a:wireshark:wireshark"] || asked["cpe:2.3:a:mozilla:firefox"] {
		t.Errorf("a program nobody has, or one read from Mozilla, was looked up in NVD: %v", nvd.requests)
	}
	f, _ := st.GetFeed(ctx, FeedWindowsPrograms)
	for _, eco := range []string{"Windows programs:google-chrome", "Windows programs:mozilla-firefox-esr", "Windows programs:adobe-acrobat-classic"} {
		if !slices.Contains(f.Ecosystems, eco) {
			t.Errorf("feed ecosystems %v lack %s", f.Ecosystems, eco)
		}
	}
	if m, _ := st.GetFeed(ctx, FeedMSRC); !slices.Contains(m.Ecosystems, "Windows programs:microsoft-edge") || !slices.Contains(m.Ecosystems, "Windows programs:dotnet-runtime") {
		t.Errorf("msrc ecosystems %v", m.Ecosystems)
	}
	if len(reevaluate) == 0 {
		t.Error("the syncs queued no re-evaluation")
	}

	now := msrcNow
	ev.Now = func() time.Time { return now }
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}

	a := programKeys(t, st, ctx, hostA)
	for key, fixed := range map[string]string{
		"CVE-2025-6554":   "138.0.7204.96", // Windows' fix; macOS and Linux got .92
		"CVE-2026-118359": "156.0.8078.73",
		"CVE-2025-0411":   "24.09",
		"CVE-2026-14266":  "26.02",
		"CVE-2026-102299": "154.0.4258.53",
		"CVE-2026-110144": "",             // 154 is on neither listed line (152, 155): needs validation
		"CVE-2026-81997":  "24.001.30429", // the Classic track's fix, not Continuous'
		"CVE-2024-9680":   "128.3.1",
	} {
		if g, ok := a[key]; !ok || g.FixedVersion != fixed {
			t.Errorf("WIN-A %s: fixed %q, want %q", key, g.FixedVersion, fixed)
		}
	}
	for _, key := range []string{"CVE-2025-2783", "CVE-2025-0435", "CVE-2024-20726", "CVE-2026-114148"} {
		if _, ok := a[key]; ok {
			t.Errorf("WIN-A must not have %s", key)
		}
	}
	if g := a["CVE-2025-6554"]; !g.KnownExploited || g.EPSS == nil || *g.EPSS != 0.61 || g.Verification != "confirmed" {
		t.Errorf("Chrome KEV finding: KEV %v, EPSS %v, %s", g.KnownExploited, g.EPSS, g.Verification)
	}
	// Each .NET line gets its own line's fix.
	for _, f := range allFindings(t, st, ctx, hostA) {
		want := map[string]string{"Microsoft .NET Runtime - 8.0.20 (x64)": "8.0.32", "Microsoft .NET Runtime - 9.0.10 (x64)": "9.0.21"}[f.ComponentName]
		if f.Key == "CVE-2026-105016" && f.ComponentName != "windows" && f.FixedVersion != want {
			t.Errorf("%s: fixed %q, want %q", f.ComponentName, f.FixedVersion, want)
		}
	}
	if g := a["CVE-2026-110144"]; g.Verification != "needs_validation" || g.Severity != "unknown" || !strings.Contains(string(g.Evidence), "version_line_unlisted") {
		t.Errorf("Edge on no listed line: %s %s %s", g.Verification, g.Severity, g.Evidence)
	}
	if !a["CVE-2025-0411"].KnownExploited || !a["CVE-2024-9680"].KnownExploited {
		t.Error("7-Zip and Firefox KEV findings must say so")
	}
	var evidence map[string]any
	_ = json.Unmarshal(a["CVE-2025-6554"].Evidence, &evidence)
	if evidence["program"] != "google-chrome" || evidence["program_label"] != "Google Chrome" || evidence["catalogue_version"] == "" ||
		evidence["target_ecosystem"] != "Windows programs:google-chrome" {
		t.Errorf("evidence %v", evidence)
	}

	// 32- and 64-bit entries of one installation: one finding per issue.
	count := func(asset int64, key string) int {
		n := 0
		for _, f := range allFindings(t, st, ctx, asset) {
			if f.Key == key && f.ComponentName != "windows" {
				n++
			}
		}
		return n
	}
	// .NET 8 (x64 and x86 entries: once) and .NET 9: one finding per line.
	if n, m := count(hostA, "CVE-2025-0411"), count(hostA, "CVE-2026-105016"); n != 1 || m != 2 {
		t.Errorf("7-Zip findings %d, .NET findings %d: the duplicate registry entries must be reported once", n, m)
	}

	// Coverage: nothing looks clean by default.
	cov := map[string]store.InventoryRow{}
	rows, _, err := st.ListInventory(ctx, store.InventoryFilter{AssetID: hostA, Page: store.Page{Limit: 100}})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		cov[r.Name] = r
	}
	for name, want := range map[string]struct{ state, words string }{
		"Java 8 Update 491 (64-bit)":            {store.CoverageUnsupported, "recognised as Oracle Java SE by the curated catalogue, but not matched"},
		"Java Auto Updater":                     {store.CoverageUnsupported, "not in the curated catalogue of Windows programs"},
		"Contoso Line of Business App":          {store.CoverageUnsupported, "not in the curated catalogue of Windows programs"},
		"Zoom Workplace (64-bit)":               {store.CoverageNotEvaluated, `the version "7.0.33767" of Zoom Workplace is not in the form`},
		"7-Zip 24.08":                           {store.CoverageEvaluated, `the same 7-Zip 24.08 as "7-Zip 24.08 (x64)"`},
		"7-Zip 24.08 (x64)":                     {store.CoverageEvaluated, "NVD also names 7-Zip in 1 CVE with no fixed version or no version bound, which are not matched; NVD has not analysed most of 7-Zip's recent CVEs"},
		"Google Chrome":                         {store.CoverageEvaluated, ""},
		"Microsoft .NET Runtime - 8.0.20 (x86)": {store.CoverageEvaluated, "the same .NET Runtime 8.0.20"},
	} {
		r, ok := cov[name]
		if !ok || r.Coverage != want.state || !strings.Contains(r.CoverageReason, want.words) {
			t.Errorf("%s: coverage %s %q, want %s with %q", name, r.Coverage, r.CoverageReason, want.state, want.words)
		}
	}

	b := programKeys(t, st, ctx, hostB)
	if g := b["CVE-2026-118359"]; g.Verification != "needs_validation" || g.Severity != "unknown" || g.FixedVersion != "156.0.8078.73" {
		t.Errorf("Chrome without a publisher: %s %s %s", g.Verification, g.Severity, g.FixedVersion)
	}
	if g := b["CVE-2024-9680"]; g.FixedVersion != "131.0.2" {
		t.Errorf("Firefox CVE-2024-9680 fixed %q", g.FixedVersion)
	}

	// The coverage-gap report counts the programs not matched, by why.
	rep, err := CoverageGaps(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	gaps := map[string]int64{}
	for _, g := range rep.NoVulnerabilitySource {
		if g.Label == "Windows programs" {
			gaps[g.Kind] = g.Components
		}
	}
	if gaps["generic|windows_program"] != 2 || gaps["generic|windows_program_unmatched"] != 1 {
		t.Errorf("Windows program gaps = %v", gaps)
	}

	// The action plan: "Update <program> to <version>" per host, one fix
	// across hosts for the same program and version.
	if _, err := planner.Rebuild(ctx, st, now); err != nil {
		t.Fatal(err)
	}
	groups := func(asset int64) map[string]fixplan.Group {
		t.Helper()
		raw, _, err := st.ListFixGroups(ctx, store.FixGroupFilter{AssetID: asset, Kind: fixplan.ProgramUpdate})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]fixplan.Group{}
		for _, r := range raw {
			var g fixplan.Group
			_ = json.Unmarshal(r, &g)
			out[g.Component] = g
		}
		return out
	}
	ga, gb := groups(hostA), groups(hostB)
	if g := ga["7-Zip"]; g.Title != "Update 7-Zip to 26.02" || g.FixKey != "program_update:7-zip>26.02" || g.FromVersion != "24.08" ||
		g.FindingCount != 3 || g.KnownExploited != 1 || !strings.Contains(g.Action, "7-zip.org") {
		t.Errorf("7-Zip on WIN-A: %+v", g)
	}
	if gb["7-Zip"].FixKey != ga["7-Zip"].FixKey {
		t.Errorf("one 7-Zip fix across hosts: %q %q", gb["7-Zip"].FixKey, ga["7-Zip"].FixKey)
	}
	for label, title := range map[string]string{
		"Google Chrome":  "Update Google Chrome to 156.0.8078.73",
		"Microsoft Edge": "Update Microsoft Edge to 154.0.4258.53", // not Stable's 155 fix: 154 is on no listed line
		// One update per side-by-side line, never "update to 9.0.21" for both.
		".NET Runtime 8": "Update .NET Runtime 8 to 8.0.32",
		".NET Runtime 9": "Update .NET Runtime 9 to 9.0.21",
		// 128 is past its line's fix for the ESR 153/115 CVEs: needs validation, not "update to 153.6".
		"Mozilla Firefox ESR":                        "Update Mozilla Firefox ESR to 128.3.1",
		"Adobe Acrobat and Acrobat Reader (Classic)": "Update Adobe Acrobat and Acrobat Reader (Classic) to 24.001.30429",
	} {
		if g := ga[label]; g.Title != title {
			t.Errorf("WIN-A %s: %q", label, g.Title)
		}
	}
	if g8, g9 := ga[".NET Runtime 8"], ga[".NET Runtime 9"]; g8.FixKey != "program_update:dotnet-runtime@8>8.0.32" || g8.FromVersion != "8.0.20" ||
		g9.FixKey != "program_update:dotnet-runtime@9>9.0.21" || g9.FromVersion != "9.0.10" {
		t.Errorf(".NET groups: %+v %+v", g8, g9)
	}
	if g := gb["Mozilla Firefox"]; g.Title != "Update Mozilla Firefox to 159" {
		t.Errorf("WIN-B Firefox: %q", g.Title)
	}

	// The second check re-derives every finding with its own reading of
	// the catalogue.
	stats, err := (&secondcheck.Runner{Store: st, All: true, Batch: 5000}).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("second check: %+v", stats)
	if stats.Checked < 300 || stats.Agreed != stats.Checked {
		for _, h := range []int64{hostA, hostB} {
			for _, g := range allFindings(t, st, ctx, h) {
				if sc, _ := st.FindingSecondCheck(ctx, g.ID); sc != nil && sc.Result != store.SecondCheckAgreed {
					t.Errorf("second check on %s %s: %+v", g.ComponentName, g.Key, sc)
				}
			}
		}
		t.Errorf("second check: %+v", stats)
	}
}

// One source failing only warns; a truncated or shrunk answer is refused and
// the stored advisories kept; everything failing fails the sync.
func TestWindowsProgramsBadSources(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up, nvd := setupPrograms(t)
	host := ingestRegistry(t, st, "WIN-C", fakeRegistry{os: server2022, native: []map[string]string{
		prog("Google Chrome", "Google LLC", "138.0.7204.93"),
		prog("7-Zip 24.08 (x64)", "Igor Pavlov", "24.08"),
		prog("Mozilla Firefox (x64 en-US)", "Mozilla", "131.0.1"),
	}})
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	evaluate := func() map[string]store.Finding {
		t.Helper()
		if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
			t.Fatal(err)
		}
		return openKeys(t, st, ctx, host)
	}
	coverage := func(name string) store.InventoryRow {
		t.Helper()
		rows, _, err := st.ListInventory(ctx, store.InventoryFilter{AssetID: host, Page: store.Page{Limit: 100}})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.Name == name {
				return r
			}
		}
		t.Fatalf("no %s", name)
		return store.InventoryRow{}
	}

	// First sync: Chrome's answer is truncated. 7-Zip and Firefox are
	// stored and evaluated; Chrome is not evaluated, never clean.
	nvd.broken["cpe:2.3:a:google:chrome"] = "truncated"
	res, err := sy.Sync(ctx, FeedWindowsPrograms)
	if err != nil || !strings.Contains(res.Warning, "Google Chrome") || !strings.Contains(res.Warning, "truncated") {
		t.Fatalf("one bad source must only warn: %+v %v", res, err)
	}
	if f, _ := st.GetFeed(ctx, FeedWindowsPrograms); !strings.Contains(f.LastError, "Google Chrome") || f.LastSuccess == nil {
		t.Errorf("feed %+v", f)
	}
	got := evaluate()
	if _, ok := got["CVE-2025-0411"]; !ok {
		t.Errorf("7-Zip was not evaluated: %s", sortedFindingKeys(got))
	}
	if r := coverage("Google Chrome"); r.Coverage != store.CoverageNotEvaluated || !strings.Contains(r.CoverageReason, "have not been read from NVD") {
		t.Errorf("Chrome coverage %s %q", r.Coverage, r.CoverageReason)
	}

	// Chrome reads; the warning clears.
	delete(nvd.broken, "cpe:2.3:a:google:chrome")
	if res, err := sy.Sync(ctx, FeedWindowsPrograms); err != nil || res.Warning != "" {
		t.Fatalf("%+v %v", res, err)
	}
	got = evaluate()
	if _, ok := got["CVE-2025-6554"]; !ok {
		t.Fatalf("Chrome findings: %s", sortedFindingKeys(got))
	}

	// A full read that lost Chrome's CVEs is refused; the findings stay.
	sy.now = func() time.Time { return msrcNow.Add(8 * 24 * time.Hour) } // past the weekly full read
	nvd.broken["cpe:2.3:a:google:chrome"] = "shrunk"
	res, err = sy.Sync(ctx, FeedWindowsPrograms)
	if err != nil || !strings.Contains(res.Warning, "refusing an answer that lost more than half") {
		t.Fatalf("shrunk: %+v %v", res, err)
	}
	ev.Now = sy.now
	if got := evaluate(); got["CVE-2025-6554"].ID == 0 {
		t.Error("a refused answer must keep the stored advisories and findings")
	}

	// A broken Mozilla archive only warns.
	up.set("/mfsa.tar.gz", "<html>rate limited</html>")
	delete(nvd.broken, "cpe:2.3:a:google:chrome")
	if res, err := sy.Sync(ctx, FeedWindowsPrograms); err != nil || !strings.Contains(res.Warning, "Mozilla Firefox") {
		t.Fatalf("broken Mozilla archive: %+v %v", res, err)
	}

	// Everything failing fails the sync and keeps the cursor.
	before, _ := st.GetFeed(ctx, FeedWindowsPrograms)
	nvd.broken["cpe:2.3:a:google:chrome"], nvd.broken["cpe:2.3:a:7-zip:7-zip"] = "error", "error"
	if _, err := sy.Sync(ctx, FeedWindowsPrograms); err == nil || !strings.Contains(err.Error(), "no Windows program's advisories could be read") {
		t.Fatalf("all failing: %v", err)
	}
	if after, _ := st.GetFeed(ctx, FeedWindowsPrograms); after.Cursor != before.Cursor {
		t.Error("a failed sync must keep the cursor")
	}

	// A CVE the source no longer lists is withdrawn on the next full read.
	for k := range nvd.broken {
		delete(nvd.broken, k)
	}
	b, _ := os.ReadFile(filepath.Join("testdata", "winprograms", "mfsa.tar.gz"))
	up.set("/mfsa.tar.gz", string(b))
	ids, _ := st.AdvisoryIDs(ctx, FeedWindowsPrograms, nvdPrefix("7-zip"))
	if len(ids) != 3 {
		t.Fatalf("7-Zip advisories %v", ids)
	}
	sy.now = func() time.Time { return msrcNow.Add(16 * 24 * time.Hour) }
	nvd.broken["cpe:2.3:a:7-zip:7-zip"] = "drop:CVE-2026-48103"
	if _, err := sy.Sync(ctx, FeedWindowsPrograms); err != nil {
		t.Fatal(err)
	}
	if ids, _ := st.AdvisoryIDs(ctx, FeedWindowsPrograms, nvdPrefix("7-zip")); len(ids) != 2 || slices.Contains(ids, "NVD-7-zip-CVE-2026-48103") {
		t.Errorf("after the drop: %v", ids)
	}
	ev.Now = sy.now
	if _, ok := evaluate()["CVE-2026-48103"]; ok {
		t.Error("the withdrawn CVE's finding must close")
	}
}
