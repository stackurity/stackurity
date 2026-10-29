package intel

import (
	"compress/bzip2"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/secondcheck"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/version"
)

// The fixtures are real ELSA OVAL files from linux.oracle.com/security/oval,
// trimmed by testdata/elsa/trim.py to a few definitions (see its KEEP list).

func elsaFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "elsa", "com.oracle.elsa-"+name+".xml.bz2"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseELSAFixture(t *testing.T, name, release string) map[string]*osv.Vulnerability {
	t.Helper()
	doc, err := parseELSA(bzip2.NewReader(strings.NewReader(string(elsaFixture(t, name)))), release)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if doc.anomalies != 0 {
		t.Errorf("%s: %d criteria not understood", name, doc.anomalies)
	}
	out := map[string]*osv.Vulnerability{}
	for _, v := range doc.vulns {
		out[v.ID] = v
	}
	return out
}

// entries lists an advisory's affected entries as "ecosystem name introduced fixed".
func entries(v *osv.Vulnerability) []string {
	var out []string
	for _, a := range v.Affected {
		ev := a.Ranges[0].Events
		out = append(out, a.Package.Ecosystem+" "+a.Package.Name+" "+ev[0].Introduced+" "+ev[1].Fixed)
	}
	return out
}

func hasEntry(v *osv.Vulnerability, want string) bool {
	return v != nil && slices.Contains(entries(v), want)
}

func TestParseELSA(t *testing.T) {
	ol9 := parseELSAFixture(t, "ol9", "9")
	if len(ol9) != 8 {
		t.Errorf("Oracle Linux 9: %d advisories, want 8: %v", len(ol9), keys(ol9))
	}
	glibc := ol9["OL9-ELSA-2023-12850"]
	if glibc == nil {
		t.Fatalf("OL9-ELSA-2023-12850 missing: %v", keys(ol9))
	}
	// One entry per package, the Oracle rebuild's own version (.0.3).
	if e := entries(glibc); len(e) == 0 || !hasEntry(glibc, "Oracle Linux:9 glibc 0 0:2.34-60.0.3.el9") {
		t.Errorf("glibc entries = %v", e)
	}
	if !slices.Equal(glibc.Aliases, []string{"ELSA-2023-12850", "CVE-2023-4911"}) || osv.GroupKey(glibc.ID, glibc.Aliases) != "CVE-2023-4911" {
		t.Errorf("aliases = %v", glibc.Aliases)
	}
	if glibc.Summary != "glibc security update (IMPORTANT)" || glibc.Published.Format("2006-01-02") != "2023-10-05" ||
		string(glibc.DatabaseSpecific) != `{"severity":"IMPORTANT"}` || len(glibc.Severity) != 1 || !strings.HasPrefix(glibc.Severity[0].Score, "CVSS:3.0/") {
		t.Errorf("metadata = %q %v %s %v", glibc.Summary, glibc.Published, glibc.DatabaseSpecific, glibc.Severity)
	}
	if r := osv.Rate(glibc); r.Level != "high" {
		t.Errorf("rating = %+v", r)
	}
	if len(glibc.References) != 2 || glibc.References[0].URL != "https://linux.oracle.com/errata/ELSA-2023-12850.html" ||
		glibc.References[1].URL != "https://linux.oracle.com/cve/CVE-2023-4911.html" {
		t.Errorf("references = %v", glibc.References)
	}
	// The Ksplice build of the same fix has epoch 2: its own channel.
	if v := ol9["OL9-ELSA-2023-12854"]; !hasEntry(v, "Oracle Linux:9:ksplice glibc 0 2:2.34-60.0.3.ksplice1.el9") ||
		slices.ContainsFunc(entries(v), func(e string) bool { return strings.HasPrefix(e, "Oracle Linux:9 ") }) {
		t.Errorf("Ksplice entries = %v", entries(v))
	}
	// FIPS builds (epoch 10) too.
	if v := ol9["OL9-ELSA-2024-12336"]; !hasEntry(v, "Oracle Linux:9:fips gnutls 0 10:3.7.6-23.el9_3.4_fips") {
		t.Errorf("FIPS entries = %v", entries(v))
	}
	// Two fixes listed for one package: the higher one.
	if v := ol9["OL9-ELSA-2023-2650"]; !hasEntry(v, "Oracle Linux:9 curl 0 0:7.76.1-23.el9_2.1") || hasEntry(v, "Oracle Linux:9 curl 0 0:7.76.1-23.el9") {
		t.Errorf("curl entries = %v", entries(v))
	}
	// One UEK R7 definition covers Oracle Linux 8 and 9: this file gives the
	// Oracle Linux 9 branch only, limited to the 5.15.0 line.
	uek7 := ol9["OL9-ELSA-2023-12017"]
	if !hasEntry(uek7, "Oracle Linux:9 kernel-uek 0:5.15.0 0:5.15.0-6.80.3.1.el9uek") || !hasEntry(uek7, "Oracle Linux:9 bpftool 0:5.15.0 0:5.15.0-6.80.3.1.el9uek") {
		t.Errorf("UEK R7 entries = %v", entries(uek7))
	}
	for _, e := range entries(uek7) {
		if strings.Contains(e, "el8uek") {
			t.Errorf("an Oracle Linux 8 branch in the Oracle Linux 9 advisory: %s", e)
		}
	}
	if v := ol9["OL9-ELSA-2025-20368"]; !hasEntry(v, "Oracle Linux:9 kernel-uek 0:6.12.0 0:6.12.0-100.28.2.el9uek") {
		t.Errorf("UEK R8 entries = %v", entries(v))
	}
	// Module streams whose name is the version line limit their packages.
	if v := ol9["OL9-ELSA-2024-1503"]; !hasEntry(v, "Oracle Linux:9 nodejs 1:18 1:18.19.1-1.module+el9.3.0+90193+90aa0dae") {
		t.Errorf("nodejs:18 entries = %v", entries(v))
	}
	if v := ol9["OL9-ELSA-2024-1688"]; !hasEntry(v, "Oracle Linux:9 nodejs 1:20 1:20.11.1-1.module+el9.3.0+90254+3f4d3ee1") {
		t.Errorf("nodejs:20 entries = %v", entries(v))
	}

	ol8 := parseELSAFixture(t, "ol8", "8")
	if len(ol8) != 8 {
		t.Errorf("Oracle Linux 8: %d advisories, want 8: %v", len(ol8), keys(ol8))
	}
	if v := ol8["OL8-ELSA-2023-12017"]; !hasEntry(v, "Oracle Linux:8 kernel-uek 0:5.15.0 0:5.15.0-6.80.3.1.el8uek") {
		t.Errorf("UEK R7 on Oracle Linux 8 = %v", entries(v))
	}
	if v := ol8["OL8-ELSA-2020-5848"]; !hasEntry(v, "Oracle Linux:8 kernel-uek 0:5.4.17 0:5.4.17-2011.6.2.el8uek") {
		t.Errorf("UEK R6 on Oracle Linux 8 = %v", entries(v))
	}
	if v := ol8["OL8-ELSA-2021-0218"]; !slices.Equal(entries(v), []string{"Oracle Linux:8 sudo 0 0:1.8.29-6.el8_3.1"}) {
		t.Errorf("sudo (listed twice) = %v", entries(v))
	}
	if v := ol8["OL8-ELSA-2023-12853"]; !hasEntry(v, "Oracle Linux:8:ksplice glibc 0 2:2.28-225.0.4.ksplice1.el8") {
		t.Errorf("Ksplice on Oracle Linux 8 = %v", entries(v))
	}
	if v := ol8["OL8-ELSA-2024-12135"]; !hasEntry(v, "Oracle Linux:8:fips gnutls 0 10:3.6.16-8.el8_9.1_fips") {
		t.Errorf("FIPS on Oracle Linux 8 = %v", entries(v))
	}

	// A version line given as a regular expression ("^1\.20\.").
	if v := parseELSAFixture(t, "ol7", "7")["OL7-ELSA-2022-9228"]; !hasEntry(v, "Oracle Linux:7 cri-o 0:1.20 0:1.20.7-1.el7") {
		t.Errorf("Oracle Linux 7 cri-o = %v", entries(v))
	}
	if v := parseELSAFixture(t, "ol10", "10")["OL10-ELSA-2025-20371"]; !hasEntry(v, "Oracle Linux:10 kernel-uek 0:6.12.0 0:6.12.0-100.28.2.el10uek") {
		t.Errorf("Oracle Linux 10 UEK = %v", entries(v))
	}
	// The Oracle Linux 9 file read for Oracle Linux 8 gives only the
	// definitions with an Oracle Linux 8 branch.
	if other := parseELSAFixture(t, "ol9", "8"); len(other) != 1 || other["OL8-ELSA-2023-12017"] == nil {
		t.Errorf("Oracle Linux 8 branches of the Oracle Linux 9 file: %v", keys(other))
	}
}

func TestParseELSARefusesBrokenFiles(t *testing.T) {
	var xmlDoc strings.Builder
	if _, err := io.Copy(&xmlDoc, bzip2.NewReader(strings.NewReader(string(elsaFixture(t, "ol9"))))); err != nil {
		t.Fatal(err)
	}
	full := xmlDoc.String()
	for name, doc := range map[string]string{
		"truncated XML":    full[:len(full)/2],
		"no closing root":  strings.TrimSuffix(strings.TrimSpace(full), "</oval_definitions>"),
		"not OVAL":         `<html><body>maintenance</body></html>`,
		"no definitions":   `<oval_definitions><definitions></definitions></oval_definitions>`,
		"bug fixes only":   `<oval_definitions><definitions><definition class="patch"><metadata><reference source="elba" ref_id="ELBA-2025-1"/></metadata></definition></definitions></oval_definitions>`,
		"empty":            ``,
		"truncated bzip2":  "bz2:" + string(elsaFixture(t, "ol9")[:len(elsaFixture(t, "ol9"))/2]),
		"corrupted bzip2":  "bz2:" + corrupt(elsaFixture(t, "ol9")),
		"plain text 'bz2'": "bz2:not bzip2 at all",
	} {
		var r io.Reader = strings.NewReader(doc)
		if b, ok := strings.CutPrefix(doc, "bz2:"); ok {
			r = bzip2.NewReader(strings.NewReader(b))
		}
		if d, err := parseELSA(r, "9"); err == nil {
			t.Errorf("%s: read as %d advisories", name, len(d.vulns))
		}
	}
	// Over the size limit: an error, never a partial read.
	cr := &elsaCapReader{r: strings.NewReader(full), left: 1000, what: "uncompressed ELSA file"}
	if _, err := parseELSA(cr, "9"); err == nil || !strings.Contains(err.Error(), "larger than the limit") {
		t.Errorf("over the limit: %v", err)
	}
}

func corrupt(b []byte) string {
	c := slices.Clone(b)
	c[len(c)/2] ^= 0xff
	return string(c)
}

// TestOracleLinuxVersions compares Oracle Linux versions the way the matcher
// does: rpm rules with epoch, Oracle's ".0.1" rebuilds of Red Hat packages
// and UEK and module lines.
func TestOracleLinuxVersions(t *testing.T) {
	affected := func(installed, introduced, fixed string) bool {
		t.Helper()
		m, err := osv.Check(osv.Affected{Ranges: []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: introduced}, {Fixed: fixed}}}}},
			osv.Target{Ecosystem: "Oracle Linux:9", Version: installed, Compare: version.RPM})
		if err != nil {
			t.Fatalf("%s: %v", installed, err)
		}
		return m.Affected
	}
	for _, c := range []struct {
		installed, introduced, fixed string
		want                         bool
		why                          string
	}{
		{"0:2.34-60.0.2.el9", "0", "0:2.34-60.0.3.el9", true, "an older Oracle rebuild"},
		{"0:2.34-60.0.3.el9", "0", "0:2.34-60.0.3.el9", false, "the fixed rebuild"},
		{"0:2.34-60.el9", "0", "0:2.34-60.0.3.el9", true, "Red Hat's build the rebuild is based on"},
		{"0:2.34-60.0.3.el9_2.7", "0", "0:2.34-60.0.3.el9", false, "a later z-stream rebuild"},
		{"0:7.76.1-23.0.1.el9_2.1", "0", "0:7.76.1-23.el9_2.1", false, "Oracle's .0.1 rebuild of the fixed Red Hat build"},
		{"0:7.76.1-23.el9", "0", "0:7.76.1-23.el9_2.1", true, "below the z-stream fix"},
		{"2.34-60.0.3.el9", "0", "1:2.34-1.el9", true, "a higher epoch wins whatever the version"},
		{"1:1.0.2k-26.el7_9", "0", "1:1.0.2k-25.el7_9", false, "same epoch, newer release"},
		// UEK: each line is its own range.
		{"0:5.15.0-6.80.3.el9uek", "0:5.15.0", "0:5.15.0-6.80.3.1.el9uek", true, "UEK R7 below the R7 fix"},
		{"0:6.12.0-100.28.1.el9uek", "0:5.15.0", "0:5.15.0-6.80.3.1.el9uek", false, "UEK R8 is past every R7 fix"},
		{"0:5.15.0-6.80.3.el9uek", "0:6.12.0", "0:6.12.0-100.28.2.el9uek", false, "UEK R7 is not on the R8 line"},
		{"0:4.18.0-477.10.1.el8_8", "0:5.15.0", "0:5.15.0-6.80.3.1.el8uek", false, "RHCK's bpftool is not UEK's"},
		{"0:5.4.17-2011.5.3.el8uek", "0:5.4.17", "0:5.4.17-2011.6.2.el8uek", true, "UEK R6 below its fix"},
		// Module streams.
		{"1:18.18.2-1.module+el9.3.0+90100+a1b2c3d4", "1:18", "1:18.19.1-1.module+el9.3.0+90193+90aa0dae", true, "nodejs:18 below its fix"},
		{"1:20.10.0-1.module+el9.3.0+90200+a1b2c3d4", "1:18", "1:18.19.1-1.module+el9.3.0+90193+90aa0dae", false, "nodejs:20 is past nodejs:18"},
		{"1:18.18.2-1.module+el9.3.0+90100+a1b2c3d4", "1:20", "1:20.11.1-1.module+el9.3.0+90254+3f4d3ee1", false, "nodejs:18 is not on the nodejs:20 line"},
		{"1:16.20.2-1.module+el9.3.0+90100+a1b2c3d4", "1:18", "1:18.19.1-1.module+el9.3.0+90193+90aa0dae", false, "nodejs:16 is not on the nodejs:18 line"},
	} {
		if got := affected(c.installed, c.introduced, c.fixed); got != c.want {
			t.Errorf("%s (%s against %s..%s): affected = %v", c.why, c.installed, c.introduced, c.fixed, got)
		}
	}
	for v, want := range map[string]string{"2:2.34-60.0.3.ksplice1.el9": "ksplice", "10:3.5.8-2.0.1.el9_8_fips": "fips", "0:2.34-60.0.3.el9": ""} {
		if got := osv.OracleBuild(v); got != want {
			t.Errorf("OracleBuild(%s) = %q", v, got)
		}
	}
	for eco, want := range map[string]bool{"Oracle Linux:9": true, "Oracle Linux:9:ksplice": true, "Oracle Linux:9:fips": true,
		"Oracle Linux:8": false, "Oracle Linux:90": false, "Red Hat:enterprise_linux:9": false} {
		if got := osv.MatchEcosystem(eco, "Oracle Linux:9"); got != want {
			t.Errorf("MatchEcosystem(%s, Oracle Linux:9) = %v", eco, got)
		}
	}
}

// serveELSA serves fixtures as Oracle's release files ("ol9" as
// com.oracle.elsa-ol9.xml.bz2); a missing name is removed.
func serveELSA(t *testing.T, up *upstream, files map[string]string) {
	t.Helper()
	for rel, fixture := range files {
		path := "/oval/com.oracle.elsa-" + rel + ".xml.bz2"
		up.mu.Lock()
		delete(up.files, path)
		up.mu.Unlock()
		if fixture != "" {
			up.set(path, string(elsaFixture(t, fixture)))
		}
	}
}

func olHost(t *testing.T, st *store.Store, name, distro string, pkgs ...string) int64 {
	t.Helper()
	var obs []model.Observation
	for _, p := range pkgs { // name@evr
		n, evr, _ := strings.Cut(p, "@")
		ver := evr
		if _, rest, ok := strings.Cut(evr, ":"); ok {
			ver = rest
		}
		obs = append(obs, confirmed("pkg:rpm/ol/"+n+"@"+ver+"?arch=x86_64&distro="+distro, map[string]string{"evr": evr}))
	}
	return ingest(t, st, model.AssetHost, name, true, obs...)
}

const elsaKEV = `{"vulnerabilities":[
 {"cveID":"CVE-2023-4911","vendorProject":"GNU","product":"glibc","vulnerabilityName":"Looney Tunables","dateAdded":"2023-11-21","dueDate":"2023-12-12","knownRansomwareCampaignUse":"Unknown"},
 {"cveID":"CVE-2021-3156","vendorProject":"Sudo","product":"Sudo","vulnerabilityName":"Baron Samedit","dateAdded":"2022-04-06","dueDate":"2022-04-27","knownRansomwareCampaignUse":"Unknown"}]}`

func TestOracleLinux(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	ol9 := olHost(t, st, "ol9", "ol-9.4",
		"glibc@0:2.34-60.0.2.el9",                      // below the .0.3 rebuild: CVE-2023-4911 (KEV)
		"curl@0:7.76.1-23.el9",                         // below the higher of two fixes
		"kernel-uek@0:5.15.0-6.80.3.el9uek",            // UEK R7 below its fix; R8 advisories do not apply
		"nodejs@1:20.10.0-1.module+el9.3.0+90200+aaaa", // nodejs:20, not nodejs:18
		"gnutls@0:3.7.6-23.el9_3.3",                    // a regular build: the FIPS fix does not apply
		"bash@0:5.1.8-9.el9")                           // no advisory
	uek8 := olHost(t, st, "ol9-uek8", "ol-9.6", "kernel-uek@0:6.12.0-100.20.1.el9uek", "glibc@0:2.34-60.0.3.el9")
	ksplice := olHost(t, st, "ol9-ksplice", "ol-9.2", "glibc@2:2.34-60.0.2.ksplice1.el9", "gnutls@10:3.7.6-23.el9_3.3_fips")
	ol8 := olHost(t, st, "ol8", "ol-8.10",
		"sudo@0:1.8.29-6.el8",                              // CVE-2021-3156 (KEV)
		"glibc@0:2.28-225.0.4.el8",                         // exactly the fix
		"kernel-uek@0:5.4.17-2011.5.3.el8uek",              // UEK R6: only R6 advisories
		"bpftool@0:4.18.0-477.10.1.el8_8",                  // RHCK's bpftool: UEK's do not apply
		"nodejs@1:18.20.2-1.module+el8.9.0+90319+0b1e7189") // nodejs:18 below its fix

	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	if f, err := st.GetFeed(ctx, FeedOracleLinux); err != nil || f.RefreshMin != 360 {
		t.Fatalf("feed %s: %+v %v", FeedOracleLinux, f, err)
	}
	up.set("/kev.json", elsaKEV)
	if _, err := sy.Sync(ctx, FeedKEV); err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureFeed(ctx, FeedEPSS, "prediction", 24*time.Hour, 72*time.Hour); err != nil {
		t.Fatal(err)
	}
	up.set("/epss_scores-current.csv.gz", gz(t, "#model_version:v2026.06.15,score_date:2026-10-28T00:00:00Z\ncve,epss,percentile\nCVE-2023-4911,0.93,0.998\n"))
	if _, err := sy.Sync(ctx, FeedEPSS); err != nil {
		t.Fatal(err)
	}
	serveELSA(t, up, map[string]string{"ol7": "ol7", "ol8": "ol8", "ol9": "ol9", "ol10": "ol10"})
	res, err := sy.Sync(ctx, FeedOracleLinux)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Full || res.Warning != "" || res.Changed != 16 {
		t.Errorf("sync result: %+v", res)
	}
	// Only the releases in inventory are downloaded.
	for _, r := range up.requests {
		if strings.Contains(r, "elsa-ol7") || strings.Contains(r, "elsa-ol10") {
			t.Errorf("a release not in inventory was downloaded: %s", r)
		}
	}
	f, _ := st.GetFeed(ctx, FeedOracleLinux)
	if f.Records != 16 || f.LastError != "" || !slices.Equal(f.Ecosystems, []string{"Oracle Linux:8", "Oracle Linux:8:fips", "Oracle Linux:8:ksplice",
		"Oracle Linux:9", "Oracle Linux:9:fips", "Oracle Linux:9:ksplice"}) {
		t.Errorf("feed after sync: records %d, error %q, ecosystems %v", f.Records, f.LastError, f.Ecosystems)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	if gaps, _, _ := st.ListEvaluationGaps(ctx, store.Page{}); len(gaps) != 0 {
		t.Errorf("Oracle Linux packages are evaluated now: %+v", gaps)
	}

	check := func(host int64, want map[string]string) map[string]store.Finding {
		t.Helper()
		got := openKeys(t, st, ctx, host)
		if len(got) != len(want) {
			t.Errorf("host %d findings: %s, want %d", host, sortedFindingKeys(got), len(want))
		}
		for key, fixed := range want {
			if f, ok := got[key]; !ok || f.FixedVersion != fixed {
				t.Errorf("host %d %s: fixed %q, want %q (%s)", host, key, f.FixedVersion, fixed, sortedFindingKeys(got))
			}
		}
		return got
	}
	f9 := check(ol9, map[string]string{
		"CVE-2023-4911":  "0:2.34-60.0.3.el9",
		"CVE-2023-27535": "0:7.76.1-23.el9_2.1",
		"CVE-2022-42895": "0:5.15.0-6.80.3.1.el9uek",
		"CVE-2023-46809": "1:20.11.1-1.module+el9.3.0+90254+3f4d3ee1",
	})
	if g := f9["CVE-2023-4911"]; !g.KnownExploited || g.EPSS == nil || *g.EPSS != 0.93 ||
		!slices.Equal(g.Sources, []string{"OL9-ELSA-2023-12850"}) || g.Severity != "high" {
		t.Errorf("glibc finding: KEV %v, EPSS %v, sources %v, severity %s", g.KnownExploited, g.EPSS, g.Sources, g.Severity)
	}
	if g := f9["CVE-2023-46809"]; !slices.Equal(g.Sources, []string{"OL9-ELSA-2024-1688"}) {
		t.Errorf("nodejs:20 host takes the nodejs:20 advisory only: %v", g.Sources)
	}
	var evidence map[string]any
	_ = json.Unmarshal(f9["CVE-2023-4911"].Evidence, &evidence)
	if evidence["feed"] != FeedOracleLinux || evidence["target_ecosystem"] != "Oracle Linux:9" || evidence["comparator"] != "rpm" {
		t.Errorf("evidence = %v", evidence)
	}
	check(uek8, map[string]string{"CVE-2024-28956": "0:6.12.0-100.28.2.el9uek"})
	fk := check(ksplice, map[string]string{
		"CVE-2023-4911": "2:2.34-60.0.3.ksplice1.el9",
		"CVE-2023-5981": "10:3.7.6-23.el9_3.4_fips",
	})
	if g := fk["CVE-2023-4911"]; !slices.Equal(g.Sources, []string{"OL9-ELSA-2023-12854"}) || strings.Contains(string(g.Evidence), "sources_disagree") {
		t.Errorf("Ksplice glibc: sources %v, evidence %s", g.Sources, g.Evidence)
	}
	f8 := check(ol8, map[string]string{
		"CVE-2021-3156":  "0:1.8.29-6.el8_3.1",
		"CVE-2020-10751": "0:5.4.17-2011.6.2.el8uek",
		"CVE-2024-22020": "1:18.20.4-1.module+el8.10.0+90402+68b79193",
	})
	if g := f8["CVE-2021-3156"]; !g.KnownExploited || !slices.Equal(g.Sources, []string{"OL8-ELSA-2021-0218"}) {
		t.Errorf("sudo finding: KEV %v, sources %v", g.KnownExploited, g.Sources)
	}

	// The second check re-derives every finding with its own rules.
	stats, err := (&secondcheck.Runner{Store: st, All: true}).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Checked != 10 || stats.Agreed != stats.Checked {
		for _, h := range []int64{ol9, uek8, ksplice, ol8} {
			for _, g := range openKeys(t, st, ctx, h) {
				if sc, _ := st.FindingSecondCheck(ctx, g.ID); sc != nil && sc.Result != store.SecondCheckAgreed {
					t.Errorf("second check on %s %s: %+v", g.ComponentName, g.Key, sc)
				}
			}
		}
		t.Errorf("second check: %+v", stats)
	}

	// An Oracle Linux 5 host has no source; the reason says which releases do.
	ol5 := olHost(t, st, "ol5", "ol-5.11", "bash@0:3.2-33.el5")
	if _, err := ev.Evaluate(ctx, nil, ol5); err != nil {
		t.Fatal(err)
	}
	gaps, _, _ := st.ListEvaluationGaps(ctx, store.Page{})
	if len(gaps) != 1 || !strings.Contains(gaps[0].Reason, "Oracle Linux 6 and later") {
		t.Errorf("Oracle Linux 5 gap: %+v", gaps)
	}
	// The coverage-gap report counts only that host under distributions
	// without a source.
	report, err := CoverageGaps(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.NoVulnerabilitySource) != 1 || report.NoVulnerabilitySource[0].Kind != "rpm|distribution" ||
		report.NoVulnerabilitySource[0].Assets != 1 || report.NoVulnerabilitySource[0].Components != 1 {
		t.Errorf("coverage-gap report: %+v", report.NoVulnerabilitySource)
	}
}

// One release's file that cannot be read, or that lost most of its
// advisories, must not hold up the others nor withdraw what is stored.
func TestOracleLinuxBadFile(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	ol9 := olHost(t, st, "ol9", "ol-9.4", "glibc@0:2.34-60.0.2.el9", "curl@0:7.76.1-23.el9")
	ol8 := olHost(t, st, "ol8", "ol-8.10", "sudo@0:1.8.29-6.el8")
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	truncated := func(name string) string {
		b := elsaFixture(t, name)
		return string(b[:len(b)/2])
	}
	setRaw := func(rel, body string) { up.set("/oval/com.oracle.elsa-"+rel+".xml.bz2", body) }
	stored := func(rel string) []string {
		t.Helper()
		ids, err := st.AdvisoryIDs(ctx, FeedOracleLinux, elsaPrefix(rel))
		if err != nil {
			t.Fatal(err)
		}
		return ids
	}
	sync := func(wantWarning string) {
		t.Helper()
		res, err := sy.Sync(ctx, FeedOracleLinux)
		if err != nil {
			t.Fatalf("sync: %v", err)
		}
		f, _ := st.GetFeed(ctx, FeedOracleLinux)
		if !strings.Contains(res.Warning, wantWarning) || (wantWarning == "") != (f.LastError == "") || !strings.Contains(f.LastError, wantWarning) {
			t.Errorf("warning %q, feed error %q; want %q", res.Warning, f.LastError, wantWarning)
		}
		if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
			t.Fatal(err)
		}
	}

	// A truncated Oracle Linux 9 file on the first sync: Oracle Linux 8 is
	// read and evaluated all the same, Oracle Linux 9 is not evaluated.
	serveELSA(t, up, map[string]string{"ol8": "ol8"})
	setRaw("ol9", truncated("ol9"))
	sync("Oracle Linux 9: ")
	if n := len(stored("8")); n != 8 {
		t.Errorf("Oracle Linux 8 advisories stored: %d", n)
	}
	if n := len(stored("9")); n != 0 {
		t.Errorf("Oracle Linux 9 advisories from a truncated file: %d", n)
	}
	if _, ok := openKeys(t, st, ctx, ol8)["CVE-2021-3156"]; !ok {
		t.Error("Oracle Linux 8 must be evaluated although the Oracle Linux 9 file is broken")
	}
	if gaps, _, _ := st.ListEvaluationGaps(ctx, store.Page{}); len(gaps) != 2 || !strings.Contains(gaps[0].Reason, "Oracle Linux:9") {
		t.Errorf("Oracle Linux 9 must be not evaluated, never clean: %+v", gaps)
	}

	// The good file: everything is read, the warning clears.
	serveELSA(t, up, map[string]string{"ol9": "ol9"})
	sync("")
	before := stored("9")
	if len(before) != 8 {
		t.Fatalf("Oracle Linux 9 advisories: %v", before)
	}
	if got := openKeys(t, st, ctx, ol9); len(got) != 2 {
		t.Fatalf("Oracle Linux 9 findings: %s", sortedFindingKeys(got))
	}

	// A file that lost most of its advisories is refused; so is a truncated
	// or corrupted one. What is stored stays, and so do the findings.
	for name, body := range map[string]string{
		"shrunk":    string(elsaFixture(t, "ol9-shrunk")),
		"truncated": truncated("ol9"),
		"corrupted": corrupt(elsaFixture(t, "ol9")),
		"not bzip2": "<html>maintenance</html>",
	} {
		setRaw("ol9", body)
		sync("Oracle Linux 9: ")
		if after := stored("9"); !slices.Equal(after, before) {
			t.Errorf("%s file: stored advisories %v, want %v", name, after, before)
		}
		if got := openKeys(t, st, ctx, ol9); len(got) != 2 {
			t.Errorf("%s file: Oracle Linux 9 findings %s", name, sortedFindingKeys(got))
		}
	}

	// Neither file readable: the sync fails and keeps everything.
	setRaw("ol8", truncated("ol8"))
	if _, err := sy.Sync(ctx, FeedOracleLinux); err == nil || !strings.Contains(err.Error(), "no ELSA file could be read") {
		t.Errorf("both files broken: %v", err)
	}
	if len(stored("8")) != 8 || len(stored("9")) != 8 {
		t.Errorf("stored after a failed sync: %d %d", len(stored("8")), len(stored("9")))
	}

	// A revision that drops one advisory (fewer than half) is read: that
	// advisory is withdrawn and its finding closed, the rest stay.
	serveELSA(t, up, map[string]string{"ol8": "ol8", "ol9": "ol9-revised"})
	sync("")
	if got := openKeys(t, st, ctx, ol9); len(got) != 1 || got["CVE-2023-4911"].ID == 0 {
		t.Errorf("after the revision, Oracle Linux 9 findings: %s", sortedFindingKeys(got))
	}
	if after := stored("9"); len(after) != 7 || slices.Contains(after, "OL9-ELSA-2023-2650") {
		t.Errorf("after the revision: %v", after)
	}
	if adv, _ := st.AdvisoryGroup(ctx, "OL9-ELSA-2023-2650"); len(adv) != 1 || adv[0].Withdrawn == nil || adv[0].GroupKey != "CVE-2023-27535" {
		t.Errorf("the dropped advisory must be withdrawn and keep its CVE: %+v", adv)
	}

	// A release Oracle publishes nothing for (404) is not a failure; its
	// hosts stay not evaluated, never clean.
	serveELSA(t, up, map[string]string{"ol9": "ol9"})
	olHost(t, st, "ol11", "ol-11.0", "bash@0:5.3-1.el11")
	res, err := sy.Sync(ctx, FeedOracleLinux)
	if err != nil || res.Warning != "" || !res.Full {
		t.Errorf("a release without a file: %+v %v", res, err)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	gaps, _, _ := st.ListEvaluationGaps(ctx, store.Page{})
	if len(gaps) != 1 || !strings.Contains(gaps[0].Reason, "no advisories for Oracle Linux:11") {
		t.Errorf("Oracle Linux 11 gap: %+v", gaps)
	}
}

// Feeds are shared: a refresh a workspace asks for (its job runs in that
// workspace) reads the releases of every workspace, not only its own.
func TestOracleLinuxReleasesOfEveryWorkspace(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, _, up := setup(t)
	olHost(t, st, "ol9", "ol-9.4", "glibc@0:2.34-60.0.2.el9")
	ws2, _, err := st.CreateWorkspace(tenant.System(context.Background()), "Other", "other", "other@example.com", "Other", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	b := model.NewBatch(model.Collector{ID: "t", Method: "test"},
		model.AssetRef{Kind: model.AssetHost, Name: "ol8", Identifiers: []model.Identifier{{Scheme: "test", Value: "ol8"}}})
	b.Observations, b.Complete = []model.Observation{confirmed("pkg:rpm/ol/sudo@1.8.29-6.el8?distro=ol-8.10", map[string]string{"evr": "0:1.8.29-6.el8"})}, true
	if _, err := st.Ingest(tenant.WithWorkspace(context.Background(), ws2.ID), b, 0); err != nil {
		t.Fatal(err)
	}
	if err := EnsureFeeds(tenant.System(context.Background()), st); err != nil {
		t.Fatal(err)
	}
	serveELSA(t, up, map[string]string{"ol8": "ol8", "ol9": "ol9"})
	res, err := sy.Sync(ctx, FeedOracleLinux)
	if err != nil || !res.Full {
		t.Fatalf("sync: %+v %v", res, err)
	}
	if !res.Ecosystems["Oracle Linux:8"] || !res.Ecosystems["Oracle Linux:9"] {
		t.Errorf("a workspace's refresh must read every workspace's releases: %v", keys(res.Ecosystems))
	}
}
