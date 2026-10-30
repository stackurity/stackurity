package intel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/version"
)

// The fixtures in testdata/msrc are real Security Update Guide documents
// (api.msrc.microsoft.com/cvrf/v3.0, read on 2026-10-29), trimmed by
// testdata/msrc/trim.py to a few CVEs and products:
//
//	2025-Sep  CVE-2025-53803 (kernel), CVE-2025-59220 (Windows 10 21H2 given
//	          a 19043 build)
//	2025-Oct  CVE-2025-59287 (WSUS, in KEV; fixed again out of band, a
//	          standalone update with a higher build), CVE-2025-59230 (in
//	          KEV), CVE-2025-59289 (disclosed in October, fixed by
//	          September's updates; hotpatch builds), CVE-2016-9535 (LibTIFF),
//	          CVE-2025-55247 (.NET only)
//	2026-Oct  CVE-2026-69950 (two cumulative updates for Server 2016)
//	2024-Oct  CVE-2024-43583 (revised with December's updates; a Windows 7
//	          build given for Windows 11 22H2)
func readCVRF(t *testing.T, doc string) *cvrfDoc {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "msrc", doc+".json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := parseCVRF(f, doc)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// fixedBuilds returns line -> fixed build of one advisory.
func fixedBuilds(t *testing.T, d *cvrfDoc, id string) map[string]string {
	t.Helper()
	for _, v := range d.vulns {
		if v.ID != id {
			continue
		}
		out := map[string]string{}
		for _, a := range v.Affected {
			if a.Package.Name != "windows" || len(a.Ranges) != 1 || len(a.Ranges[0].Events) != 2 {
				t.Fatalf("%s: unexpected affected entry %+v", id, a)
			}
			out[strings.TrimPrefix(a.Package.Ecosystem, "Windows:")] = a.Ranges[0].Events[1].Fixed
		}
		return out
	}
	return nil
}

func TestParseCVRF(t *testing.T) {
	oct := readCVRF(t, "2025-Oct")
	var ids []string
	for _, v := range oct.vulns {
		ids = append(ids, v.ID)
	}
	// The .NET-only CVE has no Windows build.
	if got := strings.Join(ids, " "); got != "MSRC-2025-Oct-CVE-2016-9535 MSRC-2025-Oct-CVE-2025-59230 MSRC-2025-Oct-CVE-2025-59287 MSRC-2025-Oct-CVE-2025-59289" {
		t.Errorf("advisories = %s", got)
	}

	// The October cumulative update (.4294) and the out-of-band update
	// that completed the fix (.4297): the higher build fixes it. Server
	// 2012 R2 (6.3 builds) is not an update line.
	wsus := fixedBuilds(t, oct, "MSRC-2025-Oct-CVE-2025-59287")
	want := map[string]string{"Server 2016": "10.0.14393.8524", "Server 2019": "10.0.17763.7922", "Server 2022": "10.0.20348.4297",
		"Server 23H2": "10.0.25398.1916", "Server 2025": "10.0.26100.6905"}
	if len(wsus) != len(want) {
		t.Errorf("CVE-2025-59287 lines = %v", wsus)
	}
	for l, b := range want {
		if wsus[l] != b {
			t.Errorf("CVE-2025-59287 %s fixed in %q, want %s", l, wsus[l], b)
		}
	}

	// Every architecture of a client release is one line; Windows 10 22H2
	// and 21H2 take the same update (KB5066791), 24H2 and 25H2 another
	// (KB5066835) with their own builds.
	tiff := fixedBuilds(t, oct, "MSRC-2025-Oct-CVE-2016-9535")
	for l, b := range map[string]string{"10 22H2": "10.0.19045.6456", "10 21H2": "10.0.19044.6456", "11 24H2": "10.0.26100.6899",
		"11 25H2": "10.0.26200.6899", "Server 2025": "10.0.26100.6899", "11 22H2": "10.0.22621.6060", "10 1607": "10.0.14393.8519"} {
		if tiff[l] != b {
			t.Errorf("CVE-2016-9535 %s fixed in %q, want %s", l, tiff[l], b)
		}
	}

	// Disclosed in October, fixed in September's updates. Windows 11 22H2
	// is given the 23H2 build (22631.5909) and 21H2/22H2 a 19044 build: the
	// revision is the same update. Windows 11 25H2 is listed with no fix
	// and is left out rather than reported unfixed. Hotpatch builds are
	// not fixes for a regular host.
	bt := fixedBuilds(t, oct, "MSRC-2025-Oct-CVE-2025-59289")
	for l, b := range map[string]string{"Server 2022": "10.0.20348.4171", "11 22H2": "10.0.22621.5909", "11 23H2": "10.0.22631.5909",
		"10 22H2": "10.0.19045.6332", "11 24H2": "10.0.26100.6584"} {
		if bt[l] != b {
			t.Errorf("CVE-2025-59289 %s fixed in %q, want %s", l, bt[l], b)
		}
	}
	if _, ok := bt["11 25H2"]; ok {
		t.Error("CVE-2025-59289 lists no fix for Windows 11 25H2; it must not be reported")
	}

	// The advisory: CVE alias (for KEV and EPSS), Microsoft's rating, the
	// Security Update Guide page and the KB articles.
	for _, v := range oct.vulns {
		if v.ID != "MSRC-2025-Oct-CVE-2025-59287" {
			continue
		}
		r := osv.Rate(v)
		if len(v.Aliases) != 1 || v.Aliases[0] != "CVE-2025-59287" || r.Level != "critical" || r.Score != 9.8 {
			t.Errorf("CVE-2025-59287 aliases %v, rating %+v", v.Aliases, r)
		}
		refs := map[string]bool{}
		for _, ref := range v.References {
			refs[ref.URL] = true
		}
		for _, u := range []string{"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59287", "https://support.microsoft.com/help/5070884"} {
			if !refs[u] {
				t.Errorf("CVE-2025-59287 references %v lack %s", v.References, u)
			}
		}
		if v.Published.Format("2006-01-02") != "2025-10-14" || !v.Modified.After(v.Published) {
			t.Errorf("published %v, modified %v", v.Published, v.Modified)
		}
	}

	// The updates: each line's own Patch Tuesday build is marked monthly;
	// the out-of-band and hotpatch builds are not.
	ups := map[string]store.WindowsUpdate{}
	for _, u := range oct.updates {
		ups[u.Line+" "+u.Build+" "+u.KB] = u
	}
	for k, w := range map[string]struct{ monthly, hotpatch bool }{
		"Server 2022 10.0.20348.4294 5066782": {monthly: true},
		"Server 2022 10.0.20348.4297 5070884": {},
		"Server 2022 10.0.20348.4297 5070892": {},
		"Server 2022 10.0.20348.4171 5065432": {},
		"Server 2022 10.0.20348.4106 5065306": {hotpatch: true},
		"Server 2025 10.0.26100.6508 5065474": {hotpatch: true},
		"11 24H2 10.0.26100.6899 5066835":     {monthly: true},
	} {
		u, ok := ups[k]
		if !ok || u.Monthly != w.monthly || u.Hotpatch != w.hotpatch || u.Released.Format("2006-01-02") != "2025-10-14" {
			t.Errorf("update %s = %+v (present %v), want %+v", k, u, ok, w)
		}
	}
	if oct.anomalies != 0 {
		t.Errorf("anomalies = %d", oct.anomalies)
	}

	// Two cumulative updates for one line in one month: the higher build.
	if b := fixedBuilds(t, readCVRF(t, "2026-Oct"), "MSRC-2026-Oct-CVE-2026-69950")["Server 2016"]; b != "10.0.14393.9612" {
		t.Errorf("CVE-2026-69950 Server 2016 fixed in %q", b)
	}
	// Windows 10 21H2 given a 19043 build: the line's own build, same revision.
	if b := fixedBuilds(t, readCVRF(t, "2025-Sep"), "MSRC-2025-Sep-CVE-2025-59220")["10 21H2"]; b != "10.0.19044.6332" {
		t.Errorf("CVE-2025-59220 10 21H2 fixed in %q", b)
	}
	// A Windows 7 build listed for Windows 11 22H2 is not 10.0 and is
	// ignored; the line's own fix stays.
	if b := fixedBuilds(t, readCVRF(t, "2024-Oct"), "MSRC-2024-Oct-CVE-2024-43583")["11 22H2"]; b != "10.0.22621.4602" {
		t.Errorf("CVE-2024-43583 11 22H2 fixed in %q", b)
	}
}

// A fixed build of another line (Microsoft's data has had them) is not a
// fix for this one.
func TestCVRFWrongLineBuild(t *testing.T) {
	c := cvrfCompact{cve: "CVE-2025-0001", title: "test", fixes: []cvrfFix{
		{kb: "5000001", subType: "Security Update", build: "10.0.17763.100", products: []string{"2016"}},
		{kb: "5000002", subType: "Security Update", build: "10.0.20348.200", products: []string{"2022"}},
	}}
	doc := &cvrfDoc{}
	ups := map[[3]string]store.WindowsUpdate{}
	v := cvrfRecord(c, "2025-Jan", cvrfTime("2025-01-14T08:00:00"), cvrfTime("2025-01-14T08:00:00"),
		map[string]string{"2016": "Server 2016", "2022": "Server 2022"}, nil, nil, ups, doc)
	if v == nil || len(v.Affected) != 1 || v.Affected[0].Package.Ecosystem != "Windows:Server 2022" || doc.anomalies != 1 {
		t.Fatalf("record %+v, anomalies %d", v, doc.anomalies)
	}
	if v.ID != "MSRC-2025-Jan-CVE-2025-0001" || len(ups) != 1 {
		t.Errorf("id %s, updates %v", v.ID, ups)
	}
}

func TestParseCVRFLimits(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "msrc", "2025-Oct.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Cut short by the size cap: an error, never a partial document.
	if _, err := parseCVRF(&msrcCapReader{r: f, left: 4096}, "2025-Oct"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("err = %v", err)
	}
	for _, bad := range []string{`[]`, `{"Vulnerability":[]}`, `{"ProductTree":{"FullProductName":[{"ProductID":"1","Value":"Windows Server 2022"}]}}`} {
		if _, err := parseCVRF(strings.NewReader(bad), "x"); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

// Builds compare as numbers: 10.0.20348.887 is older than .4294, although
// it sorts after it as text.
func TestWindowsBuildComparison(t *testing.T) {
	aff := osv.Affected{Package: osv.Package{Ecosystem: "Windows:Server 2022", Name: "windows"},
		Ranges: []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "10.0.20348.4294"}}}}}
	for installed, affected := range map[string]bool{
		"10.0.20348.887":   true,
		"10.0.20348.4293":  true,
		"10.0.20348.4294":  false,
		"10.0.20348.4297":  false,
		"10.0.20348.10001": false,
		"10.0.20348.0":     true,
	} {
		m, err := osv.Check(aff, osv.Target{Ecosystem: "Windows:Server 2022", Name: "windows", Version: installed, Compare: version.Generic})
		if err != nil || m.Affected != affected {
			t.Errorf("%s: affected %v (%v), want %v", installed, m.Affected, err, affected)
		}
		if affected && m.FixedVersion != "10.0.20348.4294" {
			t.Errorf("%s: fixed %q", installed, m.FixedVersion)
		}
	}
	if compareBuild("10.0.26100.33650", "10.0.26100.9711") <= 0 {
		t.Error("revision 33650 is after 9711")
	}
}
