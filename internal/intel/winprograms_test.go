package intel

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/version"
	"github.com/stackurity/stackurity/internal/winprograms"
)

// nvdFixture reads a saved NVD answer (testdata/winprograms/nvd).
func nvdFixture(t *testing.T, name string) []nvdCVE {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "winprograms", "nvd", name))
	if err != nil {
		t.Fatal(err)
	}
	var page nvdResponse
	if err := json.Unmarshal(b, &page); err != nil {
		t.Fatal(err)
	}
	out := make([]nvdCVE, len(page.Vulnerabilities))
	for i, w := range page.Vulnerabilities {
		out[i] = w.CVE
	}
	return out
}

// affectedAt reports whether an advisory says v is affected on a listed
// line, and the fix; a match only through an unlisted-line entry is
// reported as not affected, with unlisted set.
func affectedAt(t *testing.T, v *osv.Vulnerability, ver string) (bool, string) {
	hit, fix, _ := lineVerdict(t, v, ver)
	return hit, fix
}

func lineVerdict(t *testing.T, v *osv.Vulnerability, ver string) (hit bool, fix string, unlisted bool) {
	t.Helper()
	for _, a := range v.Affected {
		m, err := osv.Check(a, osv.Target{Ecosystem: a.Package.Ecosystem, Name: a.Package.Name, Version: ver, Compare: version.Generic})
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case !m.Affected:
		case osv.UnlistedLine(a.Package.Ecosystem, a):
			unlisted = true
		default:
			hit, fix = true, m.FixedVersion
		}
	}
	return hit, fix, unlisted
}

// The fixes a source lists per line: a version on a line with a fix is
// compared with that fix; one on a line with no listed fix needs validation
// while that line is still updated, and is affected with the next listed
// line's fix once it is not; one above every line is not affected.
func TestLineFixRanges(t *testing.T) {
	still := func(ms ...int) func(int) bool {
		return func(m int) bool { return slices.Contains(ms, m) }
	}
	for _, c := range []struct {
		name      string
		fixes     []string
		patched   func(int) bool
		installed string
		hit       bool
		fix       string
		unlisted  bool
	}{
		// The first review's probes: patched hosts on a line still updated.
		{"Thunderbird ESR 140 vs a monthly fix", []string{"143"}, still(140), "140.3.1", false, "", true},
		{"Firefox ESR 115 vs ESR 153's fix", []string{"153.2.0"}, still(115), "115.30.0", false, "", true},
		{"Edge Extended Stable vs Stable's fix", []string{"156.0.4314.42"}, still(152), "152.0.4191.137", false, "", true},
		// The second review's: lines no longer updated are affected.
		{"Edge 154, an older Stable", []string{"156.0.4314.42"}, still(152), "154.0.4258.62", true, "156.0.4314.42", false},
		{"Edge 155, an older Stable", []string{"156.0.4314.42"}, still(152), "155.0.4283.60", true, "156.0.4314.42", false},
		{"Thunderbird 157, an older monthly", []string{"159", "153.6"}, still(153), "157.0", true, "159", false},
		{"Thunderbird 158, an older monthly", []string{"159", "153.6"}, still(153), "158.0", true, "159", false},
		{"Firefox ESR 128, ended", []string{"153.6", "115.44"}, still(115), "128.3.0", true, "153.6", false},
		{".NET 6, out of support", []string{"8.0.32", "9.0.21"}, nil, "6.0.36", true, "8.0.32", false},
		{"no dates: unlisted", []string{"156.0.4314.42"}, nil, "154.0.4258.62", false, "", true},
		{"own line's fix", []string{"152.0.4191.137", "155.0.4283.60"}, still(152), "152.0.4191.100", true, "152.0.4191.137", false},
		{"past own line's fix", []string{"152.0.4191.137", "155.0.4283.60"}, still(152), "152.0.4191.137", false, "", false},
		{"between, not updated", []string{"152.0.4191.137", "155.0.4283.60"}, still(152), "154.0.4258.50", true, "155.0.4283.60", false},
		{"above every line", []string{"152.0.4191.137", "155.0.4283.60"}, still(152), "157.0.1", false, "", false},
		{".NET 9 on its line", []string{"8.0.32", "9.0.21"}, still(8, 9), "9.0.10", true, "9.0.21", false},
	} {
		patched := c.patched
		if c.name == ".NET 6, out of support" {
			patched = still(8, 9)
		}
		v := &osv.Vulnerability{ID: "x", Affected: lineEntries("Windows programs:p", "p", lineFixRanges(c.fixes, patched))}
		hit, fix, unlisted := lineVerdict(t, v, c.installed)
		if hit != c.hit || fix != c.fix || unlisted != c.unlisted {
			t.Errorf("%s: %v against %s: affected %v fix %q unlisted %v; want %v %q %v", c.name, c.fixes, c.installed, hit, fix, unlisted, c.hit, c.fix, c.unlisted)
		}
	}
	// One rolling line (Firefox's rapid release): every earlier version is affected.
	v := &osv.Vulnerability{ID: "x", Affected: lineEntries("Windows programs:p", "p", rollingFixRange([]string{"159", "131.0.2"}))}
	if hit, fix, _ := lineVerdict(t, v, "131.0.1"); !hit || fix != "159" {
		t.Errorf("rolling: %v %s", hit, fix)
	}
}

func TestNVDRecords(t *testing.T) {
	chrome := winprograms.Default().Program("google-chrome")
	anomalies := nvdAnomalies{}
	recs := map[string]*osv.Vulnerability{}
	for _, c := range nvdFixture(t, "google_chrome.json") {
		if v := nvdRecord(chrome, c, anomalies); v != nil {
			recs[c.ID] = v
		}
	}
	if recs["CVE-2025-0435"] != nil || anomalies[nvdOtherOS] != 2 {
		t.Errorf("an Android-only configuration, and CVE-2025-6554's macOS/Linux one, are not for Windows: %v", anomalies)
	}
	v := recs["CVE-2025-6554"]
	if v == nil || v.ID != "NVD-google-chrome-CVE-2025-6554" || v.Aliases[0] != "CVE-2025-6554" || v.Affected[0].Package.Ecosystem != "Windows programs:google-chrome" {
		t.Fatalf("record %+v", v)
	}
	// Windows got 138.0.7204.96; macOS and Linux .92, which is not applied.
	if hit, fix := affectedAt(t, v, "138.0.7204.93"); !hit || fix != "138.0.7204.96" {
		t.Errorf("138.0.7204.93 on Windows: affected %v, fix %s", hit, fix)
	}
	if hit, _ := affectedAt(t, v, "138.0.7204.96"); hit {
		t.Error("the fixed build is not affected")
	}
	if len(v.Severity) != 1 || !strings.HasPrefix(v.Severity[0].Score, "CVSS:3.1/") || v.Summary == "" ||
		v.References[0].URL != "https://nvd.nist.gov/vuln/detail/CVE-2025-6554" {
		t.Errorf("metadata %+v %+v", v.Severity, v.References)
	}
	if hit, fix := affectedAt(t, recs["CVE-2026-118359"], "156.0.8078.48"); !hit || fix != "156.0.8078.73" {
		t.Errorf("CVE-2026-118359: %v %s", hit, fix)
	}

	// 7-Zip: lower bounds kept; the NetApp product in the same CVE is not 7-Zip.
	sz := winprograms.Default().Program("7-zip")
	for _, c := range nvdFixture(t, "7_zip_7_zip.json") {
		v := nvdRecord(sz, c, nvdAnomalies{})
		switch c.ID {
		case "CVE-2025-0411":
			if hit, fix := affectedAt(t, v, "24.08"); !hit || fix != "24.09" || len(v.Affected[0].Ranges) != 1 {
				t.Errorf("CVE-2025-0411: %v %s %+v", hit, fix, v.Affected)
			}
		case "CVE-2026-48103":
			if hit, _ := affectedAt(t, v, "9.20"); hit {
				t.Error("9.20 is below versionStartIncluding 9.34")
			}
			if hit, _ := affectedAt(t, v, "26.00"); !hit {
				t.Error("26.00 is affected")
			}
		}
	}

	// Adobe: one CVE records both tracks; each entry reads only its own.
	cont, classic := winprograms.Default().Program("adobe-acrobat"), winprograms.Default().Program("adobe-acrobat-classic")
	for _, c := range nvdFixture(t, "adobe_acrobat_classic.json") {
		if c.ID != "CVE-2026-81997" {
			continue
		}
		vc, vk := nvdRecord(cont, c, nvdAnomalies{}), nvdRecord(classic, c, nvdAnomalies{})
		if hit, fix := affectedAt(t, vc, "26.001.21691"); !hit || fix != "26.002.21901" {
			t.Errorf("Continuous: %v %s", hit, fix)
		}
		if hit, fix := affectedAt(t, vk, "24.001.30264"); !hit || fix != "24.001.30429" {
			t.Errorf("Classic: %v %s", hit, fix)
		}
		if hit, _ := affectedAt(t, vk, "24.001.30429"); hit {
			t.Error("a patched Classic install must not get the Continuous range")
		}
	}

	// Zoom: a Linux-only client CVE is not for Windows.
	zoom := winprograms.Default().Program("zoom-workplace")
	for _, c := range nvdFixture(t, "zoom_workplace_desktop.json") {
		v := nvdRecord(zoom, c, nvdAnomalies{})
		if (v != nil) != (c.ID == "CVE-2025-46785") {
			t.Errorf("%s: record %v", c.ID, v != nil)
		}
	}
}

func TestNVDRecordSkips(t *testing.T) {
	sz := winprograms.Default().Program("7-zip")
	cve := func(m nvdCPEMatch) nvdCVE {
		return nvdCVE{ID: "CVE-2026-0001", Configurations: []nvdConfig{{Nodes: []nvdNode{{Operator: "OR", CPEMatch: []nvdCPEMatch{m}}}}}}
	}
	for name, c := range map[string]struct {
		m    nvdCPEMatch
		skip string
	}{
		"all versions":    {nvdCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*"}, nvdUnbounded},
		"lower only":      {nvdCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*", VersionStartIncluding: "24.00"}, nvdStartOnly},
		"start excluding": {nvdCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*", VersionStartExcluding: "24.00", VersionEndExcluding: "24.09"}, nvdStartExcl},
		"beta":            {nvdCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:7-zip:7-zip:24.00:beta:*:*:*:*:*:*"}, nvdUnreadable},
	} {
		a := nvdAnomalies{}
		if v := nvdRecord(sz, cve(c.m), a); v != nil || a[c.skip] != 1 || a[nvdNoUsableCPEs] != 1 {
			t.Errorf("%s: %v %v", name, v, a)
		}
	}
	exact := nvdRecord(sz, cve(nvdCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:7-zip:7-zip:24.07:*:*:*:*:*:*:*"}), nvdAnomalies{})
	if exact == nil || len(exact.Affected[0].Versions) != 1 || exact.Affected[0].Versions[0] != "24.07" {
		t.Errorf("exact %+v", exact)
	}
	rejected := cve(nvdCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:7-zip:7-zip:24.07:*:*:*:*:*:*:*"})
	rejected.VulnStatus = "Rejected"
	if nvdRecord(sz, rejected, nvdAnomalies{}) != nil {
		t.Error("a rejected CVE is not read")
	}
}

func readMozillaFixture(t *testing.T) []mfsaDoc {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "winprograms", "mfsa.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	docs, unread, err := readMozilla(f)
	if err != nil {
		t.Fatal(err)
	}
	if unread != 0 || len(docs) != 7 {
		t.Fatalf("%d advisories, %d unread", len(docs), unread)
	}
	return docs
}

func TestMozillaRecords(t *testing.T) {
	docs := readMozillaFixture(t)
	by := func(id string) map[string]*osv.Vulnerability {
		out := map[string]*osv.Vulnerability{}
		for _, v := range mozillaRecords(winprograms.Default().Program(id), docs) {
			out[v.Aliases[0]] = v
		}
		return out
	}
	ff, esr, tb := by("mozilla-firefox"), by("mozilla-firefox-esr"), by("mozilla-thunderbird")
	// CVE-2024-9680: Firefox 131.0.2, ESR 128.3.1 and 115.16.1,
	// Thunderbird 131.0.1, 128.3.1 and 115.16.0.
	for _, c := range []struct {
		recs      map[string]*osv.Vulnerability
		installed string
		hit       bool
		fix       string
	}{
		{ff, "131.0.1", true, "131.0.2"},
		{ff, "131.0.2", false, ""},
		{esr, "128.3.0", true, "128.3.1"},
		{esr, "115.16.0", true, "115.16.1"},
		{esr, "115.16.1", false, ""},    // its own line's fix, although below 128.3.1
		{esr, "120.0", true, "128.3.1"}, // between two lines, never updated: the next line's fix
		{tb, "128.2.0", true, "128.3.1"},
		{tb, "131.0.0", true, "131.0.1"},
		{tb, "130.0", true, "131.0.1"}, // an older monthly release: the next line's fix
	} {
		v := c.recs["CVE-2024-9680"]
		if v == nil {
			t.Fatal("CVE-2024-9680 not read")
		}
		if hit, fix := affectedAt(t, v, c.installed); hit != c.hit || fix != c.fix {
			t.Errorf("%s %s: %v %s", v.Affected[0].Package.Name, c.installed, hit, fix)
		}
	}
	v := ff["CVE-2024-9680"]
	if v.ID != "MFSA-mozilla-firefox-CVE-2024-9680" || !strings.Contains(string(v.DatabaseSpecific), `"critical"`) ||
		v.References[0].URL != "https://www.mozilla.org/en-US/security/advisories/mfsa2024-51/" || v.Published.IsZero() {
		t.Errorf("metadata %+v %s", v.References, v.DatabaseSpecific)
	}
	// The newest: Firefox 159 is the release's; ESR 153.6 and 115.44 the ESR's.
	newest := 0
	for _, v := range ff {
		for _, r := range v.Affected[0].Ranges {
			if r.Events[1].Fixed == "159" {
				newest++
			}
		}
	}
	if newest < 100 {
		t.Errorf("%d CVEs fixed in Firefox 159", newest)
	}
	for _, v := range esr {
		for _, a := range v.Affected {
			if a.Ranges[0].Events[1].Fixed == "159" {
				t.Fatalf("%s: a release fix applied to ESR", v.ID)
			}
		}
		// A CVE of 27 October 2026 fixed only in ESR 153.6 and 115.44:
		// ESR 115 was updated that day, so a 115 install between those
		// fixes needs validation; ESR 128 had ended, so it is affected
		// with ESR 153's fix.
		if v.Published.Year() == 2026 && v.Published.Month() == 10 && v.Published.Day() == 27 {
			if hit, fix, unlisted := lineVerdict(t, v, "128.3.0"); len(v.Affected) > 2 && (!hit || fix != "153.6" || unlisted) {
				t.Fatalf("%s on ended ESR 128: %v %s %v", v.ID, hit, fix, unlisted)
			}
		}
	}
}

func TestMozillaRefusesBrokenArchives(t *testing.T) {
	good, err := os.ReadFile(filepath.Join("testdata", "winprograms", "mfsa.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	var empty bytes.Buffer
	zw := gzip.NewWriter(&empty)
	zw.Close()
	for name, b := range map[string][]byte{
		"truncated": good[:len(good)/2],
		"not gzip":  []byte("<html>rate limited</html>"),
		"empty":     empty.Bytes(),
		"nothing":   nil,
	} {
		if _, _, err := readMozilla(bytes.NewReader(b)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMSRCPrograms(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "winprograms", "msrc-2026-Oct.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	doc, err := parseCVRF(f, "2026-Oct")
	if err != nil {
		t.Fatal(err)
	}
	ranges := map[string]map[string]string{} // CVE -> program -> its entries' ranges
	for _, v := range doc.vulns {
		for _, a := range v.Affected {
			if osv.BaseEcosystem(a.Package.Ecosystem) != winprograms.Ecosystem {
				continue
			}
			if ranges[v.Aliases[0]] == nil {
				ranges[v.Aliases[0]] = map[string]string{}
			}
			for _, e := range a.Ranges[0].Events {
				ranges[v.Aliases[0]][a.Package.Name] += e.Introduced + e.Fixed
				if e.Limit != "" {
					ranges[v.Aliases[0]][a.Package.Name] += "limit " + e.Limit
				}
				ranges[v.Aliases[0]][a.Package.Name] += " "
			}
			ranges[v.Aliases[0]][a.Package.Name] += "| "
		}
	}
	for cve, want := range map[string]map[string]string{
		// A Chromium CVE added on 10-26 for 154: Extended Stable 152 was
		// listed next to Stable that day, so it is still updated.
		"CVE-2026-102299": {"microsoft-edge": "0 limit 152 154.0.4258.53 | 152 limit 153 | 153 limit 154 154.0.4258.53 | 154 154.0.4258.53 | "},
		// Extended Stable (152) and Stable (155) fixes: each fixes its line.
		// 153 and 154, old Stable majors never listed next to a higher one,
		// are affected with 155's fix; majors below 152 with 152's.
		"CVE-2026-110144": {"microsoft-edge": "0 limit 152 152.0.4191.137 | 152 152.0.4191.137 | 153 limit 155 155.0.4283.60 | 155 155.0.4283.60 | "},
		// .NET runtime fixes per line; the preview (11.0.0-rc.2) is not read.
		"CVE-2026-105016": {"dotnet-runtime": "0 limit 8 8.0.32 | 8 8.0.32 | 9 9.0.21 | 10 10.0.14 | "},
		// SDK versions only (8.0.427): no runtime fix.
		"CVE-2026-114148": nil,
	} {
		got := ranges[cve]
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: %v, want %v", cve, got, want)
		}
	}
	// The Windows part of the same document is unchanged.
	windows := false
	for _, v := range doc.vulns {
		for _, a := range v.Affected {
			windows = windows || a.Package.Ecosystem == "Windows:Server 2022"
		}
	}
	if !windows {
		t.Error("the Windows CVE was not read")
	}
}

func TestMSRCProgramVersions(t *testing.T) {
	for _, c := range []struct {
		name, build string
		want        bool
	}{
		{"Microsoft Edge (Chromium-based)", "154.0.4258.53", true},
		{"Microsoft Edge (Chromium-based)", "10.0.20348.4294", false},
		{".NET 8.0 runtime installed on Windows", "8.0.32", true},
		{".NET 10.0 installed on Windows", "10.0.4", true},    // the runtime, named without "runtime"
		{".NET 10.0 installed on Windows", "10.0.403", false}, // an SDK feature band
		{".NET 8.0 runtime installed on Windows", "9.0.21", false},
		{".NET 11.0 runtime installed on Windows", "11.0.0-rc.2", false},
		{"ASP.NET Core 8.0", "8.0.32", true},
		{".NET 8.0 runtime installed on Linux", "8.0.32", false},
		{"Microsoft.AspNetCore.Components.WebAssembly.Server on .NET 10.0 runtime installed on Windows", "10.0.13", false},
	} {
		p, ok := msrcProgram(c.name)
		if got := ok && p.accepts(c.build); got != c.want {
			t.Errorf("%q %s = %v", c.name, c.build, got)
		}
	}
}

func TestNVDSummary(t *testing.T) {
	long := strings.Repeat("a", 470) + " " + strings.Repeat("’", 20)
	s := nvdSummaryText(long)
	if len(s) > 500 || !utf8.ValidString(s) || !strings.HasSuffix(s, "…") {
		t.Errorf("summary of %d bytes, valid %v", len(s), utf8.ValidString(s))
	}
}

// The NVD API key never follows a redirect to another host.
func TestNVDKeyStaysOnHost(t *testing.T) {
	var gotKey []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = append(gotKey, r.Header.Get("apiKey"))
		_, _ = w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer other.Close()
	nvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = append(gotKey, r.Header.Get("apiKey"))
		if r.URL.Path == "/same" {
			http.Redirect(w, r, "/elsewhere?"+r.URL.RawQuery, http.StatusFound)
			return
		}
		if r.URL.Path == "/elsewhere" {
			http.Redirect(w, r, other.URL+"/?"+r.URL.RawQuery, http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer nvd.Close()
	cfg := DefaultConfig()
	cfg.NVDURL, cfg.NVDAPIKey, cfg.NVDDelay = nvd.URL+"/same", "secret-key", 0
	s := NewSyncer(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg)
	if err := s.nvdQuery(context.Background(), "cpe:2.3:a:7-zip:7-zip", time.Time{}, time.Time{}, func(nvdCVE) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(gotKey) != 3 || gotKey[0] != "secret-key" || gotKey[1] != "secret-key" || gotKey[2] != "" {
		t.Errorf("apiKey seen as %q: kept on the same host, dropped on another", gotKey)
	}
}

// A side-by-side program's ranges whose fix is on another line are not that
// line's fix: NVD's "before 3.12.4" for every Python does not say whether
// 3.11 was affected, so a 3.11 install needs validation, with no fix.
func TestSameLineOnly(t *testing.T) {
	py := winprograms.Default().Program("python")
	rng := func(from, fixed string) osv.Range {
		return osv.Range{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: from}, {Fixed: fixed}}}
	}
	eco := py.Ecosystem()
	advs := []store.AdvisoryMatch{
		{ID: "a", Ecosystem: eco, Affected: osv.Affected{Ranges: []osv.Range{rng("0", "3.12.4")}}},
		{ID: "b", Ecosystem: eco, Affected: osv.Affected{Ranges: []osv.Range{rng("3.11.0", "3.11.9"), rng("3.12.0", "3.12.4")}}},
		{ID: "c", Ecosystem: eco, Affected: osv.Affected{Versions: []string{"3.11.2", "3.12.1"}}},
	}
	got := sameLineOnly(py, "3.11", advs)
	var ids []string
	for _, a := range got {
		ids = append(ids, a.ID)
	}
	if !slices.Equal(ids, []string{"a", "b", "c"}) || !slices.Equal(got[2].Affected.Versions, []string{"3.11.2"}) ||
		len(got[1].Affected.Ranges) != 1 || got[1].Affected.Ranges[0].Events[1].Fixed != "3.11.9" {
		t.Fatalf("same line only: %+v", got)
	}
	// "a": an entry for versions on no listed line, read as needing validation.
	if !osv.UnlistedLine(eco, got[0].Affected) {
		t.Errorf("before 3.12.4 on 3.11: %+v", got[0].Affected)
	}
	v := &osv.Vulnerability{ID: "a", Affected: []osv.Affected{{Package: osv.Package{Ecosystem: eco, Name: "python"}, Ranges: got[0].Affected.Ranges}}}
	if hit, fix, unlisted := lineVerdict(t, v, "3.11.5"); hit || fix != "" || !unlisted {
		t.Errorf("3.11.5: affected %v fix %q unlisted %v", hit, fix, unlisted)
	}
	if advs[1].Affected.Ranges[1].Events[1].Fixed != "3.12.4" {
		t.Error("the cached advisories must not be changed")
	}
}
