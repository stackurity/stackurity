package secondcheck

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

func rec(id, eco, name, affected string) store.RawAdvisoryRecord {
	return store.RawAdvisoryRecord{ID: id, GroupKey: "CVE-2099-1", Ecosystem: eco, Name: name, Affected: json.RawMessage(affected)}
}

func rng(events string) string {
	return `{"ranges":[{"type":"ECOSYSTEM","events":[` + events + `]}]}`
}

func claim(fixed string, ev map[string]any) Claim {
	if ev == nil {
		ev = map[string]any{}
	}
	return Claim{Kind: "vulnerability", Key: "CVE-2099-1", FixedVersion: fixed, Evidence: ev}
}

func TestSecondCheckAgrees(t *testing.T) {
	cases := []struct {
		name  string
		purl  string
		ver   string
		ev    map[string]string
		recs  []store.RawAdvisoryRecord
		fixed string
		claim map[string]any
	}{
		{name: "npm range", purl: "pkg:npm/lodash@4.17.15", recs: []store.RawAdvisoryRecord{
			rec("GHSA-1", "npm", "lodash", rng(`{"introduced":"0"},{"fixed":"4.17.21"}`))}, fixed: "4.17.21"},
		{name: "scoped npm, last_affected", purl: "pkg:npm/%40babel/core@7.1.0", recs: []store.RawAdvisoryRecord{
			rec("GHSA-2", "npm", "@babel/core", rng(`{"introduced":"7.0.0"},{"last_affected":"7.1.0"}`))}},
		{name: "PyPI name normalised", purl: "pkg:pypi/Typing_Extensions@4.0.0", recs: []store.RawAdvisoryRecord{
			rec("PYSEC-1", "PyPI", "typing-extensions", `{"versions":["4.0.0","4.0.1"]}`)}},
		{name: "two ranges, highest fix of the two records", purl: "pkg:npm/x@1.5.0", recs: []store.RawAdvisoryRecord{
			rec("GHSA-3", "npm", "x", rng(`{"introduced":"1.0.0"},{"fixed":"1.6.0"}`)),
			rec("GHSA-4", "npm", "x", rng(`{"introduced":"1.0.0"},{"fixed":"1.7.0"}`))}, fixed: "1.7.0"},
		{name: "Debian source package", purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u1?distro=debian-12", ev: map[string]string{"source_package": "openssl"},
			recs: []store.RawAdvisoryRecord{
				rec("DEBIAN-CVE-2099-1", "Debian:12", "openssl", rng(`{"introduced":"0"},{"fixed":"3.0.11-1~deb12u2"}`)),
				rec("DEBIAN-CVE-2099-1", "Debian:11", "openssl", rng(`{"introduced":"0"},{"fixed":"1.1.1w-0+deb11u1"}`)),
			}, fixed: "3.0.11-1~deb12u2"},
		{name: "Ubuntu free channel wins over Pro", purl: "pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.14?distro=ubuntu-22.04",
			recs: []store.RawAdvisoryRecord{
				rec("UBUNTU-CVE-2099-1", "Ubuntu:22.04:LTS", "curl", rng(`{"introduced":"0"},{"fixed":"7.81.0-1ubuntu1.15"}`)),
				rec("UBUNTU-CVE-2099-1", "Ubuntu:Pro:22.04:LTS", "curl", rng(`{"introduced":"0"},{"fixed":"7.81.0-1ubuntu1.16"}`)),
			}, fixed: "7.81.0-1ubuntu1.15"},
		{name: "Ubuntu Pro only", purl: "pkg:deb/ubuntu/curl@7.68.0-1ubuntu2.20?distro=ubuntu-20.04",
			recs: []store.RawAdvisoryRecord{
				rec("UBUNTU-CVE-2099-1", "Ubuntu:Pro:20.04:LTS", "curl", rng(`{"introduced":"0"},{"fixed":"7.68.0-1ubuntu2.21+esm1"}`)),
			}, fixed: "7.68.0-1ubuntu2.21+esm1", claim: map[string]any{"requires_subscription": "Ubuntu Pro"}},
		{name: "rpm epoch from evr", purl: "pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?distro=rocky-9.3",
			ev:    map[string]string{"evr": "1:3.0.7-24.el9", "source_rpm": "openssl-3.0.7-24.el9.src.rpm"},
			recs:  []store.RawAdvisoryRecord{rec("RLSA-1", "Rocky Linux:9", "openssl", rng(`{"introduced":"0"},{"fixed":"1:3.0.7-25.el9_3"}`))},
			fixed: "1:3.0.7-25.el9_3"},
		{name: "RHEL stream", purl: "pkg:rpm/redhat/bash@5.1.8-6.el9?distro=rhel-9.4",
			recs:  []store.RawAdvisoryRecord{rec("RHSA-1", "Red Hat:enterprise_linux:9::baseos", "bash", rng(`{"introduced":"0"},{"fixed":"0:5.1.8-9.el9"}`))},
			fixed: "0:5.1.8-9.el9"},
		{name: "Oracle Linux release, Ksplice channel ignored for a regular build", purl: "pkg:rpm/ol/glibc@2.34-60.0.2.el9?distro=ol-9.4",
			recs: []store.RawAdvisoryRecord{
				rec("OL9-ELSA-2023-12850", "Oracle Linux:9", "glibc", rng(`{"introduced":"0"},{"fixed":"0:2.34-60.0.3.el9"}`)),
				rec("OL9-ELSA-2023-12854", "Oracle Linux:9:ksplice", "glibc", rng(`{"introduced":"0"},{"fixed":"2:2.34-60.0.3.ksplice1.el9"}`)),
				rec("OL8-ELSA-2023-12851", "Oracle Linux:8", "glibc", rng(`{"introduced":"0"},{"fixed":"0:2.28-225.0.4.el8"}`)),
			}, fixed: "0:2.34-60.0.3.el9"},
		{name: "Oracle Linux Ksplice build", purl: "pkg:rpm/ol/glibc@2.34-60.0.2.ksplice1.el9?distro=ol-9.2", ev: map[string]string{"evr": "2:2.34-60.0.2.ksplice1.el9"},
			recs: []store.RawAdvisoryRecord{
				rec("OL9-ELSA-2023-12850", "Oracle Linux:9", "glibc", rng(`{"introduced":"0"},{"fixed":"0:2.34-60.0.3.el9"}`)),
				rec("OL9-ELSA-2023-12854", "Oracle Linux:9:ksplice", "glibc", rng(`{"introduced":"0"},{"fixed":"2:2.34-60.0.3.ksplice1.el9"}`)),
			}, fixed: "2:2.34-60.0.3.ksplice1.el9"},
		{name: "Oracle Linux UEK line", purl: "pkg:rpm/ol/kernel-uek@5.15.0-6.80.3.el9uek?distro=ol-9.4",
			recs: []store.RawAdvisoryRecord{
				rec("OL9-ELSA-2023-12017", "Oracle Linux:9", "kernel-uek", rng(`{"introduced":"0:5.15.0"},{"fixed":"0:5.15.0-6.80.3.1.el9uek"}`)),
				rec("OL9-ELSA-2025-20368", "Oracle Linux:9", "kernel-uek", rng(`{"introduced":"0:6.12.0"},{"fixed":"0:6.12.0-100.28.2.el9uek"}`)),
			}, fixed: "0:5.15.0-6.80.3.1.el9uek"},
		{name: "Alpine release", purl: "pkg:apk/alpine/busybox@1.36.1-r15?distro=alpine-3.19.1",
			recs:  []store.RawAdvisoryRecord{rec("ALPINE-1", "Alpine:v3.19", "busybox", rng(`{"introduced":"0"},{"fixed":"1.36.1-r16"}`))},
			fixed: "1.36.1-r16"},
		{name: "Go stdlib prefix", purl: "pkg:golang/stdlib@go1.22.1",
			recs:  []store.RawAdvisoryRecord{rec("GO-1", "Go", "stdlib", `{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.22.2"}]}]}`)},
			fixed: "1.22.2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := CheckVulnerability(claim(c.fixed, c.claim), Observed{Purl: c.purl, Version: c.ver, Evidence: c.ev}, c.recs)
			if out.Result != store.SecondCheckAgreed {
				t.Fatalf("got %s: %s %+v", out.Result, out.Reason, out.Differences)
			}
		})
	}
}

// The deliberate disagreements: a second check must catch each.
func TestSecondCheckDisagrees(t *testing.T) {
	t.Run("corrupted range", func(t *testing.T) {
		// The matcher claimed < 4.17.21; the stored record says fixed in
		// 4.17.10 (a corrupted or changed range), so 4.17.15 is not affected.
		out := CheckVulnerability(claim("4.17.21", map[string]any{"matched_ranges": []any{"GHSA-1: < 4.17.21"}}),
			Observed{Purl: "pkg:npm/lodash@4.17.15"},
			[]store.RawAdvisoryRecord{rec("GHSA-1", "npm", "lodash", rng(`{"introduced":"0"},{"fixed":"4.17.10"}`))})
		want(t, out, "affected", "GHSA-1 (npm): not affected, fixed in 4.17.10")
	})
	t.Run("events swapped", func(t *testing.T) {
		// A range whose events were written in the wrong order: the
		// record lists fixed 2.0.0 before introduced 1.0.0 and nothing
		// after; read in order, 1.5.0 is not in a closed span.
		out := CheckVulnerability(claim("2.0.0", nil), Observed{Purl: "pkg:npm/x@0.5.0"},
			[]store.RawAdvisoryRecord{rec("GHSA-9", "npm", "x", rng(`{"fixed":"2.0.0"},{"introduced":"1.0.0"}`))})
		want(t, out, "affected", "not affected")
	})
	t.Run("package identity mismatch", func(t *testing.T) {
		out := CheckVulnerability(claim("4.17.21", map[string]any{"osv_package": "lodash", "target_ecosystem": "npm"}),
			Observed{Purl: "pkg:npm/lodahs@4.17.15"},
			[]store.RawAdvisoryRecord{rec("GHSA-1", "npm", "lodash", rng(`{"introduced":"0"},{"fixed":"4.17.21"}`))})
		want(t, out, "package", "name lodash, not lodahs")
		if out.Differences[0].Note != "package identity mismatch" {
			t.Errorf("note: %q", out.Differences[0].Note)
		}
	})
	t.Run("no record for the release", func(t *testing.T) {
		out := CheckVulnerability(claim("", nil), Observed{Purl: "pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=debian-12"},
			[]store.RawAdvisoryRecord{rec("DEBIAN-CVE-2099-1", "Debian:11", "openssl", rng(`{"introduced":"0"}`))})
		want(t, out, "package", "no record of CVE-2099-1 applies to Debian 12")
	})
	t.Run("backport fixed version the upstream range calls vulnerable", func(t *testing.T) {
		// Upstream fixed the issue in 3.0.12; Debian backported the fix to
		// 3.0.11 as 3.0.11-1~deb12u2. A match that read the upstream range
		// calls the installed backport vulnerable; the Debian record does not.
		c := claim("3.0.12", map[string]any{"matched_ranges": []any{"GHSA-up: >= 3.0.0, < 3.0.12"}})
		out := CheckVulnerability(c, Observed{Purl: "pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12"},
			[]store.RawAdvisoryRecord{
				rec("GHSA-up", "npm", "openssl", rng(`{"introduced":"3.0.0"},{"fixed":"3.0.12"}`)),
				rec("DEBIAN-CVE-2099-1", "Debian:12", "openssl", rng(`{"introduced":"0"},{"fixed":"3.0.11-1~deb12u2"}`)),
			})
		want(t, out, "affected", "not affected, fixed in 3.0.11-1~deb12u2")
		if !strings.Contains(out.Differences[0].Note, "backported") {
			t.Errorf("note: %q", out.Differences[0].Note)
		}
	})
	t.Run("fixed version", func(t *testing.T) {
		out := CheckVulnerability(claim("4.17.20", nil), Observed{Purl: "pkg:npm/lodash@4.17.15"},
			[]store.RawAdvisoryRecord{rec("GHSA-1", "npm", "lodash", rng(`{"introduced":"0"},{"fixed":"4.17.21"}`))})
		want(t, out, "fixed_version", "4.17.21")
	})
	t.Run("Oracle Linux FIPS record for a regular build", func(t *testing.T) {
		// A FIPS build's fix (epoch 10) never applies to a regular build.
		out := CheckVulnerability(claim("10:3.7.6-23.el9_3.4_fips", nil), Observed{Purl: "pkg:rpm/ol/gnutls@3.7.6-23.el9_3.3?distro=ol-9.4"},
			[]store.RawAdvisoryRecord{rec("OL9-ELSA-2024-12336", "Oracle Linux:9:fips", "gnutls", rng(`{"introduced":"0"},{"fixed":"10:3.7.6-23.el9_3.4_fips"}`))})
		want(t, out, "package", "no record of CVE-2099-1 applies to Oracle Linux 9.4")
	})
	t.Run("subscription", func(t *testing.T) {
		out := CheckVulnerability(claim("7.68.0-1ubuntu2.21", nil), Observed{Purl: "pkg:deb/ubuntu/curl@7.68.0-1ubuntu2.20?distro=ubuntu-20.04"},
			[]store.RawAdvisoryRecord{rec("U-1", "Ubuntu:Pro:20.04:LTS", "curl", rng(`{"introduced":"0"},{"fixed":"7.68.0-1ubuntu2.21"}`))})
		want(t, out, "subscription", "only a paid channel lists it")
	})
}

func want(t *testing.T, out Outcome, field, independent string) {
	t.Helper()
	if out.Result != store.SecondCheckDisagreed {
		t.Fatalf("want a disagreement on %s, got %s: %s", field, out.Result, out.Reason)
	}
	for _, d := range out.Differences {
		if d.Field == field && strings.Contains(d.Independent, independent) {
			if out.Reason == "" {
				t.Error("a disagreement needs a reason")
			}
			return
		}
	}
	t.Fatalf("no difference on %s containing %q: %+v", field, independent, out.Differences)
}

// Whatever the second check cannot read is "could not check", never a
// disagreement.
func TestSecondCheckCouldNotCheck(t *testing.T) {
	npm := []store.RawAdvisoryRecord{rec("GHSA-1", "npm", "x", rng(`{"introduced":"0"},{"fixed":"2.0.0-rc.1"}`))}
	cases := []struct {
		name, purl, reason string
		recs               []store.RawAdvisoryRecord
	}{
		{"pre-release", "pkg:npm/x@1.0.0-beta.2", "not plain dotted numbers", npm},
		{"pre-release fix", "pkg:npm/x@1.0.0", "not plain dotted numbers", npm},
		{"SUSE", "pkg:rpm/suse/openssl@3.0.8-150500.5.3.1?distro=sles-15.5", "SUSE", npm},
		{"FIPS build", "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.fips.20?distro=ubuntu-20.04", "FIPS", npm},
		{"no record stored", "pkg:npm/x@1.0.0", "no advisory record", nil},
		{"GIT range only", "pkg:npm/x@1.0.0", "GIT ranges", []store.RawAdvisoryRecord{
			rec("GHSA-1", "npm", "x", `{"ranges":[{"type":"GIT","events":[{"introduced":"abc"},{"fixed":"def"}]}]}`)}},
		{"Composer repository", "pkg:composer/a/b@1.0.0", "", []store.RawAdvisoryRecord{
			rec("GHSA-1", "Packagist:https://x", "a/b", rng(`{"introduced":"0"}`))}},
		{"unreadable purl", "npm/x@1", "could not be read", npm},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fixed := "2.0.0"
			if c.name == "Composer repository" {
				fixed = ""
			}
			out := CheckVulnerability(claim(fixed, nil), Observed{Purl: c.purl}, c.recs)
			if c.name == "Composer repository" {
				// Packages from another Composer repository: read, and agreed.
				if out.Result != store.SecondCheckAgreed {
					t.Fatalf("got %s: %s", out.Result, out.Reason)
				}
				return
			}
			if out.Result != store.SecondCheckCouldNotCheck || !strings.Contains(out.Reason, c.reason) {
				t.Fatalf("got %s: %q, want could not check with %q", out.Result, out.Reason, c.reason)
			}
		})
	}
}

func TestSecondCheckEndOfLife(t *testing.T) {
	past, future := time.Date(2024, 10, 7, 0, 0, 0, 0, time.UTC), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	cycles := []store.LifecycleCycle{{Product: "python", Cycle: "3.8", EOLUntil: &past}, {Product: "python", Cycle: "3.12", EOLUntil: &future}, {Product: "python", Cycle: "3", EOLUntil: &future}}
	eol := func(cycle string) Claim {
		return Claim{Kind: "end_of_life", Key: "python:" + cycle, Evidence: map[string]any{"product": "python", "cycle": cycle}}
	}
	if out := CheckEndOfLife(eol("3.8"), Observed{Purl: "pkg:generic/python@3.8.10", Version: "3.8.10"}, cycles, now); out.Result != store.SecondCheckAgreed {
		t.Fatalf("3.8.10: %s %s", out.Result, out.Reason)
	}
	out := CheckEndOfLife(eol("3"), Observed{Purl: "pkg:generic/python@3.8.10", Version: "3.8.10"}, cycles, now)
	want(t, out, "release_line", "3.8")
	out = CheckEndOfLife(eol("3.12"), Observed{Purl: "pkg:generic/python@3.12.1", Version: "3.12.1"}, cycles, now)
	want(t, out, "end_of_life", "supported until 2030-01-01")
	php := []store.LifecycleCycle{{Product: "php", Cycle: "7.4", IsEOL: true}}
	c := Claim{Kind: "end_of_life", Evidence: map[string]any{"product": "php", "cycle": "7.4"}}
	if out := CheckEndOfLife(c, Observed{Purl: "pkg:deb/debian/php7.4-common@7.4.33-1+deb11u5?distro=debian-11", Version: "7.4.33-1+deb11u5"}, php, now); out.Result != store.SecondCheckAgreed {
		t.Fatalf("php7.4-common: %s %s", out.Result, out.Reason)
	}
}

// Windows releases are checked by build against endoflife.date's latest
// build for each release, not by the matcher's table.
func TestSecondCheckWindows(t *testing.T) {
	past, future := time.Date(2020, 11, 10, 0, 0, 0, 0, time.UTC), time.Date(2029, 1, 9, 0, 0, 0, 0, time.UTC)
	now := time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)
	ended := time.Date(2027, 1, 12, 0, 0, 0, 0, time.UTC)
	cycles := []store.LifecycleCycle{
		{Product: "windows-server", Cycle: "2019", Latest: "10.0.17763", EOLUntil: &future},
		{Product: "windows-server", Cycle: "1809-sac", Latest: "10.0.17763", EOLUntil: &past, IsEOL: true},
		{Product: "windows-server", Cycle: "2016", Latest: "10.0.14393", EOLUntil: &ended},
	}
	claim := func(cycle string) Claim {
		return Claim{Kind: "end_of_life", Evidence: map[string]any{"product": "windows-server", "cycle": cycle}}
	}
	obs := func(v string) Observed { return Observed{Purl: "pkg:generic/windows@" + v, Version: v} }
	if out := CheckEndOfLife(claim("2016"), obs("10.0.14393.7428"), cycles, now); out.Result != store.SecondCheckAgreed {
		t.Fatalf("2016: %s %s", out.Result, out.Reason)
	}
	if out := CheckEndOfLife(claim("1809-sac"), obs("10.0.17763.1577"), cycles, now); out.Result != store.SecondCheckAgreed {
		t.Fatalf("1809 SAC: %s %s", out.Result, out.Reason)
	}
	want(t, CheckEndOfLife(claim("2019"), obs("10.0.17763.6532"), cycles, now), "end_of_life", "supported until 2029-01-09")
	want(t, CheckEndOfLife(claim("2016"), obs("10.0.17763.6532"), cycles, now), "release_line", "build 17763 is 2019 or 1809-sac")
	want(t, CheckEndOfLife(claim("2016"), obs("10.0.20348.1"), cycles, now), "release_line", "no release line of windows-server lists build 20348")
}

// Windows updates: the host's build against the fixed build of its own
// update line, with the second check's own reading of the line.
func TestSecondCheckWindowsUpdates(t *testing.T) {
	recs := []store.RawAdvisoryRecord{
		rec("MSRC-2025-Oct-CVE-2099-1", "Windows:Server 2022", "windows", rng(`{"introduced":"0"},{"fixed":"10.0.20348.4294"}`)),
		rec("MSRC-2025-Oct-CVE-2099-1", "Windows:Server 2019", "windows", rng(`{"introduced":"0"},{"fixed":"10.0.17763.7919"}`)),
		rec("MSRC-2025-Oct-CVE-2099-1", "Windows:11 24H2", "windows", rng(`{"introduced":"0"},{"fixed":"10.0.26100.6899"}`)),
	}
	obs := func(v, name, edition string) Observed {
		return Observed{Purl: "pkg:generic/windows@" + v, Version: v,
			Evidence: map[string]string{"kind": "operating-system", "product_name": name, "edition_id": edition}}
	}
	// .887 is below .4294 as numbers (not as text).
	if out := CheckVulnerability(claim("10.0.20348.4294", nil), obs("10.0.20348.887", "Windows Server 2022 Datacenter", "ServerDatacenter"), recs); out.Result != store.SecondCheckAgreed {
		t.Fatalf("Server 2022: %s %s", out.Result, out.Reason)
	}
	// Windows 11 reports "Windows 10" in its product name; Server 2025 shares its build but not its line.
	if out := CheckVulnerability(claim("10.0.26100.6899", nil), obs("10.0.26100.6584", "Windows 10 Pro", "Professional"), recs); out.Result != store.SecondCheckAgreed {
		t.Fatalf("Windows 11 24H2: %s %s", out.Result, out.Reason)
	}
	want(t, CheckVulnerability(claim("10.0.20348.4294", nil), obs("10.0.20348.4294", "Windows Server 2022 Datacenter", ""), recs), "affected", "")
	for _, c := range []struct{ v, name, edition, reason string }{
		{"10.0.20348.4171", "Windows Server 2022 Datacenter: Azure Edition", "ServerTurbine", "hotpatch"},
		{"10.0.17763.1577", "Windows Server Datacenter", "ServerDatacenterACor", "not an update line"},
		{"10.0.20348", "Windows Server 2022 Datacenter", "", "10.0.<build>.<revision>"},
	} {
		if out := CheckVulnerability(claim("10.0.20348.4294", nil), obs(c.v, c.name, c.edition), recs); out.Result != store.SecondCheckCouldNotCheck ||
			!strings.Contains(out.Reason, c.reason) {
			t.Errorf("%s %s: %s %q, want could not check with %q", c.v, c.name, out.Result, out.Reason, c.reason)
		}
	}
}

func TestComparators(t *testing.T) {
	type pair struct {
		a, b string
		want int
	}
	check := func(name string, c comparator, ps []pair) {
		for _, p := range ps {
			got, err := c(p.a, p.b)
			if err != nil || got != p.want {
				t.Errorf("%s(%q, %q) = %d, %v; want %d", name, p.a, p.b, got, err, p.want)
			}
			if back, _ := c(p.b, p.a); back != -p.want {
				t.Errorf("%s(%q, %q) is not antisymmetric", name, p.b, p.a)
			}
		}
	}
	check("dotted", dottedCompare, []pair{{"1.2.10", "1.2.9", 1}, {"1.0", "1.0.0", 0}, {"v2", "1.99", 1}, {"0", "0.0.1", -1}})
	check("dpkg", dpkgCompare, []pair{
		{"1.0~rc1", "1.0", -1}, {"1:1.0", "2.0", 1}, {"3.0.11-1~deb12u1", "3.0.11-1~deb12u2", -1},
		{"3.0.11-1~deb12u2", "3.0.11-1", -1}, {"1.0a", "1.0", 1}, {"1.0+b1", "1.0", 1}, {"2.36-9+deb12u4", "2.36-9+deb12u10", -1},
		{"7.81.0-1ubuntu1.15", "7.81.0-1ubuntu1.9", 1}, {"1.0-1", "1.0-1", 0},
	})
	check("rpm", rpmCompare, []pair{
		{"1:3.0.7-25.el9_3", "1:3.0.7-24.el9", 1}, {"0:1.0-1", "1.0-1", 0}, {"1:1.0-1", "2.0-1", 1}, {"1.0~rc1-1", "1.0-1", -1},
		{"1.0^git1-1", "1.0-1", 1}, {"1.0a-1", "1.0-1", 1}, {"1.10-1", "1.9-1", 1}, {"5.1.8-6.el9", "0:5.1.8-9.el9", -1},
	})
	check("apk", apkCompare, []pair{{"1.36.1-r15", "1.36.1-r16", -1}, {"1.2.3a-r0", "1.2.3-r9", 1}, {"3.0", "3.0-r0", 0}})
	for _, bad := range []string{"1.0.0-beta", "", "1..2", strings.Repeat("1.", 100) + "1"} {
		if _, err := dottedCompare(bad, "1"); err == nil {
			t.Errorf("dotted accepted %q", bad)
		}
	}
}

func TestParsePurl(t *testing.T) {
	p, err := parsePurl("pkg:npm/%40babel/core@7.1.0?foo=b%20ar#sub")
	if err != nil || p.typ != "npm" || p.namespace != "@babel" || p.name != "core" || p.version != "7.1.0" || p.qualifiers["foo"] != "b ar" {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := parsePurl("pkg:npm"); err == nil {
		t.Error("a purl without a name was read")
	}
}

func TestSecondCheckWindowsPrograms(t *testing.T) {
	recs := []store.RawAdvisoryRecord{
		rec("NVD-google-chrome-CVE-2099-1", "Windows programs:google-chrome", "google-chrome", rng(`{"introduced":"0"},{"fixed":"138.0.7204.96"}`)),
		rec("NVD-7-zip-CVE-2099-1", "Windows programs:7-zip", "7-zip", rng(`{"introduced":"0"},{"fixed":"24.09"}`)),
		rec("MSRC-2026-Oct-CVE-2099-1", "Windows programs:dotnet-runtime", "dotnet-runtime",
			`{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"8.0.32"}]},{"type":"ECOSYSTEM","events":[{"introduced":"9"},{"fixed":"9.0.21"}]}]}`),
	}
	obs := func(name, pub, v string) Observed {
		ev := map[string]string{"registry_view": "native"}
		if pub != "" {
			ev["publisher"] = pub
		}
		return Observed{Purl: "pkg:generic/" + strings.ReplaceAll(name, " ", "%20") + "@" + v, Version: v, Evidence: ev}
	}
	for _, c := range []struct {
		o     Observed
		fixed string
	}{
		{obs("Google Chrome", "Google LLC", "138.0.7204.93"), "138.0.7204.96"}, // .93 < .96 as numbers
		{obs("7-Zip 24.08 (x64)", "Igor Pavlov", "24.08"), "24.09"},
		{obs("7-Zip 24.08", "", "24.08"), "24.09"},
		// The version is read from the name; 9.0.3 is on the 9 line.
		{obs("Microsoft .NET Runtime - 9.0.3 (x64)", "Microsoft Corporation", "72.12.29501"), "9.0.21"},
	} {
		if out := CheckVulnerability(claim(c.fixed, nil), c.o, recs); out.Result != store.SecondCheckAgreed {
			t.Errorf("%s: %s %s", c.o.Purl, out.Result, out.Reason)
		}
	}
	// A wrong claim is found: the matcher said 8.0.32 for a 9.0 runtime.
	want(t, CheckVulnerability(claim("8.0.32", nil), obs("Microsoft .NET Runtime - 9.0.3 (x64)", "Microsoft Corporation", "72.12.29501"), recs), "fixed_version", "9.0.21")
	// Programs the catalogue does not match cannot be checked.
	for name, reason := range map[string]string{
		"Contoso App":                "not a catalogued Windows program",
		"Java 8 Update 491 (64-bit)": "recognised but not matched",
	} {
		pub := "Oracle Corporation"
		if out := CheckVulnerability(claim("1", nil), obs(name, pub, "1.0"), recs); out.Result != store.SecondCheckCouldNotCheck || !strings.Contains(out.Reason, reason) {
			t.Errorf("%s: %s %q", name, out.Result, out.Reason)
		}
	}
}
