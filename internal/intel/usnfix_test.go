package intel

import (
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/version"
)

// The records of 23 Nov 2026: OSV kept UBUNTU-CVE-2026-118899 and
// UBUNTU-CVE-2026-123640 at "all versions, no fix" for 22.04 days after
// USN-9159-1 fixed both in 1.18.0-6ubuntu14.23, so hosts on 14.24 kept open
// findings that said "no fix".
func usnFixAdvs(usnEco, usnPkg string) []store.AdvisoryMatch {
	noFix := func(id, eco string) store.AdvisoryMatch {
		return store.AdvisoryMatch{ID: id, GroupKey: strings.TrimPrefix(id, "UBUNTU-"), Ecosystem: eco, SeverityLevel: "medium",
			Affected: osv.Affected{Package: osv.Package{Ecosystem: eco, Name: "nginx"},
				Ranges: []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}}}}}}
	}
	return []store.AdvisoryMatch{
		noFix("UBUNTU-CVE-2026-118899", "Ubuntu:22.04:LTS"),
		noFix("UBUNTU-CVE-2026-123640", "Ubuntu:22.04:LTS"),
		// No USN yet (USN-9182-1 was not in OSV): stays "no fix".
		noFix("UBUNTU-CVE-2026-125283", "Ubuntu:22.04:LTS"),
		{ID: "USN-9159-1", GroupKey: "USN-9159-1", Ecosystem: usnEco, SeverityLevel: "unknown",
			Upstream: []string{"UBUNTU-CVE-2026-113425", "UBUNTU-CVE-2026-118899", "UBUNTU-CVE-2026-123640"},
			Affected: osv.Affected{Package: osv.Package{Ecosystem: usnEco, Name: usnPkg},
				Ranges: []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "1.18.0-6ubuntu14.23"}}}}}},
	}
}

func usnFixMatch(t *testing.T, installed string, advs []store.AdvisoryMatch) map[string]store.FindingInput {
	t.Helper()
	tg := osv.Target{Ecosystem: "Ubuntu:22.04", Name: "nginx", Version: installed, Compare: version.Debian, SourceVersion: true}
	r := store.EvalRow{Purl: "pkg:deb/ubuntu/nginx@" + installed, Version: installed, Confidence: "confirmed", Type: "deb"}
	out, perr := matchAdvisories(r, tg, advs, store.Feed{Name: "osv:Ubuntu"})
	if perr != "" {
		t.Fatal(perr)
	}
	got := map[string]store.FindingInput{}
	for _, f := range out {
		got[f.Key] = f
	}
	return got
}

func TestUSNFixOverridesStaleUbuntuCVERecord(t *testing.T) {
	t.Run("USN fix installed", func(t *testing.T) {
		got := usnFixMatch(t, "1.18.0-6ubuntu14.24", usnFixAdvs("Ubuntu:22.04:LTS", "nginx"))
		for _, k := range []string{"CVE-2026-118899", "CVE-2026-123640", "USN-9159-1"} {
			if f, ok := got[k]; ok {
				t.Errorf("%s: USN-9159-1's fix 14.23 is installed (14.24), want no finding: %+v", k, f)
			}
		}
		f, ok := got["CVE-2026-125283"]
		if !ok || f.FixedVersion != "" || f.Evidence["match"].(map[string]any)["rule"] != "no_fix_listed" {
			t.Errorf("CVE-2026-125283 has no USN in the data: it stays open with no fix: %+v", f)
		}
	})
	t.Run("before the USN fix", func(t *testing.T) {
		got := usnFixMatch(t, "1.18.0-6ubuntu14.22", usnFixAdvs("Ubuntu:22.04:LTS", "nginx"))
		for _, k := range []string{"CVE-2026-118899", "CVE-2026-123640"} {
			f, ok := got[k]
			if !ok {
				t.Fatalf("%s: 14.22 is before USN-9159-1's fix, want a finding", k)
			}
			m := f.Evidence["match"].(map[string]any)
			if f.FixedVersion != "1.18.0-6ubuntu14.23" || m["fix_from"] != "USN-9159-1" || m["rule"] != "range" || m["record"] != "UBUNTU-"+k {
				t.Errorf("%s: want fixed 14.23 from USN-9159-1 decided by UBUNTU-%s: fixed=%q match=%v", k, k, f.FixedVersion, m)
			}
			if !strings.Contains(strings.Join(f.Sources, ","), "USN-9159-1") {
				t.Errorf("%s: the USN must be cited as a source (the second check reads it): %v", k, f.Sources)
			}
		}
	})
	t.Run("USN for another release", func(t *testing.T) {
		got := usnFixMatch(t, "1.18.0-6ubuntu14.24", usnFixAdvs("Ubuntu:24.04:LTS", "nginx"))
		if f, ok := got["CVE-2026-118899"]; !ok || f.FixedVersion != "" {
			t.Errorf("a 24.04 USN says nothing about 22.04: want the no-fix finding kept: %+v", f)
		}
	})
	t.Run("USN for another package", func(t *testing.T) {
		got := usnFixMatch(t, "1.18.0-6ubuntu14.24", usnFixAdvs("Ubuntu:22.04:LTS", "openssl"))
		if f, ok := got["CVE-2026-118899"]; !ok || f.FixedVersion != "" {
			t.Errorf("a USN for openssl says nothing about nginx: want the no-fix finding kept: %+v", f)
		}
	})
	t.Run("USN for a Pro channel", func(t *testing.T) {
		got := usnFixMatch(t, "1.18.0-6ubuntu14.24", usnFixAdvs("Ubuntu:Pro:22.04:LTS", "nginx"))
		if f, ok := got["CVE-2026-118899"]; !ok || f.FixedVersion != "" {
			t.Errorf("only a free-channel USN replaces the free record's no fix: %+v", f)
		}
	})
}
