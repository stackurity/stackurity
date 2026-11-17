package model

import (
	"strings"
	"testing"
)

func TestReachabilityValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    *Reachability
		ok   bool
	}{
		{"absent", nil, true},
		{"unknown without evidence", &Reachability{Status: ReachUnknown}, true},
		{"unknown with a reason", &Reachability{Status: ReachUnknown, Evidence: []string{"no read access to other users' processes"}}, true},
		{"not imported with evidence", &Reachability{Status: ReachNotImported, Evidence: []string{"no import in 214 source files"}}, true},
		{"reachable with evidence", &Reachability{Status: ReachReachable, Evidence: []string{"imported by src/app.js"}}, true},
		// A claim that something is not reached must say why.
		{"not running without evidence", &Reachability{Status: ReachNotRunning}, false},
		{"reachable without evidence", &Reachability{Status: ReachReachable}, false},
		{"bad status", &Reachability{Status: "safe", Evidence: []string{"x"}}, false},
		{"empty status", &Reachability{Evidence: []string{"x"}}, false},
		{"empty line", &Reachability{Status: ReachNotImported, Evidence: []string{""}}, false},
		{"long line", &Reachability{Status: ReachNotImported, Evidence: []string{strings.Repeat("a", MaxReachEvidenceLen+1)}}, false},
		{"control", &Reachability{Status: ReachNotImported, Evidence: []string{"x\x1b[31m"}}, false},
		{"too many lines", &Reachability{Status: ReachNotImported, Evidence: strings.Split(strings.Repeat("x,", MaxReachEvidence)+"x", ",")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBatch(Collector{ID: "repo"}, AssetRef{Kind: AssetRepository, Name: "r", Identifiers: []Identifier{{"git-url", "https://x/r"}}})
			o := Observation{Purl: "pkg:npm/lodash@4.17.20", Confidence: ConfidenceConfirmed, Reachability: tc.r}
			b.Observations = []Observation{o}
			if err := b.Validate(); (err == nil) != tc.ok {
				t.Errorf("Validate() = %v, want ok=%v", err, tc.ok)
			}
			if Usable(o) != tc.ok {
				t.Errorf("Usable() = %v, want %v", !tc.ok, tc.ok)
			}
		})
	}
}

func TestTrustedReach(t *testing.T) {
	mk := func(collector, purl, status, scope, reason string) (*ObservationBatch, *Observation) {
		b := NewBatch(Collector{ID: collector}, AssetRef{Kind: AssetHost, Name: "h"})
		b.Observations = []Observation{{Purl: purl, Reachability: &Reachability{Status: status, Evidence: []string{"x"}}}}
		if scope != "" {
			b.Cover(scope, "checked", reason)
		}
		return b, &b.Observations[0]
	}
	cases := []struct {
		name                                   string
		collector, purl, status, scope, reason string
		kept                                   bool
	}{
		{"agent, whole reading", ReachProcessCollector, "pkg:deb/debian/htop@3", ReachNotRunning, ReachProcessScope, "read 40 processes", true},
		{"apk", ReachProcessCollector, "pkg:apk/alpine/htop@3", ReachNotRunning, ReachProcessScope, "read 40 processes", true},
		{"partial", ReachProcessCollector, "pkg:deb/debian/htop@3", ReachNotRunning, ReachProcessScope, "partial: read 4 processes", false},
		{"access off", ReachProcessCollector, "pkg:deb/debian/htop@3", ReachNotRunning, ReachProcessScope, "process access is off: …", false},
		{"no coverage", ReachProcessCollector, "pkg:deb/debian/htop@3", ReachNotRunning, "", "", false},
		{"npm not running", ReachProcessCollector, "pkg:npm/lodash@4", ReachNotRunning, ReachProcessScope, "read 40 processes", false},
		{"other collector", "linux-docker", "pkg:deb/debian/htop@3", ReachNotRunning, ReachProcessScope, "read 40 processes", false},
		{"lockfile", ReachImportsCollector, "pkg:npm/lodash@4", ReachNotImported, ReachImportsScope, "read 3 JavaScript/TypeScript, 0 Go, 0 PHP and 0 Python source files", true},
		{"lockfile deb", ReachImportsCollector, "pkg:deb/debian/htop@3", ReachNotImported, ReachImportsScope, "read 3 JavaScript/TypeScript, 0 Go, 0 PHP and 0 Python source files", false},
		{"lockfile partial", ReachImportsCollector, "pkg:npm/lodash@4", ReachNotImported, ReachImportsScope, "partial: read 3 …", false},
		{"reachable from anyone", "test", "pkg:npm/lodash@4", ReachReachable, "", "", true},
	}
	for _, c := range cases {
		b, o := mk(c.collector, c.purl, c.status, c.scope, c.reason)
		if got := b.TrustedReach(o) != nil; got != c.kept {
			t.Errorf("%s: kept = %v, want %v", c.name, got, c.kept)
		}
	}
}
