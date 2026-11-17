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
	agent, scan := ReachTrust{Processes: true}, ReachTrust{Imports: true}
	mk := func(kind AssetKind, collector, purl, status, scope, reason string) (*ObservationBatch, *Observation) {
		b := NewBatch(Collector{ID: collector}, AssetRef{Kind: kind, Name: "h"})
		b.Observations = []Observation{{Purl: purl, Reachability: &Reachability{Status: status, Evidence: []string{"x"}}}}
		if scope != "" {
			b.Cover(scope, "checked", reason)
		}
		return b, &b.Observations[0]
	}
	const readJS = "read 3 JavaScript/TypeScript, 0 Go, 0 PHP and 0 Python source files"
	cases := []struct {
		name                                   string
		trust                                  ReachTrust
		kind                                   AssetKind
		collector, purl, status, scope, reason string
		kept                                   bool
	}{
		{"agent, whole reading", agent, AssetHost, ReachProcessCollector, "pkg:deb/debian/htop@3", ReachNotRunning, ReachProcessScope, "read 40 processes", true},
		{"apk", agent, AssetHost, ReachProcessCollector, "pkg:apk/alpine/htop@3", ReachNotRunning, ReachProcessScope, "read 40 processes", true},
		{"not an agent's token", scan, AssetHost, ReachProcessCollector, "pkg:deb/debian/htop@3", ReachNotRunning, ReachProcessScope, "read 40 processes", false},
		{"no token", ReachTrust{}, AssetHost, ReachProcessCollector, "pkg:deb/debian/htop@3", ReachNotRunning, ReachProcessScope, "read 40 processes", false},
		{"not a host", agent, AssetImage, ReachProcessCollector, "pkg:deb/debian/htop@3", ReachNotRunning, ReachProcessScope, "read 40 processes", false},
		{"partial", agent, AssetHost, ReachProcessCollector, "pkg:deb/debian/htop@3", ReachNotRunning, ReachProcessScope, "partial: read 4 processes", false},
		{"access off", agent, AssetHost, ReachProcessCollector, "pkg:deb/debian/htop@3", ReachNotRunning, ReachProcessScope, "process access is off: …", false},
		{"no coverage", agent, AssetHost, ReachProcessCollector, "pkg:deb/debian/htop@3", ReachNotRunning, "", "", false},
		{"npm not running", agent, AssetHost, ReachProcessCollector, "pkg:npm/lodash@4", ReachNotRunning, ReachProcessScope, "read 40 processes", false},
		{"other collector", agent, AssetHost, "linux-docker", "pkg:deb/debian/htop@3", ReachNotRunning, ReachProcessScope, "read 40 processes", false},
		{"source scan", scan, AssetRepository, ReachImportsCollector, "pkg:npm/lodash@4", ReachNotImported, ReachImportsScope, readJS, true},
		{"agent's token claims imports", agent, AssetRepository, ReachImportsCollector, "pkg:npm/lodash@4", ReachNotImported, ReachImportsScope, readJS, false},
		{"imports for a host", scan, AssetHost, ReachImportsCollector, "pkg:npm/lodash@4", ReachNotImported, ReachImportsScope, readJS, false},
		{"lockfile deb", scan, AssetRepository, ReachImportsCollector, "pkg:deb/debian/htop@3", ReachNotImported, ReachImportsScope, readJS, false},
		{"lockfile partial", scan, AssetRepository, ReachImportsCollector, "pkg:npm/lodash@4", ReachNotImported, ReachImportsScope, "partial: read 3 …", false},
		{"reachable from anyone", ReachTrust{}, AssetHost, "test", "pkg:npm/lodash@4", ReachReachable, "", "", true},
	}
	for _, c := range cases {
		b, o := mk(c.kind, c.collector, c.purl, c.status, c.scope, c.reason)
		if got := b.TrustedReach(o, c.trust) != nil; got != c.kept {
			t.Errorf("%s: kept = %v, want %v", c.name, got, c.kept)
		}
	}
}
