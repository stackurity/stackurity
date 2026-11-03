package model

import (
	"strings"
	"testing"
)

func TestLeakValidation(t *testing.T) {
	good := Leak{Rule: "github-token", Title: "GitHub token", Severity: "critical", Path: "/srv/app/.env", Line: 3,
		Fingerprint: strings.Repeat("ab", 16), Preview: "ghp_…1a2b"}
	for _, tc := range []struct {
		name string
		edit func(*Leak)
		ok   bool
	}{
		{"good", func(*Leak) {}, true},
		{"served", func(l *Leak) { l.Exposure = ExposureServed }, true},
		{"bad exposure", func(l *Leak) { l.Exposure = "public" }, false},
		{"bad severity", func(l *Leak) { l.Severity = "urgent" }, false},
		// A fingerprint is never a raw value.
		{"raw value", func(l *Leak) { l.Fingerprint = "ghp_" + strings.Repeat("a", 28) }, false},
		{"no path", func(l *Leak) { l.Path = "" }, false},
		{"control", func(l *Leak) { l.Title = "x\x1b[31m" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBatch(Collector{ID: "repo"}, AssetRef{Kind: AssetRepository, Name: "r", Identifiers: []Identifier{{"git-url", "https://x/r"}}})
			l := good
			tc.edit(&l)
			b.Leaks = &LeakScan{Found: []Leak{l}, Complete: true}
			if err := b.Validate(); (err == nil) != tc.ok {
				t.Errorf("Validate() = %v, want ok=%v", err, tc.ok)
			}
		})
	}
	b := NewBatch(Collector{ID: "repo"}, AssetRef{Kind: AssetRepository, Name: "r", Identifiers: []Identifier{{"git-url", "https://x/r"}}})
	b.Leaks = &LeakScan{Found: make([]Leak, MaxLeaks+1)}
	if b.Validate() == nil {
		t.Error("too many leaks accepted")
	}
}
