package model

import (
	"strings"
	"testing"
)

func hostile() *ObservationBatch {
	b := NewBatch(Collector{ID: "plugin\x00x", Method: "plugin"}, AssetRef{Kind: AssetHost, Name: "web\x00-1\x1b[31m",
		Identifiers: []Identifier{{Scheme: "hostname", Value: "web-1\x07"}},
		Attributes:  map[string]string{"git_url": " JaVa\tScript:alert(1)", "homepage": "https://example.com", "os": "linux\x00"}})
	b.Observations = []Observation{{Purl: "pkg:npm/lodash@4.17.21", Confidence: ConfidenceConfirmed, Location: "a\x00b",
		Evidence: map[string]string{"link": "data:text/html,<script>", "source_url": "file:///etc/passwd", "note": "ok\u0085", "url": "https://x"}}}
	b.Coverage = []CoverageItem{{Scope: "npm\x00", Status: "checked", Reason: "\x00"}}
	return b
}

// Output from any scanner is cleaned before it is stored: NUL and control
// characters go (PostgreSQL refused NUL and failed the whole ingest), and a
// link value that would run code or read files when followed is dropped.
func TestUntrustedOutputIsCleaned(t *testing.T) {
	b := hostile()
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if b.Asset.Name != "web-1[31m" || b.Collector.ID != "pluginx" || b.Asset.Identifiers[0].Value != "web-1" || b.Asset.Attributes["os"] != "linux" {
		t.Errorf("asset: %+v %+v", b.Asset, b.Collector)
	}
	if _, ok := b.Asset.Attributes["git_url"]; ok || b.Asset.Attributes["homepage"] != "https://example.com" {
		t.Errorf("attributes: %+v", b.Asset.Attributes)
	}
	ev := b.Observations[0].Evidence
	if _, ok := ev["link"]; ok || ev["source_url"] != "" || ev["url"] != "https://x" || ev["note"] != "ok" || b.Observations[0].Location != "ab" {
		t.Errorf("observation: %+v", b.Observations[0])
	}
	if b.Coverage[0].Scope != "npm" || b.Coverage[0].Reason != "" {
		t.Errorf("coverage: %+v", b.Coverage)
	}
}

// Identity fields are refused, not cleaned: cleaning would change what is
// matched.
func TestUntrustedIdentityIsRefused(t *testing.T) {
	for _, o := range []Observation{
		{Purl: "pkg:npm/lodash@4.17.21\x00", Confidence: ConfidenceConfirmed},
		{Purl: "pkg:npm/lodash", Version: "4.17.21\x1b", Confidence: ConfidenceConfirmed},
		{Purl: "pkg:npm/lodash", Version: "4.17.21\xff", Confidence: ConfidenceConfirmed},
	} {
		if Usable(o) {
			t.Errorf("usable: %q %q", o.Purl, o.Version)
		}
		b := hostile()
		b.Observations = []Observation{o}
		if err := b.Validate(); err == nil {
			t.Errorf("accepted: %q %q", o.Purl, o.Version)
		}
	}
	b := hostile()
	b.Asset.Environment = strings.Repeat("p", MaxShortField+1)
	if err := b.Validate(); err == nil || !strings.Contains(err.Error(), "environment") {
		t.Errorf("long environment: %v", err)
	}
}

func TestUnsafeLink(t *testing.T) {
	for _, v := range []string{"javascript:x", " JAVASCRIPT:x", "java\tscript:x", "java\x00script:x", "data:,x", "vbscript:x", "file:/x"} {
		if !UnsafeLink(v) {
			t.Errorf("%q passed", v)
		}
	}
	for _, v := range []string{"https://x", "http://x", "git@github.com:a/b.git", "ssh://git@x/y", "/relative", ""} {
		if UnsafeLink(v) {
			t.Errorf("%q refused", v)
		}
	}
}

func TestKeepUsable(t *testing.T) {
	b := hostile()
	b.Complete = true
	b.Observations = append(b.Observations, Observation{Purl: "pkg:deb/debian/ba\x00sh@5.2", Confidence: ConfidenceConfirmed},
		Observation{Purl: "pkg:deb/debian/bash", Version: strings.Repeat("1", MaxFieldLen+1), Confidence: ConfidenceConfirmed})
	if n := b.KeepUsable(); n != 2 || len(b.Observations) != 1 || b.Complete {
		t.Fatalf("dropped %d, kept %d, complete %v", n, len(b.Observations), b.Complete)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
}
