package osv

import (
	"encoding/json"
	"strings"
	"testing"
)

// The evidence the matcher stores for telnet 0.17+2.5-3ubuntu4 (built from
// inetutils 2:2.5-3ubuntu4) against UBUNTU-CVE-2026-24061.
const telnetEvidence = `{"osv_package": "inetutils", "target_ecosystem": "Ubuntu:24.04:LTS", "installed": "2:2.5-3ubuntu4",
	"comparator": "debian", "match": {"rule": "range", "record": "UBUNTU-CVE-2026-24061", "source_version": "2:2.5-3ubuntu4"}}`

func TestSourceFixOf(t *testing.T) {
	s, ok := SourceFixOfJSON("ubuntu/telnet", json.RawMessage(telnetEvidence), "2:2.5-3ubuntu4.1")
	if !ok || s != (SourceFix{Binary: "telnet", Source: "inetutils", SourceVersion: "2:2.5-3ubuntu4", Fixed: "2:2.5-3ubuntu4.1"}) {
		t.Fatalf("%+v %v", s, ok)
	}
	if got := s.Target(); got != "telnet built from inetutils 2:2.5-3ubuntu4.1 or later" {
		t.Errorf("target %q", got)
	}
	adv := s.Advice()
	for _, want := range []string{"sudo apt-get install --only-upgrade telnet", "a build from inetutils 2:2.5-3ubuntu4.1 or later",
		"dpkg-query -W -f='${source:Version}\\n' telnet"} {
		if !strings.Contains(adv, want) {
			t.Errorf("advice %q lacks %q", adv, want)
		}
	}
	if strings.Contains(adv, "telnet 2:2.5-3ubuntu4.1") || strings.Contains(adv, "telnet to 2:2.5") {
		t.Errorf("advice names the source version as telnet's: %q", adv)
	}
	if !strings.Contains((SourceFix{Binary: "telnet", Source: "inetutils", SourceVersion: "2:2.5-3ubuntu4"}).Advice(), "no fixed inetutils version is listed") {
		t.Error("no fix listed")
	}

	// The binary's version is the source's (no source_version recorded),
	// older evidence, and other ecosystems: the fixed version is the
	// package's own.
	for _, ev := range []string{
		`{"osv_package": "inetutils", "match": {"rule": "range"}}`,
		`{"osv_package": "inetutils"}`,
		`{"osv_package": "lodash", "match": {"rule": "range", "normalised": "4.17.20"}}`,
		`{"match": {"source_version": "2:2.5-3ubuntu4"}}`,
		``, `not json`,
	} {
		if s, ok := SourceFixOfJSON("telnet", json.RawMessage(ev), "1"); ok {
			t.Errorf("%s: %+v", ev, s)
		}
	}
}
