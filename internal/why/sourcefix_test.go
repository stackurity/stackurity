package why

import (
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

// telnet 0.17+2.5-3ubuntu4 is built from inetutils 2:2.5-3ubuntu4; Ubuntu
// fixed CVE-2026-24061 in inetutils 2:2.5-3ubuntu4.1. The explanation says
// which version was compared and names the fix as the source's, never as a
// version of telnet (apt has no telnet 2:2.5-3ubuntu4.1).
func TestSentenceForABinaryWithItsOwnVersion(t *testing.T) {
	in := vuln(map[string]any{"matched_ranges": []any{"UBUNTU-CVE-2026-24061: < 2:2.5-3ubuntu4.1"}, "comparator": "debian",
		"target_ecosystem": "Ubuntu:24.04:LTS", "osv_package": "inetutils", "feed": "osv:Ubuntu", "installed": "2:2.5-3ubuntu4",
		"match": map[string]any{"rule": "range", "record": "UBUNTU-CVE-2026-24061", "source_version": "2:2.5-3ubuntu4"}})
	in.Finding.Key, in.Finding.ComponentType, in.Finding.ComponentName, in.Finding.AssetKind = "CVE-2026-24061", "deb", "ubuntu/telnet", "host"
	in.Finding.Version, in.Finding.FixedVersion = "0.17+2.5-3ubuntu4", "2:2.5-3ubuntu4.1"
	in.Inventory = store.InventoryProvenance{CollectorID: "linux-packages", Confidence: "confirmed", LastSeen: at(time.Hour)}
	in.Feed = &store.Feed{Name: "osv:Ubuntu", LastSuccess: at(3 * time.Hour)}
	e := Build(in, now)
	for _, want := range []string{
		"Installed 0.17+2.5-3ubuntu4 (built from inetutils 2:2.5-3ubuntu4;",
		"fixed in inetutils 2:2.5-3ubuntu4.1 (upgrade telnet to a build from it or later).",
	} {
		if !strings.Contains(e.Sentence, want) {
			t.Errorf("sentence %q lacks %q", e.Sentence, want)
		}
	}
	if e.Installed.Compared != "inetutils 2:2.5-3ubuntu4" {
		t.Errorf("compared %q", e.Installed.Compared)
	}
	if e.OS == nil || e.OS.SourceFix == nil || e.OS.SourceFix.Binary != "telnet" || e.OS.SourceFix.Fixed != "2:2.5-3ubuntu4.1" {
		t.Errorf("os %+v", e.OS)
	}

	// The binary's version is the source's: the fixed version is its own.
	in.Evidence["match"] = map[string]any{"rule": "range", "record": "UBUNTU-CVE-2026-24061"}
	in.Finding.ComponentName, in.Finding.Version = "ubuntu/inetutils-telnetd", "2:2.5-3ubuntu4"
	e = Build(in, now)
	if !strings.HasSuffix(e.Sentence, "; fixed in 2:2.5-3ubuntu4.1.") || strings.Contains(e.Sentence, "built from") || e.OS.SourceFix != nil {
		t.Errorf("same version: %s %+v", e.Sentence, e.OS)
	}
}
