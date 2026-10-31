package store_test

import (
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

// TestNoVersionFixBySource: a component with no version is told what to do
// for where it came from, never lockfile advice for an SBOM or a host.
func TestNoVersionFixBySource(t *testing.T) {
	for _, c := range []struct{ location, collector, want, not string }{
		{"web/package.json", "lockfile", "Commit package-lock.json, yarn.lock or pnpm-lock.yaml next to web/package.json", ""},
		{"composer.json", "lockfile", "Commit composer.lock next to composer.json", ""},
		{"", "cyclonedx-import", "Include versions in the SBOM", "lockfile"},
		{"sbom.spdx.json", "spdx-import", "Include versions in the SBOM", "lockfile"},
		{"/var/lib/dpkg/status", "linux-agent", "The collector reported this component without a version", "lockfile"},
	} {
		fix, docs := store.UnreadableVersionFix("no_version", c.location, c.collector)
		if !strings.Contains(fix, c.want) || (c.not != "" && strings.Contains(fix, c.not)) || docs == "" {
			t.Errorf("%s from %s: %q (%s)", c.location, c.collector, fix, docs)
		}
	}
	// Other causes keep their own fix wherever they came from.
	if fix, _ := store.UnreadableVersionFix("windows_no_ubr", "", "windows-agent"); !strings.Contains(fix, "UBR") {
		t.Errorf("windows_no_ubr: %q", fix)
	}
}
