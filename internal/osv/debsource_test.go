package osv

import (
	"testing"

	"github.com/stackurity/stackurity/internal/version"
)

// CVE-2026-24061 (USN "inetutils vulnerability") on Ubuntu 24.04: the
// advisory names the source package inetutils, fixed in 2:2.5-3ubuntu4.1.
func inetutilsAdvisory() Affected {
	return Affected{
		Package: Package{Ecosystem: "Ubuntu:24.04:LTS", Name: "inetutils"},
		Ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{
			{Introduced: "0"}, {Fixed: "2:2.5-3ubuntu4.1"},
		}}},
	}
}

// Production false positive (11 Nov 2026, analytics-lighthouse): the binary
// package telnet 0.17+2.5-3ubuntu4.2 is built from inetutils
// 2:2.5-3ubuntu4.2, newer than the fix. Comparing the binary's version
// (epoch 0) with the source's fixed version (epoch 2) reported it affected.
func TestTargetForDebSourceVersion(t *testing.T) {
	const purl = "pkg:deb/ubuntu/telnet@0.17%2B2.5-3ubuntu4.2?arch=amd64&distro=ubuntu-24.04&upstream=inetutils"
	ev := map[string]string{"db": "dpkg", "source_package": "inetutils", "source_version": "2:2.5-3ubuntu4.2"}
	tg, ok := TargetFor(purl, "0.17+2.5-3ubuntu4.2", ev)
	if !ok || tg.Ecosystem != "Ubuntu:24.04" || tg.Name != "inetutils" || tg.Version != "2:2.5-3ubuntu4.2" || !tg.SourceVersion {
		t.Fatalf("target = %+v %v", tg, ok)
	}
	m, err := Check(inetutilsAdvisory(), tg)
	if err != nil || m.Affected {
		t.Fatalf("telnet from inetutils 2:2.5-3ubuntu4.2 must not be affected: %+v %v", m, err)
	}

	// The same binary built from a source older than the fix is affected.
	old := map[string]string{"source_package": "inetutils", "source_version": "2:2.5-3ubuntu4"}
	tg, _ = TargetFor("pkg:deb/ubuntu/telnet@0.17%2B2.5-3ubuntu4?distro=ubuntu-24.04&upstream=inetutils", "0.17+2.5-3ubuntu4", old)
	if m, err := Check(inetutilsAdvisory(), tg); err != nil || !m.Affected || m.FixedVersion != "2:2.5-3ubuntu4.1" {
		t.Fatalf("telnet from inetutils 2:2.5-3ubuntu4 must be affected: %+v %v", m, err)
	}
}

// Older agents and SBOMs report no source version: the binary version is
// compared, as before. dpkg also omits it when it equals the binary's.
func TestTargetForDebNoSourceVersion(t *testing.T) {
	for _, c := range []struct {
		name, purl, ver string
		ev              map[string]string
		affected        bool
	}{
		{"binary equals source, affected", "pkg:deb/ubuntu/inetutils-telnetd@2:2.5-3ubuntu4?distro=ubuntu-24.04&upstream=inetutils",
			"2:2.5-3ubuntu4", map[string]string{"source_package": "inetutils"}, true},
		{"binary equals source, fixed", "pkg:deb/ubuntu/inetutils-telnetd@2:2.5-3ubuntu4.2?distro=ubuntu-24.04&upstream=inetutils",
			"2:2.5-3ubuntu4.2", map[string]string{"source_package": "inetutils"}, false},
		{"no evidence", "pkg:deb/ubuntu/inetutils-ftp@2:2.5-3ubuntu4.2?distro=ubuntu-24.04&upstream=inetutils",
			"", nil, false},
		// A source version without a source package says nothing usable.
		{"source version without source package", "pkg:deb/ubuntu/inetutils@2:2.5-3ubuntu4?distro=ubuntu-24.04",
			"", map[string]string{"source_version": "2:2.5-3ubuntu4.2"}, true},
	} {
		tg, ok := TargetFor(c.purl, c.ver, c.ev)
		if !ok || tg.Name != "inetutils" || tg.SourceVersion {
			t.Errorf("%s: target = %+v %v", c.name, tg, ok)
			continue
		}
		if m, err := Check(inetutilsAdvisory(), tg); err != nil || m.Affected != c.affected {
			t.Errorf("%s: %+v %v, want affected=%v", c.name, m, err, c.affected)
		}
	}
}

// The upstream qualifier may carry the source version itself: dpkg's
// "name (version)" or Syft's "name@version".
func TestTargetForDebUpstreamWithVersion(t *testing.T) {
	for _, up := range []string{"inetutils%402:2.5-3ubuntu4.2", "inetutils%20%282:2.5-3ubuntu4.2%29"} {
		tg, ok := TargetFor("pkg:deb/ubuntu/telnet@0.17%2B2.5-3ubuntu4.2?distro=ubuntu-24.04&upstream="+up, "", nil)
		if !ok || tg.Name != "inetutils" || tg.Version != "2:2.5-3ubuntu4.2" || tg.Compare != version.Debian {
			t.Errorf("upstream=%s: %+v %v", up, tg, ok)
		}
	}
	// The source_version evidence wins over a qualifier's.
	tg, _ := TargetFor("pkg:deb/debian/bash@5.2.15-2%2Bb2?distro=debian-12&upstream=bash%405.2.15-1", "",
		map[string]string{"source_version": "5.2.15-2"})
	if tg.Version != "5.2.15-2" || tg.Name != "bash" {
		t.Errorf("bash: %+v", tg)
	}
}
