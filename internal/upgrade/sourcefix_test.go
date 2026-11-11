package upgrade

import (
	"strings"
	"testing"
)

// telnet 0.17+2.5-3ubuntu4 is built from inetutils 2:2.5-3ubuntu4, and
// Ubuntu's advisory for CVE-2026-24061 lists the fix as inetutils
// 2:2.5-3ubuntu4.1. apt has no telnet 2:2.5-3ubuntu4.1, so that version must
// never be recommended for telnet: the advice names the package to upgrade
// and the source build with the fix.
func TestRecommendBinaryWithItsOwnVersion(t *testing.T) {
	in := Input{PurlType: "deb", Installed: "0.17+2.5-3ubuntu4", Package: "telnet", SourcePackage: "inetutils", SourceVersion: "2:2.5-3ubuntu4",
		Findings: []Finding{vuln("CVE-2026-24061", "2:2.5-3ubuntu4.1"), vuln("CVE-NOFIX", "")}, Now: now}
	got := Recommend(in)
	if got.Recommended != "" {
		t.Errorf("recommended %q: apt cannot install that version of telnet", got.Recommended)
	}
	if got.Basis != BasisDistroSourceFixed || got.MinimumFixed != "2:2.5-3ubuntu4.1" || got.ChangeType != "distro" || got.RequiresMajor {
		t.Errorf("got %+v", got)
	}
	if got.Source == nil || got.Source.Binary != "telnet" || got.Source.Source != "inetutils" ||
		got.Source.SourceVersion != "2:2.5-3ubuntu4" || got.Source.Fixed != "2:2.5-3ubuntu4.1" {
		t.Errorf("source %+v", got.Source)
	}
	if strings.Join(got.Fixes, ",") != "CVE-2026-24061" || strings.Join(got.Unfixed, ",") != "CVE-NOFIX" {
		t.Errorf("fixes %v unfixed %v", got.Fixes, got.Unfixed)
	}
	why := strings.Join(got.Rationale, " ")
	for _, want := range []string{
		"Upgrade telnet to a build from inetutils 2:2.5-3ubuntu4.1 or later (sudo apt-get install --only-upgrade telnet)",
		"dpkg-query -W -f='${source:Version}\\n' telnet",
	} {
		if !strings.Contains(why, want) {
			t.Errorf("rationale %q lacks %q", why, want)
		}
	}
	if strings.Contains(why, "telnet 2:2.5") || strings.Contains(why, "to 2:2.5") {
		t.Errorf("rationale offers the source version as telnet's: %q", why)
	}
	checkNoInvented(t, in, got)

	// Behind a subscription: still no binary target, the channel is named.
	in.Findings = []Finding{{Kind: "vulnerability", Key: "CVE-2026-24061", FixedVersion: "2:2.5-3ubuntu4.1", Subscription: "Ubuntu Pro"}}
	if got := Recommend(in); got.Recommended != "" || got.Source == nil || got.Subscription != "Ubuntu Pro" {
		t.Errorf("subscription: %+v", got)
	}

	// No fixed version listed: nothing to name, as before.
	in.Findings = []Finding{vuln("CVE-NOFIX", "")}
	if got := Recommend(in); got.Recommended != "" || got.Source != nil || got.Basis != BasisNone {
		t.Errorf("no fix: %+v", got)
	}
}

// When the binary package's version is the source's (dpkg then writes no
// source version, and the matcher records none), the fixed version is the
// binary's own and is recommended as before.
func TestRecommendBinaryWithTheSourceVersion(t *testing.T) {
	in := Input{PurlType: "deb", Installed: "2:2.5-3ubuntu4", Package: "inetutils-telnetd",
		Findings: []Finding{vuln("CVE-2026-24061", "2:2.5-3ubuntu4.1")}, Now: now}
	got := Recommend(in)
	if got.Recommended != "2:2.5-3ubuntu4.1" || got.Basis != BasisDistroFixed || got.Source != nil {
		t.Errorf("got %+v", got)
	}
	checkNoInvented(t, in, got)
}
