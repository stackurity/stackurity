package secondcheck

import (
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

// Debian and Ubuntu records list source versions. telnet
// 0.17+2.5-3ubuntu4.2 is built from inetutils 2:2.5-3ubuntu4.2, past the
// fix for CVE-2026-24061 (2:2.5-3ubuntu4.1): a finding on it is a false
// positive the second check must catch (production, 11 Nov 2026).
func TestSecondCheckDebSourceVersion(t *testing.T) {
	inetutils := []store.RawAdvisoryRecord{
		rec("UBUNTU-CVE-2099-1", "Ubuntu:24.04:LTS", "inetutils", rng(`{"introduced":"0"},{"fixed":"2:2.5-3ubuntu4.1"}`)),
	}
	const noble = "?arch=amd64&distro=ubuntu-24.04&upstream=inetutils"

	out := CheckVulnerability(claim("2:2.5-3ubuntu4.1", nil), Observed{
		Purl: "pkg:deb/ubuntu/telnet@0.17%2B2.5-3ubuntu4.2" + noble, Version: "0.17+2.5-3ubuntu4.2",
		Evidence: map[string]string{"source_package": "inetutils", "source_version": "2:2.5-3ubuntu4.2"},
	}, inetutils)
	want(t, out, "affected", "not affected")

	// Built from a source before the fix: affected, agreed.
	out = CheckVulnerability(claim("2:2.5-3ubuntu4.1", nil), Observed{
		Purl: "pkg:deb/ubuntu/telnet@0.17%2B2.5-3ubuntu4" + noble, Version: "0.17+2.5-3ubuntu4",
		Evidence: map[string]string{"source_package": "inetutils", "source_version": "2:2.5-3ubuntu4"},
	}, inetutils)
	if out.Result != store.SecondCheckAgreed {
		t.Fatalf("source before the fix: %s %s %+v", out.Result, out.Reason, out.Differences)
	}

	// Binary version equals the source's (dpkg then omits it): compared as is.
	out = CheckVulnerability(claim("2:2.5-3ubuntu4.1", nil), Observed{
		Purl: "pkg:deb/ubuntu/inetutils-telnetd@2:2.5-3ubuntu4" + noble, Version: "2:2.5-3ubuntu4",
		Evidence: map[string]string{"source_package": "inetutils"},
	}, inetutils)
	if out.Result != store.SecondCheckAgreed {
		t.Fatalf("binary equals source: %s %s %+v", out.Result, out.Reason, out.Differences)
	}
}
