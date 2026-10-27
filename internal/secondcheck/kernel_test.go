package secondcheck

import (
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

// Kernel packages as production reports them: binaries named after the
// kernel ABI and flavour, built from a kernel source package that the
// advisories name. The shapes are those of second.check job 436 on 0.9.0
// (295 false "package identity mismatch" disagreements on Ubuntu kernels).
func TestSecondCheckKernelSources(t *testing.T) {
	deb := func(release, name, upstream, version string) string {
		p := "pkg:deb/ubuntu/" + name + "@" + version + "?arch=amd64&distro=ubuntu-" + release
		if upstream != "" {
			p += "&upstream=" + upstream
		}
		return p
	}
	jammy := func(name, upstream, version string) string { return deb("22.04", name, upstream, version) }
	focal := func(name, upstream, version string) string { return deb("20.04", name, upstream, version) }
	ubuntu := func(eco, src, fixed string) store.RawAdvisoryRecord {
		return rec("UBUNTU-CVE-2099-1", eco, src, rng(`{"introduced":"0"},{"fixed":"`+fixed+`"}`))
	}
	jammyRec := func(src, fixed string) store.RawAdvisoryRecord { return ubuntu("Ubuntu:22.04:LTS", src, fixed) }
	focalRec := func(src, fixed string) store.RawAdvisoryRecord { return ubuntu("Ubuntu:20.04:LTS", src, fixed) }
	kernelClaim := func(fixed string, members ...string) Claim {
		ms := make([]any, len(members))
		for i, m := range members {
			ms[i] = m
		}
		return claim(fixed, map[string]any{"kernel_packages": ms, "osv_package": "linux"})
	}

	cases := []struct {
		name  string
		purl  string
		ev    map[string]string
		claim Claim
		recs  []store.RawAdvisoryRecord
		// result is the outcome; field and independent, for a
		// disagreement, the difference expected.
		result, field, independent string
	}{
		// Unfixed kernels agree as vulnerable.
		{name: "production: focal generic image from linux-signed, Ubuntu Pro listed version",
			purl:  focal("linux-image-5.4.0-216-generic", "linux-signed", "5.4.0-216.236"),
			claim: claim("", map[string]any{"kernel_packages": []any{"linux-image-5.4.0-216-generic", "linux-modules-5.4.0-216-generic"}, "osv_package": "linux", "requires_subscription": "Ubuntu Pro"}),
			recs: []store.RawAdvisoryRecord{
				rec("UBUNTU-CVE-2099-1", "Ubuntu:Pro:20.04:LTS", "linux", `{"versions":["5.4.0-215.235","5.4.0-216.236"]}`),
				rec("UBUNTU-CVE-2099-1", "Ubuntu:20.04:LTS", "linux-aws-5.15", `{"versions":["5.15.0-1084.91~20.04.1"]}`),
				rec("UBUNTU-CVE-2099-1", "Ubuntu:20.04:LTS", "linux-hwe-5.15", `{"versions":["5.15.0-139.149~20.04.1"]}`)},
			result: store.SecondCheckAgreed},
		{name: "jammy generic image from linux-signed, modules from linux",
			purl:   jammy("linux-image-5.15.0-91-generic", "linux-signed", "5.15.0-91.101"),
			claim:  kernelClaim("5.15.0-92.102", "linux-image-5.15.0-91-generic", "linux-modules-5.15.0-91-generic"),
			recs:   []store.RawAdvisoryRecord{jammyRec("linux", "5.15.0-92.102"), jammyRec("linux-aws", "5.15.0-1052.57")},
			result: store.SecondCheckAgreed},
		{name: "source package in evidence only, with its version",
			purl: jammy("linux-image-5.15.0-91-generic", "", "5.15.0-91.101"), ev: map[string]string{"source_package": "linux-signed (5.15.0-91.101)"},
			claim: kernelClaim("5.15.0-92.102"), recs: []store.RawAdvisoryRecord{jammyRec("linux", "5.15.0-92.102")},
			result: store.SecondCheckAgreed},
		{name: "modules built by linux directly",
			purl:  jammy("linux-modules-extra-5.15.0-91-generic", "linux", "5.15.0-91.101"),
			claim: kernelClaim("5.15.0-92.102"), recs: []store.RawAdvisoryRecord{jammyRec("linux", "5.15.0-92.102")},
			result: store.SecondCheckAgreed},
		{name: "focal hwe-5.15 kernel: backport suffix, the linux (5.4) record is not used",
			purl:   focal("linux-image-5.15.0-91-generic", "linux-signed-hwe-5.15", "5.15.0-91.101~20.04.1"),
			claim:  kernelClaim("5.15.0-92.102~20.04.1"),
			recs:   []store.RawAdvisoryRecord{focalRec("linux", "5.4.0-192.212"), focalRec("linux-hwe-5.15", "5.15.0-92.102~20.04.1")},
			result: store.SecondCheckAgreed},
		{name: "focal aws-5.15 stream: linux-signed-aws-5.15, not linux-aws",
			purl:   focal("linux-image-5.15.0-1050-aws", "linux-signed-aws-5.15", "5.15.0-1050.55~20.04.1"),
			claim:  kernelClaim("5.15.0-1052.57~20.04.1"),
			recs:   []store.RawAdvisoryRecord{focalRec("linux-aws", "5.4.0-1130.140"), focalRec("linux-aws-5.15", "5.15.0-1052.57~20.04.1")},
			result: store.SecondCheckAgreed},
		{name: "unsigned azure image built by its stream directly",
			purl:  jammy("linux-image-unsigned-5.15.0-1050-azure", "linux-azure", "5.15.0-1050.57"),
			claim: kernelClaim("5.15.0-1052.60"), recs: []store.RawAdvisoryRecord{jammyRec("linux-azure", "5.15.0-1052.60")},
			result: store.SecondCheckAgreed},
		{name: "modules-extra of the gcp stream",
			purl:  jammy("linux-modules-extra-5.15.0-1048-gcp", "linux-gcp", "5.15.0-1048.56"),
			claim: kernelClaim("5.15.0-1051.59"), recs: []store.RawAdvisoryRecord{jammyRec("linux-gcp", "5.15.0-1051.59")},
			result: store.SecondCheckAgreed},
		{name: "lowlatency flavour",
			purl:   jammy("linux-image-5.15.0-91-lowlatency", "linux-signed-lowlatency", "5.15.0-91.101"),
			claim:  kernelClaim("5.15.0-92.102"),
			recs:   []store.RawAdvisoryRecord{jammyRec("linux", "5.15.0-92.102"), jammyRec("linux-lowlatency", "5.15.0-92.102")},
			result: store.SecondCheckAgreed},
		{name: "oracle stream",
			purl:  jammy("linux-image-5.15.0-1051-oracle", "linux-signed-oracle", "5.15.0-1051.57"),
			claim: kernelClaim("5.15.0-1054.60"), recs: []store.RawAdvisoryRecord{jammyRec("linux-oracle", "5.15.0-1054.60")},
			result: store.SecondCheckAgreed},
		{name: "no fix released yet",
			purl:  jammy("linux-image-5.15.0-91-generic", "linux-signed", "5.15.0-91.101"),
			claim: kernelClaim(""), recs: []store.RawAdvisoryRecord{rec("UBUNTU-CVE-2099-1", "Ubuntu:22.04:LTS", "linux", rng(`{"introduced":"0"}`))},
			result: store.SecondCheckAgreed},
		{name: "Debian signed image for amd64",
			purl:  "pkg:deb/debian/linux-image-6.1.0-18-amd64@6.1.76-1?arch=amd64&distro=debian-12&upstream=linux-signed-amd64",
			claim: kernelClaim("6.1.85-1"), recs: []store.RawAdvisoryRecord{rec("DEBIAN-CVE-2099-1", "Debian:12", "linux", rng(`{"introduced":"0"},{"fixed":"6.1.85-1"}`))},
			result: store.SecondCheckAgreed},
		{name: "RHEL kernel-core reported for kernel, kernel-core and kernel-modules",
			purl: "pkg:rpm/redhat/kernel-core@5.14.0-362.8.1.el9_3?arch=x86_64&distro=rhel-9.4", ev: map[string]string{"source_rpm": "kernel-5.14.0-362.8.1.el9_3.src.rpm"},
			claim:  kernelClaim("0:5.14.0-427.13.1.el9_4", "kernel", "kernel-core", "kernel-modules"),
			recs:   []store.RawAdvisoryRecord{rec("RHSA-2024:2394", "Red Hat:enterprise_linux:9::baseos", "kernel-modules", rng(`{"introduced":"0"},{"fixed":"0:5.14.0-427.13.1.el9_4"}`))},
			result: store.SecondCheckAgreed},
		{name: "Amazon Linux 2 extras kernel 5.10",
			purl: "pkg:rpm/amzn/kernel@5.10.210-201.852.amzn2?arch=x86_64&distro=amzn-2", ev: map[string]string{"evr": "5.10.210-201.852.amzn2"},
			claim:  kernelClaim("5.10.213-201.855.amzn2", "kernel"),
			recs:   []store.RawAdvisoryRecord{rec("ALAS2KERNEL-5.10-2024-055", "Amazon Linux:2", "kernel", rng(`{"introduced":"0"},{"fixed":"5.10.213-201.855.amzn2"}`))},
			result: store.SecondCheckAgreed},

		// A fixed kernel that the matcher called affected still disagrees.
		{name: "generic kernel at the fix",
			purl:  jammy("linux-image-5.15.0-92-generic", "linux-signed", "5.15.0-92.102"),
			claim: kernelClaim("5.15.0-92.102"), recs: []store.RawAdvisoryRecord{jammyRec("linux", "5.15.0-92.102")},
			result: store.SecondCheckDisagreed, field: "affected", independent: "not affected"},
		{name: "hwe kernel above the fix, backport suffix",
			purl:  focal("linux-image-5.15.0-94-generic", "linux-signed-hwe-5.15", "5.15.0-94.104~20.04.1"),
			claim: kernelClaim("5.15.0-92.102~20.04.1"), recs: []store.RawAdvisoryRecord{focalRec("linux-hwe-5.15", "5.15.0-92.102~20.04.1")},
			result: store.SecondCheckDisagreed, field: "affected", independent: "not affected"},

		// Records for another kernel stream, or for no kernel, still disagree.
		{name: "aws image, only azure's record",
			purl:  jammy("linux-image-5.15.0-1050-aws", "linux-signed-aws", "5.15.0-1050.55"),
			claim: kernelClaim("5.15.0-1052.60"), recs: []store.RawAdvisoryRecord{jammyRec("linux-azure", "5.15.0-1052.60")},
			result: store.SecondCheckDisagreed, field: "package", independent: "name linux-azure"},
		{name: "aws-5.15 image, only the 5.4 linux-aws record",
			purl:  focal("linux-image-5.15.0-1050-aws", "linux-signed-aws-5.15", "5.15.0-1050.55~20.04.1"),
			claim: kernelClaim("5.4.0-1130.140"), recs: []store.RawAdvisoryRecord{focalRec("linux-aws", "5.4.0-1130.140")},
			result: store.SecondCheckDisagreed, field: "package", independent: "name linux-aws"},
		{name: "hwe-5.15 image, only the generic linux record",
			purl:  focal("linux-image-5.15.0-91-generic", "linux-signed-hwe-5.15", "5.15.0-91.101~20.04.1"),
			claim: kernelClaim("5.4.0-192.212"), recs: []store.RawAdvisoryRecord{focalRec("linux", "5.4.0-192.212")},
			result: store.SecondCheckDisagreed, field: "package", independent: "name linux"},
		{name: "a record for a package that is not a kernel",
			purl:  jammy("linux-image-5.15.0-91-generic", "linux-signed", "5.15.0-91.101"),
			claim: kernelClaim("1.2"), recs: []store.RawAdvisoryRecord{jammyRec("openssl", "3.0.2-0ubuntu1.15")},
			result: store.SecondCheckDisagreed, field: "package", independent: "name openssl"},
		{name: "metapackage: no kernel code, other version scheme, not mapped",
			purl:  jammy("linux-image-generic-hwe-22.04", "linux-meta-hwe-6.5", "6.5.0.35.35~22.04.1"),
			claim: claim("6.5.0-41.41~22.04.1", nil), recs: []store.RawAdvisoryRecord{jammyRec("linux-hwe-6.5", "6.5.0-41.41~22.04.1")},
			result: store.SecondCheckDisagreed, field: "package", independent: "name linux-hwe-6.5"},

		// Without an upstream or source package the kernel stream cannot
		// be told from the binary name: could not check, never a guess.
		{name: "unknown kernel source",
			purl:  jammy("linux-image-5.15.0-1050-aws", "", "5.15.0-1050.55"),
			claim: kernelClaim("5.15.0-1052.57"), recs: []store.RawAdvisoryRecord{jammyRec("linux-aws", "5.15.0-1052.57"), jammyRec("linux-aws-5.15", "5.15.0-1052.57~20.04.1")},
			result: store.SecondCheckCouldNotCheck},
		// SUSE kernels (kernel-default) stay could not check, as all SUSE.
		{name: "SUSE kernel",
			purl:   "pkg:rpm/suse/kernel-default@5.14.21-150500.55.49.1?distro=sles-15.5",
			claim:  kernelClaim("5.14.21-150500.55.52.1", "kernel-default"),
			result: store.SecondCheckCouldNotCheck},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := CheckVulnerability(c.claim, Observed{Purl: c.purl, Evidence: c.ev}, c.recs)
			if c.result == store.SecondCheckDisagreed {
				want(t, out, c.field, c.independent)
				return
			}
			if out.Result != c.result {
				t.Fatalf("got %s, want %s: %s %+v", out.Result, c.result, out.Reason, out.Differences)
			}
		})
	}
}

func TestKernelSourceName(t *testing.T) {
	for in, want := range map[[2]string]string{
		{"Ubuntu", "linux"}:                   "linux",
		{"Ubuntu", "linux-signed"}:            "linux",
		{"Ubuntu", "linux-signed-aws-5.15"}:   "linux-aws-5.15",
		{"Ubuntu", "linux-signed-hwe-6.5"}:    "linux-hwe-6.5",
		{"Ubuntu", "linux-signed-lowlatency"}: "linux-lowlatency",
		{"Ubuntu", "linux-oracle"}:            "linux-oracle",
		{"Ubuntu", "linux-azure-fde-5.15"}:    "linux-azure-fde-5.15",
		{"Debian", "linux-signed-amd64"}:      "linux",
		{"Debian", "linux-signed-5.10-arm64"}: "linux-5.10",
		{"Ubuntu", "linux-meta-hwe-6.5"}:      "",
		{"Ubuntu", "linux-meta"}:              "",
		{"Ubuntu", "linux-firmware"}:          "",
		{"Ubuntu", "linux-firmware-raspi"}:    "",
		{"Ubuntu", "linux-base"}:              "",
		{"Ubuntu", "openssl"}:                 "",
	} {
		if got, _ := kernelSourceName(in[0], in[1]); got != want {
			t.Errorf("%v = %q, want %q", in, got, want)
		}
	}
}
