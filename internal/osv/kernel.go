package osv

import (
	"regexp"
	"strings"
)

// Debian/Ubuntu kernel packages embed the kernel ABI in the name, e.g.
// linux-image-5.4.0-190-generic, linux-modules-extra-5.15.0-91-generic,
// linux-headers-5.4.0-190.
var debKernelRE = regexp.MustCompile(`^linux-[a-z0-9.-]*?(\d+\.\d+\.\d+-\d+)(-[a-z0-9]+)?$`)
var kernelBaseRE = regexp.MustCompile(`^(\d+\.\d+\.\d+-\d+)`)

// KernelRole says how a distribution package relates to the kernel.
type KernelRole int

const (
	// NotKernel: any other package, matched on its own.
	NotKernel KernelRole = iota
	// KernelCode: the kernel image, its modules or tools built for one
	// installed kernel version. All such packages of one version share their
	// vulnerabilities, so they are reported once per version.
	KernelCode
	// KernelNoCode: headers, build files, documentation or source built
	// from the kernel source package. They contain no code that runs, so
	// kernel vulnerabilities do not apply to them.
	KernelNoCode
)

// debKernelNoCode reports Debian/Ubuntu packages built from a kernel source
// that hold no running kernel code.
func debKernelNoCode(name string) bool {
	switch {
	case name == "linux-libc-dev", name == "linux-doc", name == "linux-source":
		return true // userspace API headers, documentation, the source tree
	case strings.HasPrefix(name, "linux-") && strings.Contains(name, "-headers"):
		return true // linux-headers-5.4.0-190, linux-hwe-5.15-headers-5.15.0-91
	case strings.HasPrefix(name, "linux-") && (strings.HasSuffix(name, "-tools-common") || strings.HasSuffix(name, "-tools-host")):
		return true // version-independent wrapper scripts
	case strings.HasPrefix(name, "linux-source-"), strings.HasPrefix(name, "linux-") && strings.Contains(name, "-source-"):
		return true
	}
	return false
}

// rpmKernelFlavours are the flavour infixes of RPM kernel packages
// (kernel-rt-core, kernel-uek-modules, kernel-default-extra).
var rpmKernelFlavours = map[string]bool{"default": true, "rt": true, "debug": true, "uek": true, "64k": true, "azure": true,
	"kvmsmall": true, "zfcpdump": true, "preempt": true, "rt-debug": true, "64k-debug": true, "uek-debug": true}

// rpmKernelCodeParts are the package suffixes that carry kernel code.
var rpmKernelCodeParts = map[string]bool{"": true, "core": true, "modules": true, "modules-core": true, "modules-extra": true,
	"modules-internal": true, "base": true, "extra": true, "optional": true}

// rpmKernelNoCodeParts are the package suffixes with no running code:
// headers (userspace API headers), devel (module build tree), macros,
// source, documentation and ABI lists.
var rpmKernelNoCodeParts = map[string]bool{"headers": true, "devel": true, "devel-matched": true, "macros": true, "source": true,
	"source-vanilla": true, "doc": true, "syms": true, "abi-stablelists": true, "abi-whitelists": true}

func rpmKernelRole(name string) KernelRole {
	rest, ok := strings.CutPrefix(name, "kernel")
	if !ok || (rest != "" && rest[0] != '-') {
		return NotKernel
	}
	rest = strings.TrimPrefix(rest, "-")
	if rpmKernelNoCodeParts[rest] {
		return KernelNoCode
	}
	if rpmKernelCodeParts[rest] {
		return KernelCode
	}
	// A flavour, optionally followed by a part: kernel-rt-core,
	// kernel-default-devel, kernel-64k-debug-modules.
	for f := range rpmKernelFlavours {
		part, ok := strings.CutPrefix(rest, f)
		if !ok || (part != "" && part[0] != '-') {
			continue
		}
		part = strings.TrimPrefix(part, "-")
		switch {
		case rpmKernelNoCodeParts[part]:
			return KernelNoCode
		case rpmKernelCodeParts[part]:
			return KernelCode
		}
	}
	return NotKernel // kernel-tools, kernel-firmware, kernel-srpm-macros: ordinary packages
}

// KernelPackage classifies an OS package and returns the kernel release it
// belongs to: the ABI for Debian and Ubuntu ("5.4.0-190"), the version
// without epoch for RPM ("5.14.0-427.13.1.el9_4"). The release is "" when
// the package is not tied to one installed kernel (linux-libc-dev,
// kernel-headers).
func KernelPackage(purlType, name, version string) (KernelRole, string) {
	switch purlType {
	case "deb":
		m := debKernelRE.FindStringSubmatch(name)
		release := ""
		if m != nil {
			release = m[1]
		}
		switch {
		case debKernelNoCode(name):
			return KernelNoCode, release
		case m != nil:
			return KernelCode, release
		}
	case "rpm":
		role := rpmKernelRole(name)
		if role == NotKernel {
			return NotKernel, ""
		}
		if name == "kernel-headers" {
			return role, "" // userspace headers, one version for the system
		}
		v := version
		if i := strings.IndexByte(v, ':'); i >= 0 {
			v = v[i+1:] // epoch
		}
		return role, v
	}
	return NotKernel, ""
}

// KernelNotRunning reports whether a package belongs to a kernel that is
// installed but not the one running. Such packages expose nothing until
// someone boots them, so their findings are cleanup, not emergencies. It
// returns false whenever it cannot tell.
func KernelNotRunning(purlType, name, version, running string) bool {
	if running == "" {
		return false
	}
	role, release := KernelPackage(purlType, name, version)
	if role == NotKernel || release == "" {
		return false
	}
	switch purlType {
	case "deb":
		r := kernelBaseRE.FindStringSubmatch(running)
		return r != nil && release != r[1]
	case "rpm":
		return !rpmKernelRunning(release, running)
	}
	return false
}

// rpmKernelRunning reports whether the kernel package version v (no epoch)
// is the running kernel (uname -r). uname adds the architecture on Red Hat,
// Oracle and Amazon ("5.14.0-427.13.1.el9_4.x86_64", sometimes "+rt") and a
// flavour on SUSE, whose package release also carries a rebuild counter
// ("5.14.21-150500.55.39-default" for 5.14.21-150500.55.39.1).
func rpmKernelRunning(v, running string) bool {
	r := running
	if i := strings.IndexByte(r, '+'); i > 0 {
		r = r[:i]
	}
	if i := strings.LastIndexByte(r, '-'); i > 0 && isLetters(r[i+1:]) {
		r = r[:i]
	}
	return v == r || strings.HasPrefix(r, v+".") || strings.HasPrefix(v, r+".")
}

func isLetters(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// gaKernel is the kernel series each release shipped with. A release never
// carries a kernel series older than its own first one (its hardware
// enablement kernels are newer), so an installed kernel of an older series
// came from an earlier release.
var gaKernel = map[string]map[string]string{
	"ubuntu": {"14.04": "3.13", "16.04": "4.4", "18.04": "4.15", "20.04": "5.4", "22.04": "5.15",
		"24.04": "6.8", "24.10": "6.11", "25.04": "6.14", "25.10": "6.17"},
	"debian": {"9": "4.9", "10": "4.19", "11": "5.10", "12": "6.1", "13": "6.12"},
}

// elKernelRE finds the Enterprise Linux major release an RPM kernel was
// built for: "5.14.0-427.13.1.el9_4" is 9, Oracle's "5.15.0-208.159.3.el9uek" too.
var elKernelRE = regexp.MustCompile(`\.el(\d+)`)

var seriesRE = regexp.MustCompile(`^(\d+)\.(\d+)`)

// KernelFromEarlierRelease reports whether a kernel package (one with
// kernel code) was built for an earlier release of the host's distribution
// than the one the host now runs, as a kernel left behind by a release
// upgrade is (a 22.04 linux-image on a 24.04 host). distro is the purl
// qualifier ("ubuntu-24.04", "debian-12", "rhel-9.4"). It returns what the
// kernel was built for ("5.15", "el8") and the host's release ("24.04",
// "9.4"), and false whenever it cannot tell.
//
// The host release's advisories do not describe such a kernel: Ubuntu
// 24.04 lists fixes in 6.8 versions, which every 5.15 version sorts before,
// so each 24.04 kernel issue would match it.
func KernelFromEarlierRelease(purlType, namespace, name, version, distro string) (kernel, host string, earlier bool) {
	role, release := KernelPackage(purlType, name, version)
	if role != KernelCode || release == "" {
		return "", "", false
	}
	switch purlType {
	case "deb":
		ns := strings.ToLower(namespace)
		rel, ok := strings.CutPrefix(distro, ns+"-")
		if !ok || gaKernel[ns] == nil {
			return "", "", false
		}
		key := rel
		if ns == "debian" {
			key = majorOf(rel)
		}
		ga := gaKernel[ns][key]
		if ga == "" {
			return "", "", false
		}
		m := seriesRE.FindStringSubmatch(release)
		if m == nil {
			return "", "", false
		}
		series := m[1] + "." + m[2]
		if compareSeries(series, ga) < 0 {
			return series, rel, true
		}
	case "rpm":
		id, rel := rpmDistro(distro)
		switch id {
		case "rhel", "rocky", "almalinux", "ol":
		default:
			return "", "", false // SUSE and Amazon kernels do not name a release this way
		}
		m := elKernelRE.FindStringSubmatch(release)
		hostMajor := majorOf(rel)
		if m == nil || !isDigits(hostMajor) {
			return "", "", false
		}
		if atoi(m[1]) < atoi(hostMajor) {
			return "el" + m[1], rel, true
		}
	}
	return "", "", false
}

func compareSeries(a, b string) int {
	ma, mb := seriesRE.FindStringSubmatch(a), seriesRE.FindStringSubmatch(b)
	for i := 1; i <= 2; i++ {
		if x, y := atoi(ma[i]), atoi(mb[i]); x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
