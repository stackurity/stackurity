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
