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

var rpmKernelPkgs = map[string]bool{"kernel": true, "kernel-core": true, "kernel-modules": true, "kernel-modules-core": true,
	"kernel-modules-extra": true, "kernel-devel": true, "kernel-headers": false}

// KernelNotRunning reports whether a package belongs to a kernel that is
// installed but not the one running. Such packages expose nothing until
// someone boots them, so their findings are cleanup, not emergencies. It
// returns false whenever it cannot tell.
func KernelNotRunning(purlType, name, version, running string) bool {
	if running == "" {
		return false
	}
	switch purlType {
	case "deb":
		m := debKernelRE.FindStringSubmatch(name)
		r := kernelBaseRE.FindStringSubmatch(running)
		if m == nil || r == nil || strings.Contains(name, "-tools-common") {
			return false
		}
		return m[1] != r[1]
	case "rpm":
		if !rpmKernelPkgs[name] {
			return false
		}
		v := version
		if i := strings.IndexByte(v, ':'); i >= 0 {
			v = v[i+1:] // epoch
		}
		return !strings.HasPrefix(running, v)
	}
	return false
}
