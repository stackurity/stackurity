package linux

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// rebootState reports whether the host runs older code than is installed:
// the distro's reboot flag (Debian, Ubuntu), or a kernel newer than the
// running one. Updated packages do nothing until the process or kernel
// restarts, so a patched host can still be exposed.
//
// It returns host attributes: reboot_required is "true", "false" or
// "unknown" (no flag file and no kernel modules to compare, as in most
// containers).
func (c *Collector) rebootState() map[string]string {
	attrs := map[string]string{}
	var reasons []string
	flag := false
	for _, p := range []string{"run/reboot-required", "var/run/reboot-required"} {
		if _, err := os.Stat(c.path(p)); err == nil {
			flag = true
			reason := "the package manager requested a reboot"
			if pkgs := readLines(c.path(p+".pkgs"), 20); len(pkgs) > 0 {
				reason += " (" + strings.Join(pkgs, ", ") + ")"
			}
			reasons = append(reasons, reason)
			break
		}
	}

	known := flag
	running := strings.TrimSpace(readFirst(c.path("proc/sys/kernel/osrelease")))
	installed := c.installedKernels()
	if running != "" {
		attrs["kernel_running"] = running
	}
	if running != "" && len(installed) > 0 {
		known = true
		has := false
		var newest string
		for _, k := range installed {
			if k == running {
				has = true
			}
			if kernelFlavour(k) == kernelFlavour(running) && (newest == "" || naturalCompare(k, newest) > 0) {
				newest = k
			}
		}
		if newest != "" {
			attrs["kernel_latest_installed"] = newest
		}
		switch {
		case newest != "" && naturalCompare(newest, running) > 0:
			reasons = append(reasons, "kernel "+newest+" is installed but "+running+" is running")
		case !has:
			reasons = append(reasons, "the running kernel "+running+" is no longer installed")
		}
	}

	switch {
	case len(reasons) > 0:
		attrs["reboot_required"] = "true"
		attrs["reboot_reason"] = strings.Join(reasons, "; ")
	case known:
		attrs["reboot_required"] = "false"
		attrs["reboot_reason"] = ""
	default:
		attrs["reboot_required"] = "unknown"
		attrs["reboot_reason"] = "no reboot flag and no kernel modules to compare"
	}
	return attrs
}

// installedKernels lists kernel releases with a modules directory.
func (c *Collector) installedKernels() []string {
	seen := map[string]bool{}
	for _, dir := range []string{"lib/modules", "usr/lib/modules"} {
		entries, err := os.ReadDir(c.path(dir))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() && e.Name() != "" && unicode.IsDigit(rune(e.Name()[0])) {
				seen[e.Name()] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// kernelFlavour drops the digits from a kernel release, so that
// "6.8.0-45-generic" and "6.8.0-50-generic" compare as one flavour while
// "-generic" and "-lowlatency", or "-amd64" and "-cloud-amd64", do not.
func kernelFlavour(rel string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) {
			return -1
		}
		return r
	}, rel)
}

// naturalCompare orders strings with embedded numbers numerically.
func naturalCompare(a, b string) int {
	ac, bc := chunks(a), chunks(b)
	for i := 0; i < len(ac) && i < len(bc); i++ {
		x, y := ac[i], bc[i]
		xn, xerr := strconv.ParseUint(x, 10, 64)
		yn, yerr := strconv.ParseUint(y, 10, 64)
		switch {
		case xerr == nil && yerr == nil:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case x != y:
			return strings.Compare(x, y)
		}
	}
	return len(ac) - len(bc)
}

func chunks(s string) []string {
	var out []string
	start := 0
	for i := 1; i <= len(s); i++ {
		if i == len(s) || unicode.IsDigit(rune(s[i])) != unicode.IsDigit(rune(s[i-1])) {
			out = append(out, s[start:i])
			start = i
		}
	}
	return out
}

func readFirst(path string) string {
	if l := readLines(path, 1); len(l) > 0 {
		return l[0]
	}
	return ""
}

// readLines returns up to max non-empty, de-duplicated lines of a small file.
func readLines(path string, max int) []string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 64<<10 {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !seen[l] && len(out) < max {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}
