package confcheck

import (
	"bufio"
	"bytes"
	"path"
	"sort"
	"strings"

	"github.com/stackurity/stackurity/internal/model"
)

// Kernel modules an attacker who already runs code on a server can use to
// become root. The first is SCTP: in November 2026 Xint used a
// use-after-free in the Linux kernel's SCTP send path (present since Linux
// 4.15) as the last step of "nginx2root", from a compromised nginx worker
// to root, from inside a Docker container. The kernel bug has no CVE and no
// fix yet, so no package version can be matched: what can be checked is
// whether the module is loaded, built in, or can be loaded. An unprivileged
// process that opens an SCTP socket makes the kernel load the module on its
// own, so "loadable" is enough for the attack.
//
// Only files are read: /proc/modules, /sys/module, /proc/cmdline,
// /proc/sys/kernel, the running kernel's module tree and modprobe.d. When
// the running kernel's release cannot be read (a mounted root without
// /proc, an image) nothing is reported.

// Kernel module rules.
const (
	// RuleKernelSCTP: the SCTP module is loaded, built into the kernel, or
	// can be loaded (it is installed and no modprobe.d install line or
	// module_blacklist stops it). One rule; the subject says which.
	RuleKernelSCTP = "kernel-sctp-loadable"
)

// KernelModulesDoc is the how-to every kernel module finding links to.
const KernelModulesDoc = "https://stackurity.ai/docs/config-checks#kernel-modules"

// modprobeDirs are read in this order; a file name in an earlier directory
// hides the same name in a later one, as modprobe does.
var modprobeDirs = []string{"/etc/modprobe.d", "/run/modprobe.d", "/usr/local/lib/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"}

// moduleTrees are where a kernel release's modules are installed (/lib is
// /usr/lib on merged-/usr systems, but not everywhere).
var moduleTrees = []string{"/lib/modules", "/usr/lib/modules"}

// sctpState is what the host says about the SCTP module.
type sctpState struct {
	release   string
	loaded    string // the file that shows it loaded, or ""
	builtin   string // modules.builtin that lists it, or ""
	module    string // the installed module file, or ""
	blocked   string // the modprobe.d file and line, or kernel setting, that stops loading, or ""
	blacklist string // a modprobe.d file with "blacklist sctp" (does not stop the attack), or ""
}

// kernelModules reports the SCTP module when the host could load it.
func (h *hostFS) kernelModules() []model.ConfigFinding {
	s, ok := h.sctp()
	if !ok {
		return nil
	}
	f, ok := sctpFinding(s)
	if !ok {
		return nil
	}
	return []model.ConfigFinding{f}
}

// sctp reads the SCTP module's state. ok is false when the running
// kernel's release is unknown, so nothing can be said.
func (h *hostFS) sctp() (s sctpState, ok bool) {
	rel, _ := h.read("/proc/sys/kernel/osrelease", 4096)
	s.release = strings.TrimSpace(string(rel))
	if s.release == "" || strings.ContainsAny(s.release, "/ \t") {
		return s, false
	}
	if mods, _ := h.read("/proc/modules", 4<<20); moduleListed(mods) {
		s.loaded = "/proc/modules"
	}
	for _, tree := range moduleTrees {
		dir := path.Join(tree, s.release)
		if s.builtin == "" {
			b, _ := h.read(path.Join(dir, "modules.builtin"), 4<<20)
			if builtinListed(b) {
				s.builtin = path.Join(dir, "modules.builtin")
			}
		}
		if s.module == "" {
			for _, ext := range []string{".ko", ".ko.xz", ".ko.zst", ".ko.gz"} {
				p := path.Join(dir, "kernel/net/sctp/sctp"+ext)
				if _, ok := h.regular(p); ok {
					s.module = p
					break
				}
			}
		}
	}
	if s.loaded == "" && s.builtin == "" && h.exists("/sys/module/sctp") {
		// /sys/module has a directory for every loaded module, and for
		// built-in ones with parameters.
		s.loaded = "/sys/module/sctp"
	}
	if d, _ := h.read("/proc/sys/kernel/modules_disabled", 64); strings.TrimSpace(string(d)) == "1" {
		s.blocked = "/proc/sys/kernel/modules_disabled is 1"
	} else if c, _ := h.read("/proc/cmdline", 64<<10); cmdlineBlocks(string(c)) {
		s.blocked = "module_blacklist=sctp on the kernel command line"
	} else {
		s.blocked, s.blacklist = h.modprobeSCTP()
	}
	return s, true
}

// moduleListed reports whether /proc/modules lists sctp.
func moduleListed(data []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) > 0 && f[0] == "sctp" {
			return true
		}
	}
	return false
}

// builtinListed reports whether modules.builtin lists the SCTP module.
func builtinListed(data []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "kernel/net/sctp/sctp.ko" {
			return true
		}
	}
	return false
}

// cmdlineBlocks reports whether the kernel command line refuses to load
// sctp (module_blacklist=a,b,…).
func cmdlineBlocks(cmdline string) bool {
	for _, a := range strings.Fields(cmdline) {
		if v, ok := strings.CutPrefix(a, "module_blacklist="); ok {
			for _, m := range strings.Split(v, ",") {
				if m == "sctp" {
					return true
				}
			}
		}
	}
	return false
}

// modprobeSCTP reads the modprobe.d files (*.conf, one name hiding the same
// name in a later directory) for "install sctp /bin/false" (or true, or
// any command ending in false or true), which makes every load of the
// module run that command instead, and "blacklist sctp", which only stops
// loading by alias and so not the kernel's own load when a socket asks for
// SCTP. It returns where each is, "" for none.
func (h *hostFS) modprobeSCTP() (blocked, blacklist string) {
	files := map[string]string{} // file name -> host path
	for _, dir := range modprobeDirs {
		for _, e := range h.readDir(dir) {
			name := e.Name()
			if !strings.HasSuffix(name, ".conf") || files[name] != "" {
				continue
			}
			files[name] = path.Join(dir, name)
		}
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names) // modprobe reads them in name order
	for _, n := range names {
		p := files[n]
		data, _ := h.read(p, 1<<20)
		for _, line := range modprobeLines(data) {
			f := strings.Fields(line)
			if len(f) < 2 || f[1] != "sctp" {
				continue
			}
			switch f[0] {
			case "install":
				if len(f) >= 3 && noopCommand(f[2]) && blocked == "" {
					blocked = p + ": " + line
				}
			case "blacklist":
				if blacklist == "" {
					blacklist = p
				}
			}
		}
	}
	return blocked, blacklist
}

// modprobeLines are a modprobe.d file's lines, comments dropped and lines
// ending in a backslash joined to the next.
func modprobeLines(data []byte) []string {
	var out []string
	var cur strings.Builder
	for _, raw := range strings.Split(string(data), "\n") {
		l := strings.TrimRight(raw, " \t\r")
		if strings.HasSuffix(l, "\\") {
			cur.WriteString(strings.TrimSuffix(l, "\\") + " ")
			continue
		}
		cur.WriteString(l)
		line := strings.TrimSpace(cur.String())
		cur.Reset()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.Join(strings.Fields(line), " "))
	}
	return out
}

// noopCommand reports whether an install command does nothing: false or
// true, by any path (/bin/false, /usr/bin/true).
func noopCommand(cmd string) bool {
	b := path.Base(cmd)
	return b == "false" || b == "true"
}

// sctpFinding grades the SCTP module's state: medium when it is loaded or
// built in (a modprobe.d line cannot stop it), low when it is installed and
// nothing stops it loading; none when it is not installed, or blocked and
// not loaded.
func sctpFinding(s sctpState) (model.ConfigFinding, bool) {
	const title = "SCTP kernel module can be used to become root"
	risk := "A use-after-free in the Linux kernel's SCTP code (since Linux 4.15, no CVE and no fix yet, Nov 2026) lets a " +
		"program that already runs on this server, as any user, become root; it was the last step of the nginx2root attack, " +
		"after a compromised nginx worker. It matters where code you do not trust could run as a local user."
	block := "add a file /etc/modprobe.d/disable-sctp.conf with the line \"install sctp /bin/false\""
	later := " Remove this once your distribution ships a kernel with the fix."
	switch {
	case s.builtin != "":
		return finding(RuleKernelSCTP, model.ConfigKernel, title, "medium", s.builtin, 0, "sctp built into kernel "+s.release,
			"SCTP is built into the running kernel ("+s.release+"), so it is always available and modprobe settings cannot turn it off. "+risk,
			"Boot a kernel that has SCTP as a module (most distribution kernels do) and "+block+"."+later), true
	case s.loaded != "":
		fix := "Stop what uses SCTP if you do not need it, run \"rmmod sctp\" (it works only when nothing uses it, otherwise reboot), and " +
			block + " so it is not loaded again."
		why := "The SCTP module is loaded in the running kernel (" + s.release + ")."
		if s.blocked != "" {
			why += " Loading is already blocked (" + s.blocked + "), but the module was loaded before that and stays until it is removed or the server restarts."
			fix = "Run \"rmmod sctp\" (it works only when nothing uses it), or restart the server; loading is already blocked."
		}
		return finding(RuleKernelSCTP, model.ConfigKernel, title, "medium", s.loaded, 0, "sctp loaded in kernel "+s.release,
			why+" "+risk, fix+later), true
	case s.module != "" && s.blocked == "":
		why := "The SCTP module is installed for the running kernel (" + s.release + ") and nothing stops it loading: the kernel loads it " +
			"by itself when any program opens an SCTP socket."
		if s.blacklist != "" {
			why += " \"blacklist sctp\" in " + s.blacklist + " does not stop that; only an install line does."
		}
		return finding(RuleKernelSCTP, model.ConfigKernel, title, "low", s.module, 0, "sctp loadable in kernel "+s.release,
			why+" "+risk, "Unless something here uses SCTP, "+block+"."+later), true
	}
	return model.ConfigFinding{}, false
}
