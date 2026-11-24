package confcheck

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/stackurity/stackurity/internal/model"
)

// Shirudo (https://docs.shirudo.dev, open source, November 2026) loads
// signed BPF micropatches, "upatches", into a running Linux kernel to block
// an exploit until the real patch is installed. A server that relies on one
// is exposed again when the upatch is not loaded: after a reboot where
// shirudo.service did not run, after a failed load, or when the LSM that
// enforces signed loading is not attached. The vulnerability findings still
// show, but a person who counted the upatch as the mitigation would not
// know it stopped working.
//
// Only files are read, as Shirudo itself documents them
// (docs.shirudo.dev/reference/files.html):
//
//   - /var/lib/shirudo/upatches/<name>.upatch: the archive of each upatch
//     the operator loaded, restored at every boot.
//   - /run/shirudo/bpffs/: Shirudo's private bpffs for this boot (mode
//     0700, so only root can list it). upatches/<pin>/ has one directory
//     per loaded upatch, <pin> being the name with every "." written as
//     "~d"; lsm_link is there while enforcement is attached.
//
// Nothing is reported when /var/lib/shirudo/upatches has no archives
// (Shirudo is not used here), when the running kernel's release cannot be
// read (a mounted root or an image: /run belongs to a boot), or when
// /run/shirudo/bpffs cannot be listed (the agent does not run as root),
// which is noted as not read rather than shown as fine.

// Shirudo rules.
const (
	// RuleShirudoNotLoaded: an archived upatch is not loaded in the running
	// kernel. One finding per upatch.
	RuleShirudoNotLoaded = "shirudo-upatch-not-loaded"
	// RuleShirudoLSMOff: upatches are archived but Shirudo's LSM link is
	// not attached, so signed loading is not enforced.
	RuleShirudoLSMOff = "shirudo-enforcement-off"
)

// ShirudoDoc is the how-to every Shirudo finding links to.
const ShirudoDoc = "https://stackurity.ai/docs/config-checks#shirudo-micropatches"

const (
	shirudoArchive = "/var/lib/shirudo/upatches"
	shirudoBPFFS   = "/run/shirudo/bpffs"
	// maxShirudoUpatches bounds the findings from one host.
	maxShirudoUpatches = 50
)

// shirudo reports archived upatches that are not loaded, and enforcement
// that is not attached.
func (h *hostFS) shirudo() []model.ConfigFinding {
	archived := h.shirudoArchived()
	if len(archived) == 0 {
		return nil
	}
	rel, _ := h.read("/proc/sys/kernel/osrelease", 4096)
	release := strings.TrimSpace(string(rel))
	if release == "" {
		return nil
	}
	pins, lsm, ok := h.shirudoLoaded()
	if !ok {
		return nil
	}
	var out []model.ConfigFinding
	if !lsm {
		out = append(out, finding(RuleShirudoLSMOff, model.ConfigKernel, "Shirudo micropatch enforcement is not attached", "high",
			shirudoBPFFS+"/lsm_link", 0, "shirudo lsm_link missing in kernel "+release,
			"This server has "+shirudoPlural(len(archived), "Shirudo micropatch", "Shirudo micropatches")+" in "+shirudoArchive+
				", but Shirudo's LSM link ("+shirudoBPFFS+"/lsm_link) is not attached in the running kernel ("+release+
				"). Without it Shirudo does not restrict BPF loading to signed loaders, so the micropatches it loads cannot be relied on.",
			"Run \"shirudo status\" as root to see why (status lsm-off: the bpf LSM is not in the kernel's lsm= list), "+
				"then \"systemctl restart shirudo.service\" or restart the server. Installing the vendor's fixed packages removes the need for the micropatches."))
	}
	for _, name := range archived {
		if pins[shirudoPinName(name)] {
			continue
		}
		p := shirudoArchive + "/" + name + ".upatch"
		out = append(out, finding(RuleShirudoNotLoaded, model.ConfigKernel, "Shirudo micropatch is not loaded", "high",
			p, 0, "upatch "+name+" not loaded in kernel "+release,
			"The Shirudo micropatch \""+name+"\" is archived on this server ("+p+") but is not loaded in the running kernel ("+
				release+"), so the exploit it was put there to block is not blocked. This happens after a restart where "+
				"shirudo.service did not run, or when loading failed.",
			"Run \"shirudo upatch list\" and \"shirudo status\" as root to see why, then \"systemctl restart shirudo.service\" or "+
				"\"shirudo upatch load\" it again. If the vulnerable package has been upgraded since, unload and remove the micropatch instead."))
	}
	return out
}

// shirudoArchived lists the names of the archived upatches, sorted and
// bounded. Unload directives (<name>.unload.upatch) are not upatches.
func (h *hostFS) shirudoArchived() []string {
	var names []string
	for _, e := range h.readDir(shirudoArchive) {
		n := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(n, ".upatch") || strings.HasSuffix(n, ".unload.upatch") {
			continue
		}
		if name := strings.TrimSuffix(n, ".upatch"); name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) > maxShirudoUpatches {
		names = names[:maxShirudoUpatches]
	}
	return names
}

// shirudoLoaded reads this boot's bpffs: the pin directories of the loaded
// upatches and whether the LSM link is pinned. ok is false when it cannot
// be said: the directory exists but cannot be listed (noted as a problem).
// A bpffs that does not exist means Shirudo did not run this boot: nothing
// is loaded and enforcement is off.
func (h *hostFS) shirudoLoaded() (pins map[string]bool, lsm bool, ok bool) {
	pins = map[string]bool{}
	real, err := h.resolve(shirudoBPFFS)
	if errors.Is(err, fs.ErrNotExist) {
		return pins, false, true
	}
	if err != nil {
		h.problem(shirudoBPFFS, "cannot be read")
		return nil, false, false
	}
	entries, err := os.ReadDir(real)
	if err != nil {
		h.problem(shirudoBPFFS, "cannot be listed (Shirudo checks need the agent to run as root)")
		return nil, false, false
	}
	for _, e := range entries {
		if e.Name() == "lsm_link" {
			lsm = true
		}
	}
	ups, err := os.ReadDir(path.Join(real, "upatches"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		h.problem(shirudoBPFFS+"/upatches", "cannot be listed")
		return nil, false, false
	}
	for _, e := range ups {
		if e.IsDir() {
			pins[e.Name()] = true
		}
	}
	return pins, lsm, true
}

// shirudoPinName is the bpffs directory name of an upatch: every "." is
// written as "~d".
func shirudoPinName(name string) string { return strings.ReplaceAll(name, ".", "~d") }

func shirudoPlural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
