package linux

// Process reachability: which installed OS packages the host's running
// processes have loaded. It only reads /proc (each process's exe link,
// memory map file names, file-descriptor links and the kernel's socket
// tables) and the package databases' file lists; it never attaches to a
// process or reads its memory.
//
// Reading other users' processes needs CAP_SYS_PTRACE, which the agent's
// service gets only when it was installed with STACKURITY_PROCESSES=1.
// Without it the agent still sees programs started by their full path
// (/proc/<pid>/cmdline is readable by everyone), so it can say a package
// is running but never that one is not.

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/model"
)

// ProcessScope is the coverage scope of the process reading. Its status is
// always "checked", with any limit in the reason: what the agent could see
// of running processes is not an inventory gap (asset health, gap alerts,
// the trust badge), and a limit shows as packages left unknown.
const ProcessScope = "reachability/processes"

// ProcessAccessAttribute is the host attribute that says whether the agent
// may read every process ("on") or not ("off"); the dashboard offers the
// command that turns it on.
const ProcessAccessAttribute = "process_access"

// Limits keep one reading small on a host with little memory: the
// distinct file names kept, not the processes, decide its size.
const (
	MaxProcs       = 4096
	MaxMapLines    = 1 << 16 // per process
	MaxMappedFiles = 50000
	MaxFDs         = 4096 // per process
	// SeenFor is how long a package seen running stays reachable in a
	// long-running agent, so programs that run now and then are not
	// called not running between their runs.
	SeenFor = 7 * 24 * time.Hour
)

// capSysPtrace is CAP_SYS_PTRACE's bit in /proc/self/status CapEff.
const capSysPtrace = 19

type procRef struct {
	pid  int
	comm string
	how  string // "loaded" (mapped), "runs" (its executable) or "started as" (cmdline only)
}

type procSnapshot struct {
	files  map[string]procRef  // normalised path -> first process seen with it
	listen map[string][]string // normalised executable -> "0.0.0.0:443"
	exes   map[string]string   // normalised executable -> comm, for listen evidence
	hostNS bool                // kernel threads are visible: this is the host's PID namespace
	read   int                 // processes whose maps were read
	denied int                 // processes the agent may not read
	capped bool                // a limit was reached
}

// complete: every process of the host was read. Kernel threads (kthreadd
// is pid 2) are visible only in the host's PID namespace, so an agent in a
// container, which sees only the container's processes, is never complete;
// nor is one under hidepid, which hides them.
func (s *procSnapshot) complete() bool { return s.hostNS && s.denied == 0 && !s.capped && s.read > 0 }

func (s *procSnapshot) add(path string, r procRef) {
	if old, ok := s.files[path]; ok {
		// A process's own executable says more than its map listing it.
		if r.how == "runs" && old.how != "runs" {
			s.files[path] = r
		}
		return
	}
	if len(s.files) >= MaxMappedFiles {
		s.capped = true
		return
	}
	s.files[path] = r
}

// usrMerged reports whether /lib is a link to usr/lib, so the package
// lists' /lib paths and the maps' /usr/lib paths are the same files.
func (c *Collector) usrMerged() bool {
	t, err := os.Readlink(c.path("lib"))
	return err == nil && strings.TrimPrefix(strings.TrimSuffix(t, "/"), "/") == "usr/lib"
}

func normaliser(merged bool) func(string) string {
	return func(p string) string {
		p = strings.TrimSuffix(p, " (deleted)")
		p = filepath.Clean(p)
		if merged {
			for _, d := range []string{"/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/"} {
				if strings.HasPrefix(p, d) {
					return "/usr" + p
				}
			}
		}
		return p
	}
}

// readProcesses takes one snapshot of the processes under procDir.
func readProcesses(procDir string, norm func(string) string) *procSnapshot {
	s := &procSnapshot{files: map[string]procRef{}, listen: map[string][]string{}, exes: map[string]string{}}
	entries, err := os.ReadDir(procDir)
	if err != nil {
		s.capped = true
		return s
	}
	sockets := map[string]string{} // socket inode -> normalised executable
	n := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if n++; n > MaxProcs {
			s.capped = true
			break
		}
		dir := filepath.Join(procDir, e.Name())
		commB, _ := readSmall(filepath.Join(dir, "comm"), 64)
		comm := strings.TrimSpace(string(commB))
		exe, exeErr := os.Readlink(filepath.Join(dir, "exe"))
		if errors.Is(exeErr, fs.ErrNotExist) {
			// A kernel thread (it has a name but no program), or the
			// process has exited.
			if pid == 2 && comm == "kthreadd" {
				s.hostNS = true
			}
			continue
		}
		mapsOK := exeErr == nil && readMaps(filepath.Join(dir, "maps"), pid, comm, s, norm)
		if !mapsOK {
			if exeErr != nil && !errors.Is(exeErr, fs.ErrPermission) {
				continue
			}
			s.denied++
			// cmdline is readable by everyone: a program started by its
			// full path is running, whatever else cannot be read.
			if cl, err := readSmall(filepath.Join(dir, "cmdline"), 4096); err == nil {
				arg0, _, _ := strings.Cut(string(cl), "\x00")
				if strings.HasPrefix(arg0, "/") && !strings.ContainsAny(arg0, " \t") {
					s.add(norm(arg0), procRef{pid: pid, comm: comm, how: "started as"})
				}
			}
			continue
		}
		s.read++
		x := norm(exe)
		s.add(x, procRef{pid: pid, comm: comm, how: "runs"})
		s.exes[x] = comm
		readSockets(filepath.Join(dir, "fd"), x, sockets)
	}
	if len(sockets) > 0 {
		for inode, addr := range listeningSockets(procDir) {
			if x, ok := sockets[inode]; ok && len(s.listen[x]) < 4 {
				s.listen[x] = append(s.listen[x], addr)
			}
		}
	}
	return s
}

// readMaps adds the files a process has mapped; false when it may not be
// read.
func readMaps(path string, pid int, comm string, s *procSnapshot, norm func(string) string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	lines := 0
	for sc.Scan() {
		if lines++; lines > MaxMapLines {
			s.capped = true
			break
		}
		// address perms offset dev inode path
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 || !strings.HasPrefix(fields[5], "/") {
			continue
		}
		s.add(norm(strings.Join(fields[5:], " ")), procRef{pid: pid, comm: comm, how: "loaded"})
	}
	return sc.Err() == nil
}

// readSockets records the process's socket inodes. Its fd links can be
// read only with the same access as its maps.
func readSockets(fdDir, exe string, sockets map[string]string) {
	d, err := os.Open(fdDir)
	if err != nil {
		return
	}
	defer d.Close()
	names, _ := d.Readdirnames(MaxFDs)
	for _, n := range names {
		t, err := os.Readlink(filepath.Join(fdDir, n))
		if err != nil || !strings.HasPrefix(t, "socket:[") {
			continue
		}
		sockets[strings.TrimSuffix(strings.TrimPrefix(t, "socket:["), "]")] = exe
	}
}

// listeningSockets reads the kernel's TCP tables: socket inode -> the
// address it listens on.
func listeningSockets(procDir string) map[string]string {
	out := map[string]string{}
	for _, name := range []string{"tcp", "tcp6"} {
		f, err := os.Open(filepath.Join(procDir, "net", name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			if first {
				first = false
				continue
			}
			// sl local rem st tx:rx tr:tm retrnsmt uid timeout inode
			f := strings.Fields(sc.Text())
			if len(f) < 10 || f[3] != "0A" { // 0A: LISTEN
				continue
			}
			if a, ok := decodeProcAddr(f[1]); ok {
				out[f[9]] = a
			}
		}
		f.Close()
	}
	return out
}

// decodeProcAddr turns /proc/net/tcp's "0100007F:0050" into 127.0.0.1:80.
// Each 32-bit word of the address is in the host's (little-endian) order.
func decodeProcAddr(s string) (string, bool) {
	h, p, ok := strings.Cut(s, ":")
	port, err := strconv.ParseUint(p, 16, 16)
	if !ok || err != nil || (len(h) != 8 && len(h) != 32) {
		return "", false
	}
	b := make([]byte, len(h)/2)
	for i := 0; i < len(h); i += 8 {
		w, err := strconv.ParseUint(h[i:i+8], 16, 32)
		if err != nil {
			return "", false
		}
		j := i / 2
		b[j], b[j+1], b[j+2], b[j+3] = byte(w), byte(w>>8), byte(w>>16), byte(w>>24)
	}
	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return "", false
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)).String(), true
}

// hasProcessAccess reports whether the agent may read every process: root,
// or CAP_SYS_PTRACE in its effective set.
func hasProcessAccess(procDir string, uid uint32) bool {
	if uid == 0 {
		return true
	}
	data, err := readSmall(filepath.Join(procDir, "self", "status"), 8192)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			caps, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return err == nil && caps&(1<<capSysPtrace) != 0
		}
	}
	return false
}

// pkgFacts is what one package's file list says about it.
type pkgFacts struct {
	programs bool     // ships a program under a bin directory
	other    string   // why it cannot be called not running, if it cannot
	hit      *procRef // a running process uses one of its files
	hitPath  string
	hitExe   string // its file that is a running executable
}

// classify notes what path tells about its package.
func (f *pkgFacts) classify(p string) {
	if f.other != "" {
		return
	}
	base := filepath.Base(p)
	switch {
	case strings.HasPrefix(p, "/usr/bin/"), strings.HasPrefix(p, "/usr/sbin/"), strings.HasPrefix(p, "/usr/games/"),
		strings.HasPrefix(p, "/bin/"), strings.HasPrefix(p, "/sbin/"):
		if interpreted(base) {
			f.other = "it holds scripts"
			return
		}
		f.programs = true
	case strings.HasPrefix(p, "/etc/cron"), strings.HasPrefix(p, "/etc/periodic/"),
		strings.HasSuffix(p, ".timer"), strings.HasSuffix(p, ".socket"), strings.HasSuffix(p, ".path"),
		strings.HasPrefix(p, "/usr/share/dbus-1/"), strings.HasPrefix(p, "/etc/xinetd.d/"),
		strings.Contains(p, "/hooks/"), strings.Contains(p, ".d/") && strings.HasPrefix(p, "/etc/network/"):
		f.other = "it is started on a schedule or on demand"
	case strings.HasPrefix(p, "/usr/lib/systemd/"), strings.HasPrefix(p, "/lib/systemd/system/"),
		strings.HasPrefix(p, "/usr/lib/tmpfiles.d/"), strings.HasPrefix(p, "/usr/lib/sysusers.d/"):
		// Service definitions: a service that is not running is stopped.
	case strings.HasPrefix(p, "/usr/lib"), strings.HasPrefix(p, "/lib"), strings.HasPrefix(p, "/usr/libexec/"),
		strings.HasPrefix(p, "/usr/local/"), strings.HasPrefix(p, "/opt/"):
		f.other = "libraries and helpers can be loaded or started on demand"
	case interpreted(base):
		f.other = "it holds scripts"
	}
}

func interpreted(base string) bool {
	switch filepath.Ext(base) {
	case ".py", ".pyc", ".pl", ".pm", ".rb", ".php", ".js", ".mjs", ".cjs", ".jar", ".class", ".sh", ".lua", ".tcl":
		return true
	}
	return false
}

// pkgFiles streams (package, file) pairs from the host's package
// databases; false when there are none it can read.
func (c *Collector) pkgFiles(each func(typ, pkg, path string)) bool {
	ok := false
	if lists, _ := filepath.Glob(c.path("var/lib/dpkg/info/*.list")); len(lists) > 0 {
		ok = true
		for _, l := range lists {
			pkg, _, _ := strings.Cut(strings.TrimSuffix(filepath.Base(l), ".list"), ":")
			f, err := os.Open(l)
			if err != nil {
				continue
			}
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				if p := sc.Text(); strings.HasPrefix(p, "/") {
					each("deb", pkg, p)
				}
			}
			f.Close()
		}
	}
	if f, err := os.Open(c.path("lib/apk/db/installed")); err == nil {
		ok = true
		sc := bufio.NewScanner(f)
		var pkg, dir string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "P:"):
				pkg, dir = line[2:], ""
			case strings.HasPrefix(line, "F:"):
				dir = line[2:]
			case strings.HasPrefix(line, "R:") && pkg != "":
				each("apk", pkg, "/"+filepath.Join(dir, line[2:]))
			}
		}
		f.Close()
	}
	return ok
}

type seenRec struct {
	at   time.Time
	line string
}

// annotateProcesses sets reachability on the batch's OS packages from one
// snapshot of the running processes and returns its coverage record.
func (c *Collector) annotateProcesses(b *model.ObservationBatch) (model.CoverageItem, bool) {
	if c.ProcDir == "" {
		return model.CoverageItem{}, false
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	access := hasProcessAccess(c.ProcDir, c.UID)
	if c.ProcessAccess != nil {
		access = c.ProcessAccess()
	}
	if b.Asset.Attributes == nil {
		b.Asset.Attributes = map[string]string{}
	}
	b.Asset.Attributes[ProcessAccessAttribute] = map[bool]string{true: "on", false: "off"}[access]
	norm := normaliser(c.usrMerged())
	snap := readProcesses(c.ProcDir, norm)

	facts := map[string]*pkgFacts{}
	have := c.pkgFiles(func(typ, pkg, p string) {
		key := typ + "/" + pkg
		f := facts[key]
		if f == nil {
			f = &pkgFacts{}
			facts[key] = f
		}
		p = norm(p)
		f.classify(p)
		if r, ok := snap.files[p]; ok {
			if f.hit == nil || (r.how == "runs" && f.hitExe == "") {
				r := r
				f.hit, f.hitPath = &r, p
			}
			if r.how == "runs" {
				f.hitExe = p
			}
		}
	})
	if !have {
		return model.CoverageItem{Scope: ProcessScope, Status: "checked", Reason: "unsupported: no dpkg or apk file lists to match processes against"}, true
	}
	if c.seen == nil {
		c.seen = map[string]seenRec{}
	}
	when := now.Format("2006-01-02 15:04 UTC")
	complete := access && snap.complete()
	for i := range b.Observations {
		o := &b.Observations[i]
		pu, err := packageurl.FromString(o.Purl)
		if err != nil || (pu.Type != "deb" && pu.Type != "apk") || kernelPackage(pu.Name) {
			continue
		}
		key := pu.Type + "/" + pu.Name
		f := facts[key]
		if f == nil {
			continue
		}
		switch {
		case f.hit != nil:
			ev := []string{hitLine(f.hit, f.hitPath)}
			if f.hitExe != "" {
				for _, a := range snap.listen[f.hitExe] {
					ev = append(ev, fmt.Sprintf("%s (%s) listens on %s.", snap.exes[f.hitExe], f.hitExe, a))
				}
			}
			ev = append(ev, "Seen "+when+".")
			o.Reachability = &model.Reachability{Status: model.ReachReachable, Evidence: capLines(ev)}
			c.seen[key] = seenRec{at: now, line: ev[0]}
		case c.seen[key].at.After(now.Add(-SeenFor)):
			s := c.seen[key]
			o.Reachability = &model.Reachability{Status: model.ReachReachable, Evidence: capLines([]string{
				s.line, "Seen " + s.at.Format("2006-01-02 15:04 UTC") + "; not running at " + when + ".",
			})}
		case complete && f.programs && f.other == "":
			o.Reachability = &model.Reachability{Status: model.ReachNotRunning, Evidence: []string{
				fmt.Sprintf("None of its programs was running at %s (%d processes read).", when, snap.read),
				"Programs started only now and then, by scripts or by hand, are not seen between the agent's readings.",
			}}
		}
	}
	for k, s := range c.seen {
		if !s.at.After(now.Add(-SeenFor)) {
			delete(c.seen, k)
		}
	}
	switch {
	case !access:
		return model.CoverageItem{Scope: ProcessScope, Status: "checked",
			Reason: "process access is off: only programs started by their full path are seen, so no package is called not running (install with STACKURITY_PROCESSES=1 to turn it on)"}, true
	case snap.read > 0 && !snap.hostNS:
		return model.CoverageItem{Scope: ProcessScope, Status: "checked",
			Reason: "partial: the host's kernel threads are not visible (the agent runs in a container's PID namespace, or /proc hides other processes), so only some processes were read; no package is called not running"}, true
	case !complete:
		return model.CoverageItem{Scope: ProcessScope, Status: "checked",
			Reason: fmt.Sprintf("partial: read %d processes, %d could not be read or a limit was reached; no package is called not running", snap.read, snap.denied)}, true
	}
	return model.CoverageItem{Scope: ProcessScope, Status: "checked", Reason: fmt.Sprintf("read %d processes", snap.read)}, true
}

func hitLine(r *procRef, path string) string {
	switch r.how {
	case "runs":
		return fmt.Sprintf("Running: %s (pid %d) is %s.", r.comm, r.pid, path)
	case "started as":
		return fmt.Sprintf("Running: %s (pid %d) was started as %s.", r.comm, r.pid, path)
	}
	return fmt.Sprintf("Loaded by %s (pid %d): %s.", r.comm, r.pid, path)
}

func capLines(ev []string) []string {
	if len(ev) > model.MaxReachEvidence {
		ev = ev[:model.MaxReachEvidence]
	}
	for i, e := range ev {
		// Process names and file names may hold anything.
		e = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f || r == 0xfffd {
				return '?'
			}
			return r
		}, strings.ToValidUTF8(e, "?"))
		ev[i] = e
		if len(e) > model.MaxReachEvidenceLen {
			ev[i] = e[:model.MaxReachEvidenceLen-3] + "..."
		}
	}
	return ev
}

// kernelPackage: the running kernel has its own check (not_running_kernel).
func kernelPackage(name string) bool {
	for _, p := range []string{"linux-image", "linux-modules", "linux-headers", "linux-lts", "linux-virt", "linux-firmware"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return name == "linux"
}
