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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
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
	// SeenFor is how long a package seen running stays reachable, so
	// programs that run now and then are not called not running between
	// their runs; and how long the agent must have read every process,
	// without a gap, before it calls any package not running.
	SeenFor = 7 * 24 * time.Hour
	// MaxReadingGap: readings further apart than this (the agent reads
	// every 6 hours by default) break the run, since a program could have
	// run unseen in between.
	MaxReadingGap = 13 * time.Hour
	maxStateBytes = 4 << 20
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
		if kernelThread(dir) {
			// Kernel threads run no package's code. kthreadd, their parent,
			// is pid 2 only in the host's PID namespace.
			if pid == 2 && comm == "kthreadd" {
				s.hostNS = true
			}
			continue
		}
		exe, exeErr := os.Readlink(filepath.Join(dir, "exe"))
		if errors.Is(exeErr, fs.ErrNotExist) {
			continue // the process has exited
		}
		mapsOK := exeErr == nil && readMaps(filepath.Join(dir, "maps"), pid, comm, s, norm)
		if !mapsOK {
			// Refused, or any other error reading it: unread either way.
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

// pfKthread is PF_KTHREAD, the kernel's flag for its own threads.
const pfKthread = 0x00200000

// kernelThread: the process is one of the kernel's threads, by the flags in
// /proc/<pid>/stat, which everyone may read and no process can set. (Their
// exe link is no evidence: without CAP_SYS_PTRACE reading it is refused
// before the kernel finds there is no program.)
func kernelThread(dir string) bool {
	b, err := readSmall(filepath.Join(dir, "stat"), 1024)
	if err != nil {
		return false
	}
	// pid (comm) state ppid pgrp session tty_nr tpgid flags ...; comm may
	// hold spaces and parentheses, so fields start after the last ')'.
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return false
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 7 {
		return false
	}
	flags, err := strconv.ParseUint(f[6], 10, 64)
	return err == nil && flags&pfKthread != 0
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
	services []string // its systemd services ("nginx.service") and init scripts ("init.d/nginx")
	other    string   // why it cannot be called not running, if it cannot
	hit      *procRef // a running process uses one of its files
	hitPath  string
	hitExe   string // its file that is a running executable
}

// classify notes what path tells about its package; program says why a
// program can never be seen running itself ("" when it can). dpkg lists
// name directories too ("/usr/lib"); isDir keeps them from counting as
// the files a rule is about.
func (f *pkgFacts) classify(p string, program func(string) string, isDir func(string) bool) {
	if f.other != "" {
		return
	}
	base := filepath.Base(p)
	other := func(why string) {
		if !isDir(p) {
			f.other = why
		}
	}
	switch {
	case strings.HasPrefix(p, "/usr/bin/"), strings.HasPrefix(p, "/usr/sbin/"), strings.HasPrefix(p, "/usr/games/"),
		strings.HasPrefix(p, "/bin/"), strings.HasPrefix(p, "/sbin/"):
		// A running script's program is its interpreter: the script itself
		// is never seen running.
		if interpreted(base) {
			f.other = "it holds scripts"
			return
		}
		if why := program(p); why != "" {
			f.other = why
			return
		}
		f.programs = true
	case strings.HasPrefix(p, "/etc/cron"), strings.HasPrefix(p, "/etc/periodic/"),
		strings.HasSuffix(p, ".timer"), strings.HasSuffix(p, ".socket"), strings.HasSuffix(p, ".path"),
		strings.HasPrefix(p, "/usr/share/dbus-1/"), strings.HasPrefix(p, "/etc/xinetd.d/"),
		strings.Contains(p, "/hooks/"), strings.Contains(p, ".d/") && strings.HasPrefix(p, "/etc/network/"):
		other("it is started on a schedule or on demand")
	case strings.HasSuffix(p, ".service") && (path.Dir(p) == "/usr/lib/systemd/system" || path.Dir(p) == "/lib/systemd/system"):
		f.services = append(f.services, base)
	case strings.HasPrefix(p, "/usr/lib/systemd/user/"), strings.HasPrefix(p, "/lib/systemd/user/"):
		other("its user services start when someone logs in")
	case strings.HasPrefix(p, "/etc/init.d/") && path.Dir(p) == "/etc/init.d":
		f.services = append(f.services, "init.d/"+base)
	case strings.HasPrefix(p, "/usr/lib/systemd/"), strings.HasPrefix(p, "/lib/systemd/system/"),
		strings.HasPrefix(p, "/usr/lib/tmpfiles.d/"), strings.HasPrefix(p, "/usr/lib/sysusers.d/"):
		// Other service definitions and settings.
	case strings.HasPrefix(p, "/usr/lib"), strings.HasPrefix(p, "/lib"), strings.HasPrefix(p, "/usr/libexec/"),
		strings.HasPrefix(p, "/usr/local/"), strings.HasPrefix(p, "/opt/"):
		other("libraries and helpers can be loaded or started on demand")
	case interpreted(base):
		other("it holds scripts")
	}
}

// isDir: p is a directory on the host (a dpkg list's directory entry; a
// link to one, such as a merged /usr's /lib, counts).
func (c *Collector) isDir(p string) bool {
	fi, err := os.Stat(c.path(strings.TrimPrefix(p, "/")))
	return err == nil && fi.IsDir()
}

// unseenProgram says why the program at p (on the host) would not be seen
// as itself while it runs: a script ("#!") runs as its interpreter, and a
// link (busybox's /bin/sh) as the program it points to. "" when it would
// be; a program that is not there cannot be running.
func (c *Collector) unseenProgram(p string) string {
	full := c.path(strings.TrimPrefix(p, "/"))
	fi, err := os.Lstat(full)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ""
	case err != nil:
		return "its programs could not be read"
	case fi.Mode()&fs.ModeSymlink != 0:
		return "its programs are links to other programs"
	case !fi.Mode().IsRegular():
		return ""
	case fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid) != 0:
		// pkexec, sudo, mount: anyone can start them, and they are attacked
		// by being started, so not running now says nothing.
		return "its programs run with raised privileges (setuid or setgid) when anyone starts them"
	}
	caps := c.FileCaps
	if caps == nil {
		caps = fileCaps
	}
	if caps(full) {
		return "its programs get capabilities (setcap) when anyone starts them"
	}
	b, err := readSmall(full, 2)
	if err != nil {
		return "its programs could not be read"
	}
	if string(b) == "#!" {
		return "it holds scripts"
	}
	return ""
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

// procHistory is what the agent remembers between readings, in its state
// file: which packages it saw running and when, and since when every
// reading has been whole.
type procHistory struct {
	// Since is the first of an unbroken run of whole readings (each within
	// MaxReadingGap of the last); zero when the last reading was partial.
	Since time.Time `json:"since"`
	Last  time.Time `json:"last"`
	// Seen: package ("deb/nginx") -> when it was last seen running and the
	// evidence line then.
	Seen map[string]seenRec `json:"seen"`
}

type seenRec struct {
	At   time.Time `json:"at"`
	Line string    `json:"line"`
}

// loadHistory reads the state file once; a missing or damaged one starts
// afresh, which only delays any not running claim by SeenFor.
func (c *Collector) loadHistory() *procHistory {
	if c.hist != nil {
		return c.hist
	}
	h := &procHistory{}
	if c.StateFile != "" {
		if data, err := readSmall(c.StateFile, maxStateBytes); err == nil && json.Unmarshal(data, h) != nil {
			h = &procHistory{}
		}
	}
	if h.Seen == nil {
		h.Seen = map[string]seenRec{}
	}
	c.hist = h
	return h
}

// saveHistory writes the state file whole (a new file renamed over the
// old); false when it could not, so no claim rests on history that may be
// lost.
func (c *Collector) saveHistory() bool {
	if c.StateFile == "" {
		return false
	}
	data, err := json.Marshal(c.hist)
	if err != nil || len(data) > maxStateBytes {
		return false
	}
	tmp := c.StateFile + ".new"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return false
	}
	return os.Rename(tmp, c.StateFile) == nil
}

// serviceEnabled names the first of services that starts at boot or with
// another unit, or "" when none does. A systemd unit is enabled by a link
// in a .wants or .requires directory or under /etc/systemd/system (masked,
// a link to /dev/null, is not); one without an [Install] section is
// static, started by other units, so it counts as enabled. An init script
// is enabled by a runlevel link (OpenRC /etc/runlevels, SysV /etc/rc?.d).
func (c *Collector) serviceEnabled(services []string) string {
	exists := func(pattern string) bool {
		m, _ := filepath.Glob(c.path(pattern))
		return len(m) > 0
	}
	for _, svc := range services {
		if name, ok := strings.CutPrefix(svc, "init.d/"); ok {
			if exists("etc/runlevels/*/"+name) || exists("etc/rc[2345S].d/S*"+name) {
				return svc
			}
			continue
		}
		unit := svc
		if b, ok := strings.CutSuffix(svc, "@.service"); ok {
			unit = b + "@*.service" // a template: any enabled instance
		}
		if t, err := os.Readlink(c.path("etc/systemd/system/" + svc)); err == nil && t == "/dev/null" {
			continue // masked
		}
		for _, dir := range []string{"etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system", "run/systemd/system"} {
			if exists(dir+"/*.wants/"+unit) || exists(dir+"/*.requires/"+unit) {
				return svc
			}
		}
		if exists("etc/systemd/system/" + unit) {
			return svc // enabled under an alias, or overridden here
		}
		data, err := readSmall(c.path("usr/lib/systemd/system/"+svc), 64<<10)
		if err != nil {
			data, err = readSmall(c.path("lib/systemd/system/"+svc), 64<<10)
		}
		if err != nil || !installable.Match(data) {
			return svc // static, or unreadable
		}
	}
	return ""
}

var installable = regexp.MustCompile(`(?m)^\s*\[Install\]\s*$(?:\n[^\[]*)*?^\s*(?:WantedBy|RequiredBy|UpheldBy)\s*=\s*\S`)

// annotateProcesses sets reachability on the batch's OS packages from one
// snapshot of the running processes and the agent's history of earlier
// ones, and returns its coverage record.
//
// Not running is claimed only for a service package (a systemd service or
// init script) whose service is not enabled, whose programs all run as
// themselves without raised privileges, and none of whose programs was
// seen in SeenFor of unbroken whole readings, remembered in StateFile.
// Command-line tools are never called not running: they are started on
// demand, and some (pkexec) are attacked by being started.
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
		f.classify(p, c.unseenProgram, c.isDir)
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

	h := c.loadHistory()
	complete := access && snap.complete()
	switch {
	case !complete:
		h.Since, h.Last = time.Time{}, time.Time{}
	case h.Since.IsZero() || h.Last.IsZero() || now.Sub(h.Last) > MaxReadingGap || now.Before(h.Last):
		h.Since, h.Last = now, now
	default:
		h.Last = now
	}
	when := now.Format("2006-01-02 15:04 UTC")
	for k, f := range facts {
		if f.hit != nil {
			h.Seen[k] = seenRec{At: now, Line: hitLine(f.hit, f.hitPath)}
		}
	}
	for k, s := range h.Seen {
		if !s.At.After(now.Add(-SeenFor)) {
			delete(h.Seen, k)
		}
	}
	saved := c.saveHistory()
	settled := complete && saved && !h.Since.After(now.Add(-SeenFor))

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
		case h.Seen[key].At.After(now.Add(-SeenFor)):
			s := h.Seen[key]
			o.Reachability = &model.Reachability{Status: model.ReachReachable, Evidence: capLines([]string{
				s.Line, "Seen " + s.At.Format("2006-01-02 15:04 UTC") + "; not running at " + when + ".",
			})}
		case settled && f.programs && f.other == "" && len(f.services) > 0:
			if c.serviceEnabled(f.services) != "" {
				continue
			}
			o.Reachability = &model.Reachability{Status: model.ReachNotRunning, Evidence: capLines([]string{
				fmt.Sprintf("Its service (%s) is not enabled, and none of its programs was running in any of the agent's readings of the last 7 days (it has read every process, at most %d hours apart, since %s; %d processes at %s).",
					strings.Join(f.services, ", "), int(MaxReadingGap.Hours()), h.Since.Format("2006-01-02 15:04 UTC"), snap.read, when),
				"It may still run: it can be started by hand or by another program, and a program that runs only between the agent's readings is not seen.",
			})}
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
	case !saved:
		return model.CoverageItem{Scope: ProcessScope, Status: "checked",
			Reason: fmt.Sprintf("read %d processes; no state directory to remember readings in, so no package is called not running", snap.read)}, true
	case !settled:
		return model.CoverageItem{Scope: ProcessScope, Status: "checked",
			Reason: fmt.Sprintf("read %d processes; every process has been read since %s, and no package is called not running until that is 7 days", snap.read, h.Since.Format("2006-01-02 15:04 UTC"))}, true
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
