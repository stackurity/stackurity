package linux

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/model"
)

// procHost builds a Debian host with merged /usr and a /proc of three
// processes: nginx (listening on 443, with libssl mapped), a shell started
// by path and a kernel thread.
func procHost(t *testing.T) (root string, c *Collector) {
	t.Helper()
	root = t.TempDir()
	write := func(p, data string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(p, target string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n")
	for _, d := range []string{"etc/cron.d", "usr/lib/systemd/system"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	link("lib", "usr/lib")
	var status strings.Builder
	fixturePackages = nil
	pkg := func(name string, files ...string) {
		fixturePackages = append(fixturePackages, name)
		status.WriteString("Package: " + name + "\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\n\n")
		// Like dpkg's, the list names directories too.
		write("var/lib/dpkg/info/"+name+":amd64.list", "/.\n/usr\n/usr/lib\n/lib\n/lib/systemd\n/lib/systemd/system\n/etc\n/etc/cron.d\n"+strings.Join(files, "\n")+"\n")
	}
	pkg("nginx", "/usr/sbin/nginx", "/usr/share/doc/nginx/copyright", "/lib/systemd/system/nginx.service")
	pkg("libssl3", "/lib/x86_64-linux-gnu/libssl.so.3")
	pkg("htop", "/usr/bin/htop", "/usr/share/man/man1/htop.1.gz")
	pkg("dash", "/bin/dash")
	pkg("libunused1", "/usr/lib/x86_64-linux-gnu/libunused.so.1")
	pkg("logrotate", "/usr/sbin/logrotate", "/etc/cron.daily/logrotate")
	pkg("python3-yaml", "/usr/bin/yamlcheck.py", "/usr/lib/python3/dist-packages/yaml/__init__.py")
	pkg("linux-image-6.1.0-13-amd64", "/boot/vmlinuz-6.1.0-13-amd64")
	// Scripts without an extension: a running one shows only its
	// interpreter (/bin/sh, perl) as its program.
	pkg("init-system-helpers", "/usr/sbin/service", "/usr/bin/deb-systemd-helper")
	write("usr/sbin/service", "#!/bin/sh\nexec systemctl \"$@\"\n")
	write("usr/bin/deb-systemd-helper", "#!/usr/bin/perl\n")
	write("usr/bin/htop", "\x7fELF")
	// Services. memcached: a service, not enabled, not running.
	unit := "[Unit]\nDescription=x\n\n[Service]\nExecStart=/usr/bin/x\n\n[Install]\nWantedBy=multi-user.target\n"
	pkg("memcached", "/usr/bin/memcached", "/lib/systemd/system/memcached.service")
	write("usr/bin/memcached", "\x7fELF")
	write("usr/lib/systemd/system/memcached.service", unit)
	// redis-server: the same, but enabled.
	pkg("redis-server", "/usr/bin/redis-server", "/lib/systemd/system/redis-server.service")
	write("usr/bin/redis-server", "\x7fELF")
	write("usr/lib/systemd/system/redis-server.service", unit)
	link("etc/systemd/system/multi-user.target.wants/redis-server.service", "/usr/lib/systemd/system/redis-server.service")
	// staticd: no [Install], so other units start it.
	pkg("staticd", "/usr/sbin/staticd", "/lib/systemd/system/staticd.service")
	write("usr/sbin/staticd", "\x7fELF")
	write("usr/lib/systemd/system/staticd.service", "[Service]\nExecStart=/usr/sbin/staticd\n")
	// polkitd: a service whose package also has a setuid program (pkexec).
	pkg("polkitd", "/usr/bin/pkexec", "/lib/systemd/system/polkit.service")
	write("usr/bin/pkexec", "\x7fELF")
	write("usr/lib/systemd/system/polkit.service", unit)
	if err := os.Chmod(filepath.Join(root, "usr/bin/pkexec"), 0o755|fs.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	// capd: a service whose program has file capabilities.
	pkg("capd", "/usr/sbin/capd", "/lib/systemd/system/capd.service")
	write("usr/sbin/capd", "\x7fELF")
	write("usr/lib/systemd/system/capd.service", unit)
	// sysvd: an init script started in runlevel 2.
	pkg("sysvd", "/usr/sbin/sysvd", "/etc/init.d/sysvd")
	write("usr/sbin/sysvd", "\x7fELF")
	write("etc/init.d/sysvd", "#!/bin/sh\n")
	link("etc/rc2.d/S01sysvd", "../init.d/sysvd")
	// A program that is a link: running, it shows as the program it
	// points to (busybox for Alpine's /bin/sh).
	pkg("busybox-binsh", "/usr/bin/ash")
	link("usr/bin/ash", "dash")
	write("var/lib/dpkg/status", status.String())

	// pid 100: nginx, readable.
	link("proc/100/exe", "/usr/sbin/nginx")
	write("proc/100/comm", "nginx\n")
	write("proc/100/maps", "55d0-55e0 r-xp 00000000 08:01 11 /usr/sbin/nginx\n"+
		"7f00-7f10 r-xp 00000000 08:01 12 /usr/lib/x86_64-linux-gnu/libssl.so.3\n"+
		"7f20-7f30 rw-p 00000000 00:00 0 [heap]\n"+
		"7f40-7f50 r--p 00000000 00:00 0 \n")
	write("proc/100/cmdline", "nginx: master process /usr/sbin/nginx\x00")
	write("proc/100/stat", "100 (nginx) S 1 100 100 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 50 0 0\n")
	link("proc/100/fd/6", "socket:[999]")
	link("proc/100/fd/1", "/dev/null")
	// pid 200: a shell started by path, readable.
	link("proc/200/exe", "/usr/bin/dash")
	write("proc/200/comm", "sh\n")
	write("proc/200/maps", "55d0-55e0 r-xp 00000000 08:01 13 /usr/bin/dash\n")
	write("proc/200/cmdline", "/bin/sh\x00-c\x00true\x00")
	// pid 2: kthreadd, a kernel thread (PF_KTHREAD in its flags, no exe).
	write("proc/2/comm", "kthreadd\n")
	write("proc/2/stat", "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0\n")
	// pid 3: another kernel thread whose exe the agent may not read; it is
	// skipped, not counted as unreadable.
	write("proc/3/comm", "pool_workqueue_release\n")
	write("proc/3/stat", "3 (pool_workqueue_release) S 2 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0\n")
	link("proc/3/exe", "/nonexistent-denied")
	write("proc/net/tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999 1 0 100 0 0 10 0\n"+
		"   1: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 998 1 0 100 0 0 10 0\n")

	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	c = &Collector{Root: root, Version: "test", LookPath: func(string) (string, error) { return "", errors.New("none") },
		ProcDir: filepath.Join(root, "proc"), Now: func() time.Time { return now }, ProcessAccess: func() bool { return true },
		StateFile: filepath.Join(t.TempDir(), "processes.json"),
		FileCaps:  func(p string) bool { return strings.HasSuffix(p, "/usr/sbin/capd") }}
	// Eight days of whole readings, the last six hours ago.
	writeHistory(t, c.StateFile, now.Add(-8*24*time.Hour), now.Add(-6*time.Hour))
	return root, c
}

// writeHistory writes the agent's state: whole readings since since, the
// last at last, and every fixture package installed since since.
func writeHistory(t *testing.T, file string, since, last time.Time) {
	t.Helper()
	h := procHistory{Since: since, Last: last, Installed: map[string]time.Time{}}
	if !since.IsZero() {
		for _, n := range fixturePackages {
			h.Installed["deb/"+n+"@1.0-1"] = since
		}
	}
	data, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

var fixturePackages []string

func reachOf(t *testing.T, b *model.ObservationBatch) map[string]*model.Reachability {
	t.Helper()
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	out := map[string]*model.Reachability{}
	for _, o := range b.Observations {
		pu, err := packageurl.FromString(o.Purl)
		if err != nil {
			t.Fatal(err)
		}
		out[pu.Name] = o.Reachability
	}
	return out
}

func status(r *model.Reachability) string {
	if r == nil {
		return model.ReachUnknown
	}
	return r.Status
}

func coverage(b *model.ObservationBatch) model.CoverageItem {
	for _, c := range b.Coverage {
		if c.Scope == ProcessScope {
			return c
		}
	}
	return model.CoverageItem{}
}

func TestProcessReachability(t *testing.T) {
	_, c := procHost(t)
	b, err := c.Collect(context.Background(), "web1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !b.Complete {
		t.Errorf("the package list is whole; the process reading must not change that: %+v", b.Coverage)
	}
	if cov := coverage(b); cov.Status != "checked" || cov.Reason != "read 2 processes" {
		t.Errorf("coverage %+v", cov)
	}
	if a := b.Asset.Attributes[ProcessAccessAttribute]; a != "on" {
		t.Errorf("process_access = %q", a)
	}
	got := reachOf(t, b)
	want := map[string]string{
		"nginx":                      model.ReachReachable,
		"libssl3":                    model.ReachReachable, // /lib/... in the list, /usr/lib/... in maps
		"dash":                       model.ReachReachable,
		"htop":                       model.ReachUnknown, // a command-line tool, started on demand
		"libunused1":                 model.ReachUnknown, // libraries load on demand
		"logrotate":                  model.ReachUnknown, // runs from cron
		"python3-yaml":               model.ReachUnknown, // scripts
		"init-system-helpers":        model.ReachUnknown, // scripts, found by their "#!"
		"busybox-binsh":              model.ReachUnknown, // a link to another program
		"memcached":                  model.ReachNotRunning,
		"redis-server":               model.ReachUnknown, // its service is enabled
		"staticd":                    model.ReachUnknown, // started by other units
		"polkitd":                    model.ReachUnknown, // setuid pkexec
		"capd":                       model.ReachUnknown, // file capabilities
		"sysvd":                      model.ReachUnknown, // its init script is enabled
		"linux-image-6.1.0-13-amd64": model.ReachUnknown, // the kernel has its own check
	}
	for name, st := range want {
		if s := status(got[name]); s != st {
			t.Errorf("%s: %s, want %s (%+v)", name, s, st, got[name])
		}
	}
	ev := strings.Join(got["nginx"].Evidence, " | ")
	if !strings.Contains(ev, "nginx (pid 100) is /usr/sbin/nginx") || !strings.Contains(ev, "listens on 0.0.0.0:443") {
		t.Errorf("nginx evidence: %s", ev)
	}
	if ev := strings.Join(got["libssl3"].Evidence, " | "); !strings.Contains(ev, "Loaded by nginx (pid 100): /usr/lib/x86_64-linux-gnu/libssl.so.3") {
		t.Errorf("libssl3 evidence: %s", ev)
	}
	if ev := strings.Join(got["memcached"].Evidence, " | "); !strings.Contains(ev, "Its service (memcached.service) is not enabled") ||
		!strings.Contains(ev, "since 2026-11-09 12:00 UTC; 2 processes at 2026-11-17 12:00 UTC") || !strings.Contains(ev, "It may still run") {
		t.Errorf("memcached evidence: %s", ev)
	}
}

// Without process access nothing is called not running, and the coverage
// says how to turn it on; programs started by path are still seen.
func TestProcessReachabilityWithoutAccess(t *testing.T) {
	root, c := procHost(t)
	c.ProcessAccess = func() bool { return false }
	if os.Geteuid() != 0 {
		// As the agent's user sees them: other users' maps refuse to open.
		for _, pid := range []string{"100", "200"} {
			if err := os.Chmod(filepath.Join(root, "proc", pid, "maps"), 0); err != nil {
				t.Fatal(err)
			}
		}
	}
	b, err := c.Collect(context.Background(), "web1", "")
	if err != nil {
		t.Fatal(err)
	}
	if cov := coverage(b); cov.Status != "checked" || !strings.Contains(cov.Reason, "STACKURITY_PROCESSES=1") {
		t.Errorf("coverage %+v", cov)
	}
	if a := b.Asset.Attributes[ProcessAccessAttribute]; a != "off" {
		t.Errorf("process_access = %q", a)
	}
	if !b.Complete {
		t.Error("no process access made the package list incomplete")
	}
	got := reachOf(t, b)
	for name, st := range map[string]string{"htop": model.ReachUnknown, "libunused1": model.ReachUnknown} {
		if s := status(got[name]); s != st {
			t.Errorf("%s: %s, want %s", name, s, st)
		}
	}
	if os.Geteuid() != 0 {
		// /bin/sh -> /usr/bin/sh is not dash's file; /usr/sbin/nginx is not
		// argv[0] ("nginx: master process ..."), so neither is seen.
		if s := status(got["nginx"]); s != model.ReachUnknown {
			t.Errorf("nginx: %s", s)
		}
	}
}

// A process the agent may not read makes the reading partial: nothing is
// called not running, but a program started by its full path still counts.
func TestProcessReachabilityPartial(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	root, c := procHost(t)
	dir := filepath.Join(root, "proc", "300")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/htop", filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte("/usr/bin/htop\x00-d\x0010\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "maps"), nil, 0); err != nil {
		t.Fatal(err)
	}
	b, err := c.Collect(context.Background(), "web1", "")
	if err != nil {
		t.Fatal(err)
	}
	if cov := coverage(b); cov.Status != "checked" || !strings.HasPrefix(cov.Reason, "partial: read 2 processes, 1 could not") {
		t.Errorf("coverage %+v", cov)
	}
	if !b.Complete {
		t.Error("a partial process reading made the package list incomplete")
	}
	got := reachOf(t, b)
	if r := got["htop"]; status(r) != model.ReachReachable || !strings.Contains(r.Evidence[0], "started as /usr/bin/htop") {
		t.Errorf("htop: %+v", r)
	}
}

// The agent remembers across restarts, in its state file, what it saw
// running for SeenFor; and calls nothing not running until it has read
// every process, readings at most MaxReadingGap apart, for SeenFor.
func TestProcessReachabilityHistory(t *testing.T) {
	root, c := procHost(t)
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	writeHistory(t, c.StateFile, time.Time{}, time.Time{}) // a new agent
	// memcached is running at the first reading.
	dir := filepath.Join(root, "proc", "400")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/memcached", filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "maps"), []byte("55d0-55e0 r-xp 00000000 08:01 14 /usr/bin/memcached\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	read := func() (map[string]*model.Reachability, model.CoverageItem) {
		t.Helper()
		// A new Collector each time: the agent restarted.
		c2 := *c
		c2.hist = nil
		c2.Now = func() time.Time { return now }
		b, err := c2.Collect(context.Background(), "web1", "")
		if err != nil {
			t.Fatal(err)
		}
		return reachOf(t, b), coverage(b)
	}
	got, cov := read()
	if status(got["memcached"]) != model.ReachReachable || !strings.Contains(cov.Reason, "until that is 7 days") {
		t.Fatalf("first reading: memcached %+v, coverage %q", got["memcached"], cov.Reason)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	// Readings every 6 hours: memcached stays reachable for SeenFor after
	// it was last seen, then is not running.
	var last string
	for i := 1; i <= 30; i++ {
		now = now.Add(6 * time.Hour)
		got, cov = read()
		st := status(got["memcached"])
		if want := model.ReachReachable; i*6 < 7*24 && st != want {
			t.Fatalf("after %d h: %s, want %s (%+v)", i*6, st, want, got["memcached"])
		}
		last = st
	}
	if last != model.ReachNotRunning || cov.Reason != "read 2 processes" {
		t.Fatalf("after 180 h: memcached %s, coverage %q", last, cov.Reason)
	}

	// A gap longer than MaxReadingGap starts the run again.
	now = now.Add(MaxReadingGap + time.Hour)
	got, cov = read()
	if status(got["memcached"]) != model.ReachUnknown || !strings.Contains(cov.Reason, "since "+now.Format("2006-01-02 15:04 UTC")) {
		t.Errorf("after a gap: memcached %s, coverage %q", status(got["memcached"]), cov.Reason)
	}

	// So does a partial reading.
	writeHistory(t, c.StateFile, now.Add(-8*24*time.Hour), now)
	if err := os.RemoveAll(filepath.Join(root, "proc", "2")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Hour)
	if got, _ = read(); status(got["memcached"]) != model.ReachUnknown {
		t.Errorf("partial reading: %s", status(got["memcached"]))
	}
	var h procHistory
	data, _ := os.ReadFile(c.StateFile)
	if err := json.Unmarshal(data, &h); err != nil || !h.Since.IsZero() {
		t.Errorf("after a partial reading the run must end: %+v %v", h, err)
	}
}

// Without a state file, or with a damaged one, nothing is called not
// running: the agent cannot show it read every process for long enough.
func TestProcessReachabilityNoState(t *testing.T) {
	_, c := procHost(t)
	c.StateFile = ""
	b, err := c.Collect(context.Background(), "web1", "")
	if err != nil {
		t.Fatal(err)
	}
	if s := status(reachOf(t, b)["memcached"]); s != model.ReachUnknown || !strings.Contains(coverage(b).Reason, "no state directory") {
		t.Errorf("no state file: memcached %s, coverage %q", s, coverage(b).Reason)
	}

	_, c = procHost(t)
	if err := os.WriteFile(c.StateFile, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err = c.Collect(context.Background(), "web1", "")
	if err != nil {
		t.Fatal(err)
	}
	if s := status(reachOf(t, b)["memcached"]); s != model.ReachUnknown {
		t.Errorf("damaged state file: memcached %s", s)
	}
}

func TestDecodeProcAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0100007F:0050":                         "127.0.0.1:80",
		"00000000:01BB":                         "0.0.0.0:443",
		"00000000000000000000000000000000:1F90": "[::]:8080",
		"0000000000000000FFFF00000100007F:0016": "127.0.0.1:22",
		"zz:0050":                               "",
	} {
		got, ok := decodeProcAddr(in)
		if got != want || ok != (want != "") {
			t.Errorf("%s: %q %v, want %q", in, got, ok, want)
		}
	}
}

// Not this running host: no process reading at all.
func TestProcessReachabilityOff(t *testing.T) {
	_, c := procHost(t)
	c.ProcDir = ""
	b, err := c.Collect(context.Background(), "web1", "")
	if err != nil {
		t.Fatal(err)
	}
	if cov := coverage(b); cov.Scope != "" {
		t.Errorf("coverage %+v", cov)
	}
	if _, ok := b.Asset.Attributes[ProcessAccessAttribute]; ok {
		t.Error("process_access set for a filesystem that is not this running host")
	}
	for name, r := range reachOf(t, b) {
		if r != nil {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

// An agent in a container's PID namespace reads every process it can see,
// but not the host's: no kernel threads, so nothing is called not running.
func TestProcessReachabilityContainerNamespace(t *testing.T) {
	root, c := procHost(t)
	if err := os.RemoveAll(filepath.Join(root, "proc", "2")); err != nil {
		t.Fatal(err)
	}
	b, err := c.Collect(context.Background(), "web1", "")
	if err != nil {
		t.Fatal(err)
	}
	if cov := coverage(b); cov.Status != "checked" || !strings.Contains(cov.Reason, "kernel threads are not visible") {
		t.Errorf("coverage %+v", cov)
	}
	got := reachOf(t, b)
	for name, r := range got {
		if s := status(r); s == model.ReachNotRunning || s == model.ReachNotImported {
			t.Errorf("%s: %s without the host's processes", name, s)
		}
	}
	if s := status(got["nginx"]); s != model.ReachReachable {
		t.Errorf("nginx: %s (what was seen running still counts)", s)
	}
}

// A process in a container's own PID namespace can be pid 2 and call
// itself kthreadd; without the kernel's flag it is not taken for one.
func TestProcessReachabilityFakeKthreadd(t *testing.T) {
	root, c := procHost(t)
	write := func(rel, s string) {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("proc/2/stat", "2 (kthreadd) S 1 2 2 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 5 0 0\n")
	b, err := c.Collect(context.Background(), "web1", "")
	if err != nil {
		t.Fatal(err)
	}
	for name, r := range reachOf(t, b) {
		if status(r) == model.ReachNotRunning {
			t.Errorf("%s: not running without the host's kernel threads", name)
		}
	}
}

// Missing data never claims not running: an unreadable /proc, or no
// package file lists, leave every package unknown.
func TestProcessReachabilityMissingData(t *testing.T) {
	root, c := procHost(t)
	c.ProcDir = filepath.Join(root, "no-such-proc")
	b, err := c.Collect(context.Background(), "web1", "")
	if err != nil {
		t.Fatal(err)
	}
	for name, r := range reachOf(t, b) {
		if r != nil {
			t.Errorf("unreadable /proc: %s: %+v", name, r)
		}
	}
	if cov := coverage(b); !strings.HasPrefix(cov.Reason, "partial: ") {
		t.Errorf("unreadable /proc: coverage %+v", cov)
	}

	root, c = procHost(t)
	lists, _ := filepath.Glob(filepath.Join(root, "var/lib/dpkg/info/*.list"))
	for _, l := range lists {
		if err := os.Remove(l); err != nil {
			t.Fatal(err)
		}
	}
	b, err = c.Collect(context.Background(), "web1", "")
	if err != nil {
		t.Fatal(err)
	}
	for name, r := range reachOf(t, b) {
		if r != nil {
			t.Errorf("no file lists: %s: %+v", name, r)
		}
	}
	if cov := coverage(b); !strings.HasPrefix(cov.Reason, "unsupported: ") {
		t.Errorf("no file lists: coverage %+v", cov)
	}
}

// Each package needs SeenFor of readings of its own: one installed (or
// upgraded) an hour ago is not claimed, however long the host was read.
func TestProcessReachabilityNewPackage(t *testing.T) {
	_, c := procHost(t)
	now := c.Now()
	h := procHistory{Since: now.Add(-30 * 24 * time.Hour), Last: now.Add(-time.Hour), Installed: map[string]time.Time{}}
	for _, n := range fixturePackages {
		h.Installed["deb/"+n+"@1.0-1"] = now.Add(-30 * 24 * time.Hour)
	}
	h.Installed["deb/memcached@1.0-1"] = now.Add(-time.Hour)
	h.Installed["deb/memcached@0.9-1"] = now.Add(-30 * 24 * time.Hour) // the version before an upgrade
	data, _ := json.Marshal(h)
	if err := os.WriteFile(c.StateFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := c.Collect(context.Background(), "web1", "")
	if err != nil {
		t.Fatal(err)
	}
	if s := status(reachOf(t, b)["memcached"]); s != model.ReachUnknown {
		t.Errorf("memcached installed an hour ago: %s", s)
	}
	var after procHistory
	data, _ = os.ReadFile(c.StateFile)
	if err := json.Unmarshal(data, &after); err != nil {
		t.Fatal(err)
	}
	if _, ok := after.Installed["deb/memcached@0.9-1"]; ok {
		t.Error("a version no longer installed is kept")
	}
}

// Anything else that can start the service keeps it unknown; so does a
// crontab the agent cannot read.
func TestProcessReachabilityStartedOtherwise(t *testing.T) {
	cases := map[string]func(t *testing.T, root string){
		"an administrator's timer": func(t *testing.T, root string) {
			writeFile(t, root, "etc/systemd/system/memcached.timer", "[Timer]\nOnCalendar=daily\n")
		},
		"another unit's Wants=": func(t *testing.T, root string) {
			writeFile(t, root, "usr/lib/systemd/system/cache-warm.service", "[Unit]\nWants=memcached.service\n")
		},
		"a drop-in's Upholds=": func(t *testing.T, root string) {
			writeFile(t, root, "etc/systemd/system/app.service.d/override.conf", "[Unit]\nUpholds=memcached.service\n")
		},
		"a generated wants link": func(t *testing.T, root string) {
			dir := filepath.Join(root, "run/systemd/generator/multi-user.target.wants")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/usr/lib/systemd/system/memcached.service", filepath.Join(dir, "memcached.service")); err != nil {
				t.Fatal(err)
			}
		},
		"a crontab line": func(t *testing.T, root string) {
			writeFile(t, root, "etc/cron.d/warm", "*/5 * * * * root /usr/bin/memcached -d\n")
		},
		"inetd": func(t *testing.T, root string) {
			writeFile(t, root, "etc/inetd.conf", "cache stream tcp nowait root /usr/bin/memcached memcached\n")
		},
		"an unreadable crontab directory": func(t *testing.T, root string) {
			if os.Geteuid() == 0 {
				t.Skip("root reads every directory")
			}
			dir := filepath.Join(root, "var/spool/cron/crontabs")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o300); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(dir, 0o755) })
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			root, c := procHost(t)
			setup(t, root)
			b, err := c.Collect(context.Background(), "web1", "")
			if err != nil {
				t.Fatal(err)
			}
			if s := status(reachOf(t, b)["memcached"]); s != model.ReachUnknown {
				t.Errorf("memcached: %s", s)
			}
			if name == "an unreadable crontab directory" && !strings.Contains(coverage(b).Reason, "/var/spool/cron/crontabs could not be read") {
				t.Errorf("coverage %q", coverage(b).Reason)
			}
		})
	}
}

// systemd's own helpers (generators, sleep and shutdown hooks) run without
// a process to see, on a merged /usr as elsewhere.
func TestProcessReachabilitySystemdHelpers(t *testing.T) {
	f := &pkgFacts{}
	never := func(string) string { return "" }
	notDir := func(string) bool { return false }
	for _, p := range []string{"/usr/bin/x", "/usr/lib/systemd/system/x.service", "/usr/lib/systemd/system-generators/x-generator"} {
		f.classify(p, never, notDir)
	}
	if f.other == "" {
		t.Error("a system generator did not keep the package unknown")
	}
}

func writeFile(t *testing.T, root, rel, data string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}
