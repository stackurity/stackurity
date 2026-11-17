package linux

import (
	"context"
	"errors"
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
	if err := os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	link("lib", "usr/lib")
	var status strings.Builder
	pkg := func(name string, files ...string) {
		status.WriteString("Package: " + name + "\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\n\n")
		write("var/lib/dpkg/info/"+name+":amd64.list", "/.\n/usr\n"+strings.Join(files, "\n")+"\n")
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
		ProcDir: filepath.Join(root, "proc"), Now: func() time.Time { return now }, ProcessAccess: func() bool { return true }}
	return root, c
}

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
		"htop":                       model.ReachNotRunning,
		"libunused1":                 model.ReachUnknown, // libraries load on demand
		"logrotate":                  model.ReachUnknown, // runs from cron
		"python3-yaml":               model.ReachUnknown, // scripts
		"init-system-helpers":        model.ReachUnknown, // scripts, found by their "#!"
		"busybox-binsh":              model.ReachUnknown, // a link to another program
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
	if ev := strings.Join(got["htop"].Evidence, " | "); !strings.Contains(ev, "2026-11-17 12:00 UTC (2 processes read)") || !strings.Contains(ev, "now and then") {
		t.Errorf("htop evidence: %s", ev)
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

// A long-running agent remembers what it saw running for SeenFor.
func TestProcessReachabilityRemembers(t *testing.T) {
	root, c := procHost(t)
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return now }
	if _, err := c.Collect(context.Background(), "web1", ""); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, "proc", "200")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Hour)
	b, err := c.Collect(context.Background(), "web1", "")
	if err != nil {
		t.Fatal(err)
	}
	if r := reachOf(t, b)["dash"]; status(r) != model.ReachReachable || !strings.Contains(strings.Join(r.Evidence, " "), "not running at 2026-11-17 18:00 UTC") {
		t.Errorf("dash 6 h later: %+v", r)
	}
	now = now.Add(SeenFor)
	b, err = c.Collect(context.Background(), "web1", "")
	if err != nil {
		t.Fatal(err)
	}
	if s := status(reachOf(t, b)["dash"]); s != model.ReachNotRunning {
		t.Errorf("dash after %v: %s", SeenFor, s)
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
