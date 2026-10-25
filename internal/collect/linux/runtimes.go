package linux

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/model"
)

// Runtimes and servers are often installed outside the package manager: Node
// through nvm or a tarball, a database or search engine as a downloaded
// binary. Package databases cannot see them, yet they reach end of life and
// need patching like anything else. The agent looks for well-known binaries,
// skips those a package owns (the package is already inventoried), and
// reports the rest with the version they print.

// runtimeProbe describes one product. product is the endoflife.date name, so
// lifecycle data attaches to the generic purl.
type runtimeProbe struct {
	product string
	bins    []string
	args    []string
	re      *regexp.Regexp // first group is the version
}

var runtimeProbes = []runtimeProbe{
	{"nodejs", []string{"node"}, []string{"--version"}, regexp.MustCompile(`^v(\d+\.\d+\.\d+)`)},
	{"python", []string{"python3"}, []string{"--version"}, regexp.MustCompile(`^Python (\d+\.\d+\.\d+)`)},
	{"go", []string{"go"}, []string{"version"}, regexp.MustCompile(`^go version go(\d+\.\d+(?:\.\d+)?)`)},
	{"ruby", []string{"ruby"}, []string{"--version"}, regexp.MustCompile(`^ruby (\d+\.\d+\.\d+)`)},
	{"php", []string{"php"}, []string{"--version"}, regexp.MustCompile(`^PHP (\d+\.\d+\.\d+)`)},
	{"redis", []string{"redis-server"}, []string{"--version"}, regexp.MustCompile(`v=(\d+\.\d+\.\d+)`)},
	{"valkey", []string{"valkey-server"}, []string{"--version"}, regexp.MustCompile(`v=(\d+\.\d+\.\d+)`)},
	{"mysql", []string{"mysqld"}, []string{"--version"}, regexp.MustCompile(`Ver (\d+\.\d+\.\d+)`)},
	{"mariadb", []string{"mariadbd"}, []string{"--version"}, regexp.MustCompile(`Ver (\d+\.\d+\.\d+)`)},
	{"postgresql", []string{"postgres"}, []string{"--version"}, regexp.MustCompile(`\(PostgreSQL\) (\d+(?:\.\d+)?)`)},
	{"mongodb", []string{"mongod"}, []string{"--version"}, regexp.MustCompile(`db version v(\d+\.\d+\.\d+)`)},
	{"nginx", []string{"nginx"}, []string{"-v"}, regexp.MustCompile(`nginx/(\d+\.\d+\.\d+)`)},
	{"haproxy", []string{"haproxy"}, []string{"-v"}, regexp.MustCompile(`version (\d+\.\d+\.\d+)`)},
	{"meilisearch", []string{"meilisearch"}, []string{"--version"}, regexp.MustCompile(`meilisearch (\d+\.\d+\.\d+)`)},
}

// runtimeDirs are searched for the binaries. Globs cover version managers
// and vendor trees under /opt. Home directories are only visible when the
// agent's service unit allows it (ProtectHome=read-only).
var runtimeDirs = []string{
	"/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
	"/usr/local/*/bin", "/opt/*/bin", "/opt/*/*/bin",
	"/root/.nvm/versions/node/*/bin", "/home/*/.nvm/versions/node/*/bin", "/usr/local/nvm/versions/node/*/bin",
	"/root/.pyenv/versions/*/bin", "/home/*/.pyenv/versions/*/bin",
}

// versionFromPath reads the version a version manager encodes in the path,
// e.g. ~/.nvm/versions/node/v20.11.1/bin/node.
var versionFromPath = regexp.MustCompile(`/(?:\.nvm/versions/node|nvm/versions/node|\.pyenv/versions)/v?(\d+\.\d+\.\d+)/bin/[^/]+$`)

// maxRuntimeCandidates bounds the work on hosts with many vendor trees.
const maxRuntimeCandidates = 200

// collectRuntimes adds unmanaged runtimes to b and records coverage.
func (c *Collector) collectRuntimes(ctx context.Context, b *model.ObservationBatch) {
	owned, ownErr := c.ownedFiles()
	candidates := c.runtimeCandidates()
	var rpmCheck []string
	for _, cand := range candidates {
		if owned != nil && (owned[cand.path] || owned[cand.resolved] || owned[usrMerge(cand.path)] || owned[usrMerge(cand.resolved)]) {
			cand.owned = true
		}
		if owned == nil {
			rpmCheck = append(rpmCheck, cand.resolved)
		}
	}
	if len(rpmCheck) > 0 && c.RunRPMOwner != nil {
		if _, err := c.LookPath("rpm"); err == nil {
			if byRPM, err := c.RunRPMOwner(ctx, c.Root, rpmCheck); err == nil {
				for _, cand := range candidates {
					cand.owned = byRPM[cand.resolved]
				}
				ownErr = nil
			} else {
				ownErr = err
			}
		}
	}
	if ownErr != nil {
		// Without ownership data every runtime would be reported twice
		// (once as a package), so report nothing rather than noise.
		b.Cover("runtimes", "skipped", "package ownership unknown: "+ownErr.Error())
		return
	}

	seen := map[string]bool{}
	for _, cand := range candidates {
		if cand.owned || seen[cand.resolved] {
			continue
		}
		seen[cand.resolved] = true
		b.Observations = append(b.Observations, c.probeRuntime(ctx, cand))
	}
	b.Cover("runtimes", "checked", "")
}

type runtimeCandidate struct {
	probe    runtimeProbe
	path     string // as found, absolute on the host
	resolved string // after symlinks, absolute on the host
	owned    bool
}

func (c *Collector) runtimeCandidates() []*runtimeCandidate {
	var out []*runtimeCandidate
	for _, pattern := range runtimeDirs {
		dirs, _ := filepath.Glob(c.path(pattern))
		sort.Strings(dirs)
		for _, dir := range dirs {
			for _, p := range runtimeProbes {
				for _, bin := range p.bins {
					hostPath := c.hostPath(filepath.Join(dir, bin))
					resolved, ok := c.resolve(hostPath)
					if !ok {
						continue
					}
					if fi, err := os.Stat(c.path(resolved)); err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
						continue
					}
					out = append(out, &runtimeCandidate{probe: p, path: hostPath, resolved: resolved})
					if len(out) >= maxRuntimeCandidates {
						return out
					}
				}
			}
		}
	}
	return out
}

// hostPath turns a path under Root back into the host's absolute path.
func (c *Collector) hostPath(p string) string {
	rel, err := filepath.Rel(c.Root, p)
	if err != nil {
		return p
	}
	return "/" + filepath.ToSlash(rel)
}

// resolve follows symlinks inside Root, so absolute link targets resolve
// against the collected filesystem rather than the agent's own.
func (c *Collector) resolve(hostPath string) (string, bool) {
	cur := hostPath
	for i := 0; i < 16; i++ {
		fi, err := os.Lstat(c.path(cur))
		if err != nil {
			return "", false
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			// Resolve symlinked parent directories too (e.g. /bin -> usr/bin).
			dir, base := path.Split(cur)
			if dir != "/" {
				if rd, ok := c.resolveDir(strings.TrimSuffix(dir, "/")); ok {
					return path.Join(rd, base), true
				}
			}
			return cur, true
		}
		target, err := os.Readlink(c.path(cur))
		if err != nil {
			return "", false
		}
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(cur), target)
		}
		cur = path.Clean(target)
	}
	return "", false
}

func (c *Collector) resolveDir(dir string) (string, bool) {
	real, err := filepath.EvalSymlinks(c.path(dir))
	if err != nil {
		return "", false
	}
	root, err := filepath.EvalSymlinks(c.Root)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(root, real)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", false
	}
	return "/" + filepath.ToSlash(rel), true
}

// usrMerge maps /bin/x to /usr/bin/x and back: package lists may use either
// on merged-/usr systems.
func usrMerge(p string) string {
	for _, d := range []string{"/bin/", "/sbin/", "/lib/"} {
		if strings.HasPrefix(p, d) {
			return "/usr" + p
		}
		if strings.HasPrefix(p, "/usr"+d) {
			return strings.TrimPrefix(p, "/usr")
		}
	}
	return p
}

// ownedFiles returns the paths that dpkg or apk installed. It returns nil,
// nil when neither database exists (an rpm host is checked separately).
func (c *Collector) ownedFiles() (map[string]bool, error) {
	owned := map[string]bool{}
	found := false
	if lists, err := filepath.Glob(c.path("var/lib/dpkg/info/*.list")); err == nil && len(lists) > 0 {
		found = true
		for _, l := range lists {
			f, err := os.Open(l)
			if err != nil {
				return nil, err
			}
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				// Binaries for runtime detection; library metadata for
				// host-wide npm and Python packages.
				if line := sc.Text(); strings.Contains(line, "bin/") || strings.Contains(line, "node_modules/") ||
					strings.Contains(line, "-packages/") {
					owned[line] = true
				}
			}
			f.Close()
		}
	}
	if f, err := os.Open(c.path("lib/apk/db/installed")); err == nil {
		found = true
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
		var dir string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "F:"):
				dir = "/" + line[2:]
			case strings.HasPrefix(line, "R:"):
				owned[path.Join(dir, line[2:])] = true
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	if !found {
		if hasRPMDB(c) {
			return nil, nil
		}
		return nil, fmt.Errorf("no package database")
	}
	return owned, nil
}

func (c *Collector) probeRuntime(ctx context.Context, cand *runtimeCandidate) model.Observation {
	o := model.Observation{
		Purl:       purl("generic", "", cand.probe.product, "", nil),
		Location:   cand.path,
		Scope:      "runtime",
		Confidence: model.ConfidenceUnknown,
		Evidence:   map[string]string{"kind": "runtime", "install": "unmanaged", "binary": cand.resolved},
	}
	set := func(product, v string, conf model.Confidence, how string) {
		o.Version, o.Confidence = v, conf
		o.Purl = purl("generic", "", product, v, nil)
		o.Evidence["detected_by"] = how
	}
	if m := versionFromPath.FindStringSubmatch(cand.resolved); m != nil {
		set(cand.probe.product, m[1], model.ConfidenceInferred, "install-path")
		return o
	}
	if c.RunVersion == nil {
		o.Evidence["not_run"] = "running binaries is disabled"
		return o
	}
	if reason := c.unsafeToRun(cand.resolved); reason != "" {
		o.Evidence["not_run"] = reason
		return o
	}
	out, err := c.RunVersion(ctx, c.path(cand.resolved), cand.probe.args)
	if m := cand.probe.re.FindSubmatch(out); m != nil {
		product := cand.probe.product
		if product == "mysql" && bytes.Contains(out, []byte("MariaDB")) {
			product = "mariadb" // older MariaDB installs ship the server as mysqld
		}
		set(product, string(m[1]), model.ConfidenceConfirmed, "version-output")
		return o
	}
	if err != nil {
		o.Evidence["error"] = truncateErr(err.Error())
	} else {
		o.Evidence["error"] = "version not recognised in output"
	}
	return o
}

// unsafeToRun refuses binaries another user could have replaced: running
// them would hand that user the agent's privileges.
func (c *Collector) unsafeToRun(hostPath string) string {
	for p := hostPath; ; p = path.Dir(p) {
		fi, err := os.Stat(c.path(p))
		if err != nil {
			return "cannot stat " + p
		}
		uid, ok := fileOwner(fi)
		if !ok {
			return "file ownership unavailable"
		}
		if uid != 0 && uid != c.UID {
			return fmt.Sprintf("%s is owned by uid %d", p, uid)
		}
		writable := fi.Mode().Perm()&0o022 != 0
		sticky := fi.Mode()&os.ModeSticky != 0
		if writable && !(fi.IsDir() && sticky) {
			return p + " is writable by other users"
		}
		if p == "/" {
			return ""
		}
	}
}

func truncateErr(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// runVersion runs a binary's version flag with a clean environment, no
// input and a short timeout, keeping at most 64 KiB of output.
func runVersion(ctx context.Context, bin string, args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "HOME=/nonexistent"}
	cmd.Dir = "/"
	var buf limitedBuffer
	buf.max = 64 << 10
	cmd.Stdout, cmd.Stderr = &buf, &buf // nginx and haproxy print to stderr
	err := cmd.Run()
	return buf.Bytes(), err
}

type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

var _ io.Writer = (*limitedBuffer)(nil)

// runRPMOwner asks rpm which of paths belong to a package.
func runRPMOwner(ctx context.Context, root string, paths []string) (map[string]bool, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	args := []string{"-qf", "--queryformat", "%{NAME}\n"}
	if root != "/" && root != "" {
		args = append([]string{"--root", root}, args...)
	}
	cmd := exec.CommandContext(ctx, "rpm", append(args, paths...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil, err // rpm exits non-zero when any path is unowned, so only empty output is a failure
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != len(paths) {
		return nil, fmt.Errorf("rpm -qf returned %d lines for %d paths", len(lines), len(paths))
	}
	owned := map[string]bool{}
	for i, l := range lines {
		owned[paths[i]] = !strings.Contains(l, "is not owned by any package")
	}
	return owned, nil
}
