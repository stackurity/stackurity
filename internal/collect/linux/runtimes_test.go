package linux

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

func TestUnmanagedRuntimes(t *testing.T) {
	root := t.TempDir()
	file := func(p, data string, mode os.FileMode) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil {
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
	file("etc/os-release", "ID=debian\nVERSION_ID=12\n", 0o644)
	file("var/lib/dpkg/status", "Package: python3\nStatus: install ok installed\nVersion: 3.11.2-1\n\n", 0o644)
	// dpkg lists the pre-usrmerge path; the binary lives in /usr/bin.
	file("var/lib/dpkg/info/python3.list", "/.\n/bin\n/bin/python3\n", 0o644)
	link("bin", "usr/bin")
	file("usr/bin/python3", "", 0o755)
	file("usr/local/bin/redis-server", "", 0o755)
	file("usr/local/sbin/mysqld", "", 0o755)
	file("usr/local/bin/php", "", 0o777) // anyone could replace it
	file("opt/node-v20.11.1-linux-x64/bin/node", "", 0o755)
	link("usr/local/bin/node", "/opt/node-v20.11.1-linux-x64/bin/node")
	file("root/.nvm/versions/node/v18.19.0/bin/node", "", 0o755)

	c := fixture(root)
	var ran []string
	c.RunVersion = func(_ context.Context, bin string, _ []string) ([]byte, error) {
		ran = append(ran, strings.TrimPrefix(bin, root))
		switch filepath.Base(bin) {
		case "redis-server":
			return []byte("Redis server v=7.2.4 sha=00000000:0 malloc=jemalloc-5.3.0 bits=64 build=1\n"), nil
		case "mysqld":
			return []byte("/usr/local/sbin/mysqld  Ver 10.6.12-MariaDB for Linux on x86_64 (MariaDB Server)\n"), nil
		case "node":
			return []byte("v20.11.1\n"), nil
		}
		return nil, os.ErrNotExist
	}
	osBatch, err := c.Collect(context.Background(), "web-1", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range osBatch.Observations {
		if o.Evidence["kind"] == "runtime" {
			t.Errorf("runtime in the OS package batch: %s", o.Purl)
		}
	}
	b := c.CollectSoftware(context.Background(), osBatch, nil)
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if b.Collector.ID != SoftwareCollectorID || b.Asset.Name != "web-1" || !b.Complete {
		t.Errorf("software batch = %+v %+v", b.Collector, b.Coverage)
	}
	got := map[string]model.Observation{}
	for _, o := range b.Observations {
		if o.Evidence["kind"] == "runtime" {
			got[o.Purl] = o
		}
	}
	for _, want := range []string{"pkg:generic/redis@7.2.4", "pkg:generic/mariadb@10.6.12", "pkg:generic/nodejs@20.11.1", "pkg:generic/nodejs@18.19.0", "pkg:generic/php"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s; have %v", want, keys(got))
		}
	}
	if len(got) != 5 {
		t.Errorf("python3 is owned by dpkg and /opt node is one binary; got %v", keys(got))
	}
	if o := got["pkg:generic/nodejs@18.19.0"]; o.Evidence["detected_by"] != "install-path" || o.Confidence != model.ConfidenceInferred {
		t.Errorf("nvm node = %+v", o)
	}
	if o := got["pkg:generic/php"]; !strings.Contains(o.Evidence["not_run"], "writable by other users") || o.Confidence != model.ConfidenceUnknown {
		t.Errorf("php = %+v", o)
	}
	for _, r := range ran {
		if strings.Contains(r, "php") || strings.Contains(r, ".nvm") || strings.Contains(r, "python3") {
			t.Errorf("ran %s", r)
		}
	}
	var cov string
	for _, cv := range b.Coverage {
		if cv.Scope == "runtimes" {
			cov = cv.Status
		}
	}
	if cov != "checked" {
		t.Errorf("runtimes coverage = %q", cov)
	}
}

func TestRuntimesDisabled(t *testing.T) {
	c := fixture("testdata/debian")
	c.Runtimes = false
	osBatch, err := c.Collect(context.Background(), "web-1", "")
	if err != nil {
		t.Fatal(err)
	}
	b := c.CollectSoftware(context.Background(), osBatch, nil)
	for _, cv := range b.Coverage {
		if cv.Scope == "runtimes" {
			t.Errorf("runtimes checked while disabled")
		}
	}
}

func keys(m map[string]model.Observation) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
