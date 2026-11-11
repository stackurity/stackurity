// Package gobintest builds small Go binaries for tests, offline: the
// dependencies are vendored, so no module proxy is contacted.
package gobintest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The fixture module example.com/app requires
//
//   - example.com/dep v1.4.0 (vendored);
//   - example.com/old v1.0.0, replaced by example.com/new v1.2.0;
//   - example.com/local, replaced by the local directory ./local.
//
// Built outside a repository, its main module version is "(devel)".
var files = map[string]string{
	"go.mod": `module example.com/app

go 1.22

require (
	example.com/dep v1.4.0
	example.com/local v0.0.0
	example.com/old v1.0.0
)

replace example.com/old v1.0.0 => example.com/new v1.2.0

replace example.com/local => ./local
`,
	"vendor/modules.txt": `# example.com/dep v1.4.0
## explicit; go 1.22
example.com/dep
# example.com/local v0.0.0 => ./local
## explicit; go 1.22
example.com/local
# example.com/old v1.0.0 => example.com/new v1.2.0
## explicit; go 1.22
example.com/old
# example.com/local => ./local
# example.com/old v1.0.0 => example.com/new v1.2.0
`,
	"vendor/example.com/dep/dep.go":     "package dep\n\nfunc Name() string { return \"dep\" }\n",
	"vendor/example.com/old/old.go":     "package old\n\nfunc Name() string { return \"old\" }\n",
	"vendor/example.com/local/local.go": "package local\n\nfunc Name() string { return \"local\" }\n",
	"local/go.mod":                      "module example.com/local\n\ngo 1.22\n",
	"local/local.go":                    "package local\n\nfunc Name() string { return \"local\" }\n",
	"main.go": `package main

import (
	"example.com/dep"
	"example.com/local"
	"example.com/old"
)

func main() { println(dep.Name(), old.Name(), local.Name()) }
`,
}

// Binaries are the fixture built for linux/amd64 (an ELF file whatever the
// test host), once with symbols and once stripped (-s -w).
type Binaries struct {
	Plain, Stripped []byte
}

var (
	once   sync.Once
	built  Binaries
	errOut string
)

// Build returns the fixture binaries, building them on first use. The test
// is skipped when no go command is available.
func Build(t testing.TB) Binaries {
	t.Helper()
	goCmd, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to build the fixture binary")
	}
	once.Do(func() {
		dir, err := os.MkdirTemp("", "gobintest")
		if err != nil {
			errOut = err.Error()
			return
		}
		defer os.RemoveAll(dir)
		for name, body := range files {
			p := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				errOut = err.Error()
				return
			}
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				errOut = err.Error()
				return
			}
		}
		build := func(out string, extra ...string) []byte {
			args := append([]string{"build", "-mod=vendor", "-buildvcs=false", "-o", out}, extra...)
			cmd := exec.Command(goCmd, append(args, ".")...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0",
				"GOFLAGS=", "GOWORK=off", "GOPROXY=off", "GOTOOLCHAIN=local")
			if b, err := cmd.CombinedOutput(); err != nil {
				errOut = strings.TrimSpace(string(b)) + ": " + err.Error()
				return nil
			}
			b, err := os.ReadFile(filepath.Join(dir, out))
			if err != nil {
				errOut = err.Error()
			}
			return b
		}
		built.Plain = build("app")
		if errOut == "" {
			built.Stripped = build("app-stripped", "-ldflags=-s -w")
		}
	})
	if errOut != "" {
		t.Fatalf("build fixture binary: %s", errOut)
	}
	return built
}
