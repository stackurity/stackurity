package confcheck

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

// PentAGI's backend/go.mod declares the bare module "pentagi"; the server
// is built from ./cmd/pentagi and its test tools from ./cmd/ctester and
// others (github.com/vxcontrol/pentagi). Its image is vxcontrol/pentagi.
func TestPentAGIModules(t *testing.T) {
	// 0: no match, 1: name only (medium), 2: the tool's module (high).
	for in, want := range map[string]int{
		"pentagi":                       2,
		"pentagi/cmd/pentagi":           2,
		"pentagi/cmd/ctester":           2,
		"PentAGI":                       2,
		"github.com/someone/pentagi":    1,
		"github.com/vxcontrol/PentAGI":  1,
		"pentagis":                      0,
		"pentagi-docs":                  0,
		"github.com/acme/pentagon":      0,
		"github.com/acme/app/pentagi":   0,
		"example.com/a/b/pentagi/cmd/x": 0,
	} {
		tool, _, strong, ok := toolForModule(in)
		got := 0
		if ok {
			got = 1
			if strong {
				got = 2
			}
			if tool.name != "PentAGI" {
				t.Errorf("toolForModule(%q) = %s, want PentAGI", in, tool.name)
			}
		}
		if got != want {
			t.Errorf("toolForModule(%q) = %d, want %d", in, got, want)
		}
	}

	f, ok := GoBinaryAttackTool("/pentagi", "pentagi/cmd/pentagi", "pentagi")
	if !ok || f.Rule != RuleAttackToolPentAGI || f.Severity != "high" || f.Category != model.ConfigAttackTool ||
		!strings.Contains(f.Why, "PentAGI") {
		t.Errorf("binary finding = %+v, %v", f, ok)
	}
	f, ok = GoBinaryAttackTool("/tmp/x", "github.com/someone/pentagi", "github.com/someone/pentagi")
	if !ok || f.Rule != RuleAttackToolPentAGIName || f.Severity != "medium" {
		t.Errorf("name-only binary finding = %+v, %v", f, ok)
	}
	if RuleDoc(RuleAttackToolPentAGI) != AttackToolsDoc {
		t.Error("PentAGI rule has no doc link")
	}
}

func TestPentAGIImagesAndRepo(t *testing.T) {
	for _, ref := range []string{"vxcontrol/pentagi:latest", "docker.io/vxcontrol/pentagi@sha256:abc", "ghcr.io/acme/pentagi:1"} {
		if got := ImageAttackTools(ref); len(got) != 1 || got[0].Rule != RuleAttackToolPentAGIName || got[0].Severity != "medium" {
			t.Errorf("ImageAttackTools(%q) = %+v", ref, got)
		}
	}
	// PentAGI's own helper images are not the tool.
	if got := ImageAttackTools("vxcontrol/pgvector:latest", "vxcontrol/scraper:latest", "acme/pentagi-docs"); len(got) != 0 {
		t.Errorf("unrelated images reported: %+v", got)
	}

	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":             "module pentagi\n\ngo 1.26.5\n",
		"docker-compose.yml": "services:\n  pentagi:\n    image: vxcontrol/pentagi:latest\n",
	})
	got := byRule(Repo(context.Background(), dir).Found)
	if fs := got[RuleAttackToolPentAGI]; len(fs) != 1 || fs[0].Path != "go.mod" || fs[0].Line != 1 || fs[0].Severity != "high" {
		t.Errorf("go.mod finding: %+v", got)
	}
	if fs := got[RuleAttackToolPentAGIName]; len(fs) != 1 || fs[0].Path != "docker-compose.yml" || fs[0].Line != 3 {
		t.Errorf("compose finding: %+v", got)
	}
}

// A clone of github.com/vxcontrol/pentagi: the Go server's go.mod is in
// backend/, under the web frontend.
func TestPentAGIClone(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"backend/go.mod":        "module pentagi\n\ngo 1.26.5\n",
		"frontend/package.json": "{}\n",
	})
	got := byRule(Repo(context.Background(), dir).Found)
	if fs := got[RuleAttackToolPentAGI]; len(fs) != 1 || fs[0].Path != "backend/go.mod" || fs[0].Severity != "high" {
		t.Errorf("backend/go.mod finding: %+v", got)
	}
	// Another project's backend is not reported.
	other := t.TempDir()
	writeTree(t, other, map[string]string{"backend/go.mod": "module example.com/shop/backend\n"})
	if got := Repo(context.Background(), other).Found; len(byRule(got)[RuleAttackToolPentAGI]) != 0 {
		t.Errorf("unrelated backend reported: %+v", got)
	}
}

// A real Go executable built from the pentagi module's cmd/pentagi, where
// the project's Dockerfile puts it and where an intruder would leave it.
func TestHostPentAGI(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command")
	}
	src := t.TempDir()
	writeTree(t, src, map[string]string{
		"go.mod":              "module pentagi\n\ngo 1.22\n",
		"cmd/pentagi/main.go": "package main\n\nfunc main() {}\n",
	})
	out := filepath.Join(t.TempDir(), "pentagi")
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, "./cmd/pentagi")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=-mod=mod", "GOPROXY=off", "GOWORK=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %s", b)
	}
	bin, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/passwd":                       "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n",
		"home/deploy/pentagi/go.mod":       "module pentagi\n\ngo 1.26.5\n",
		"home/deploy/pentagi-notes/go.mod": "module example.com/notes\n\ngo 1.26.5\n",
	})
	for _, p := range []string{"opt/pentagi/bin/pentagi", "var/tmp/agent"} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, bin, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string]string{}
	for _, f := range Host(context.Background(), root, nil).Found {
		if f.Category == model.ConfigAttackTool {
			got[f.Path] = f.Rule
		}
	}
	want := map[string]string{"/opt/pentagi/bin/pentagi": RuleAttackToolPentAGI,
		"/var/tmp/agent": RuleAttackToolPentAGI, "/home/deploy/pentagi/go.mod": RuleAttackToolPentAGI}
	if len(got) != len(want) {
		t.Fatalf("attack tool findings = %v, want %v", got, want)
	}
	for p, r := range want {
		if got[p] != r {
			t.Errorf("%s: rule %q, want %q", p, got[p], r)
		}
	}
}
