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

// CyberStrikeAI's go.mod declares the bare module "cyberstrike-ai" and its
// server is built from ./cmd/server (github.com/AIPentest/CyberStrikeAI).
func TestCyberStrikeAIModules(t *testing.T) {
	// 0: no match, 1: name only (medium), 2: the tool's module (high).
	for in, want := range map[string]int{
		"cyberstrike-ai":                     2,
		"cyberstrike-ai/cmd/server":          2,
		"CyberStrike-AI":                     2,
		"github.com/someone/cyberstrike-ai":  1,
		"github.com/someone/CyberStrikeAI":   1,
		"cyberstrikeai":                      1,
		"cyberstrike-aid":                    0,
		"github.com/acme/cyberstrike":        0,
		"github.com/acme/app/cyberstrikeai":  0,
		"example.com/a/b/cyberstrike-ai/cmd": 0,
	} {
		tool, _, strong, ok := toolForModule(in)
		got := 0
		if ok {
			got = 1
			if strong {
				got = 2
			}
			if tool.name != "CyberStrikeAI" {
				t.Errorf("toolForModule(%q) = %s, want CyberStrikeAI", in, tool.name)
			}
		}
		if got != want {
			t.Errorf("toolForModule(%q) = %d, want %d", in, got, want)
		}
	}

	f, ok := GoBinaryAttackTool("/opt/cs/cyberstrike-ai", "cyberstrike-ai/cmd/server", "cyberstrike-ai")
	if !ok || f.Rule != RuleAttackToolCyberStrikeAI || f.Severity != "high" || f.Category != model.ConfigAttackTool ||
		!strings.Contains(f.Why, "CyberStrikeAI") {
		t.Errorf("binary finding = %+v, %v", f, ok)
	}
	f, ok = GoBinaryAttackTool("/tmp/x", "github.com/someone/cyberstrikeai", "github.com/someone/cyberstrikeai")
	if !ok || f.Rule != RuleAttackToolCyberStrikeAIName || f.Severity != "medium" {
		t.Errorf("name-only binary finding = %+v, %v", f, ok)
	}
	if RuleDoc(RuleAttackToolCyberStrikeAI) != AttackToolsDoc {
		t.Error("CyberStrikeAI rule has no doc link")
	}
}

func TestCyberStrikeAIImagesAndRepo(t *testing.T) {
	for _, ref := range []string{"cyberstrike-ai:latest", "ghcr.io/acme/cyberstrikeai:1"} {
		if got := ImageAttackTools(ref); len(got) != 1 || got[0].Rule != RuleAttackToolCyberStrikeAIName || got[0].Severity != "medium" {
			t.Errorf("ImageAttackTools(%q) = %+v", ref, got)
		}
	}
	if got := ImageAttackTools("acme/cyberstrike-ai-docs", "nginx:1.27"); len(got) != 0 {
		t.Errorf("unrelated images reported: %+v", got)
	}

	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module cyberstrike-ai\n\ngo 1.25.0\n"})
	got := byRule(Repo(context.Background(), dir).Found)
	if fs := got[RuleAttackToolCyberStrikeAI]; len(fs) != 1 || fs[0].Path != "go.mod" || fs[0].Line != 1 || fs[0].Severity != "high" {
		t.Errorf("go.mod finding: %+v", got)
	}
}

// A real Go executable built from the cyberstrike-ai module's cmd/server,
// on a host where an intruder would leave it.
func TestHostCyberStrikeAI(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command")
	}
	src := t.TempDir()
	writeTree(t, src, map[string]string{
		"go.mod":             "module cyberstrike-ai\n\ngo 1.22\n",
		"cmd/server/main.go": "package main\n\nfunc main() {}\n",
	})
	out := filepath.Join(t.TempDir(), "cyberstrike-ai")
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, "./cmd/server")
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
		"home/deploy/CyberStrikeAI/go.mod": "module cyberstrike-ai\n\ngo 1.25.0\n",
	})
	for _, p := range []string{"opt/CyberStrikeAI/cyberstrike-ai", "dev/shm/srv"} {
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
	want := map[string]string{"/opt/CyberStrikeAI/cyberstrike-ai": RuleAttackToolCyberStrikeAI,
		"/dev/shm/srv": RuleAttackToolCyberStrikeAI, "/home/deploy/CyberStrikeAI/go.mod": RuleAttackToolCyberStrikeAI}
	if len(got) != len(want) {
		t.Fatalf("attack tool findings = %v, want %v", got, want)
	}
	for p, r := range want {
		if got[p] != r {
			t.Errorf("%s: rule %q, want %q", p, got[p], r)
		}
	}
}
