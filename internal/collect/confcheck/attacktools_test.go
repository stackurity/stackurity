package confcheck

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stackurity/stackurity/internal/collect/gobin/gobintest"
	"github.com/stackurity/stackurity/internal/model"
)

func TestToolForModule(t *testing.T) {
	// 0: no match, 1: name only (medium), 2: a known module (high).
	for in, want := range map[string]int{
		"github.com/Autumn-27/ARTEX":               1 + 1,
		"github.com/autumn-27/artex/cmd/console":   2,
		"github.com/RuoJi6/ARTEX":                  2,
		"github.com/cskwork/scopeweaver":           2,
		"artex":                                    1,
		"github.com/someone/artex":                 1,
		"example.com/acme/tools/artex":             0,
		"github.com/acme/artexpaint":               0,
		"github.com/stackurity/stackurity":         0,
		"":                                         0,
		"github.com/acme/app/internal/scopeweaver": 0,
	} {
		_, _, strong, ok := toolForModule(in)
		got := 0
		if ok {
			got = 1
			if strong {
				got = 2
			}
		}
		if got != want {
			t.Errorf("toolForModule(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestImageRepo(t *testing.T) {
	for in, want := range map[string]string{
		"tomicdd/artex":                    "tomicdd/artex",
		"docker.io/tomicdd/artex:latest":   "tomicdd/artex",
		"TOMICDD/ARTEX@sha256:abc":         "tomicdd/artex",
		"localhost:5000/team/artex:v2":     "team/artex",
		"library/nginx:1.27":               "nginx",
		"ghcr.io/acme/scopeweaver:1.0":     "acme/scopeweaver",
		"registry.example.com:443/x/y/z:1": "x/y/z",
		"":                                 "",
	} {
		if got := imageRepo(in); got != want {
			t.Errorf("imageRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestImageAttackTools(t *testing.T) {
	got := byRule(ImageAttackTools("docker.io/tomicdd/artex:latest", "tomicdd/artex:v1"))
	if len(got[RuleAttackToolArtexBackdoor]) != 1 || len(got[RuleAttackToolArtex]) != 0 {
		t.Fatalf("backdoored image: %+v", got)
	}
	f := got[RuleAttackToolArtexBackdoor][0]
	if f.Severity != "high" || f.Category != model.ConfigAttackTool || !strings.Contains(f.Why, "backdoor") {
		t.Errorf("finding = %+v", f)
	}
	if got := ImageAttackTools("ghcr.io/acme/artex:2"); len(got) != 1 || got[0].Rule != RuleAttackToolArtexName || got[0].Severity != "medium" {
		t.Errorf("image named artex: %+v", got)
	}
	// One image tagged as the backdoored build and by name: one finding.
	if got := ImageAttackTools("artex:local", "tomicdd/artex:latest"); len(got) != 1 || got[0].Rule != RuleAttackToolArtexBackdoor {
		t.Errorf("backdoored image with a second tag: %+v", got)
	}
	// Pulled by digest only.
	if got := ImageAttackTools("tomicdd/artex@sha256:" + strings.Repeat("ab", 32)); len(got) != 1 {
		t.Errorf("digest reference: %+v", got)
	}
	if got := ImageAttackTools("nginx:1.27", "artexpaint/app", "acme/artex-docs-site"); len(got) != 0 {
		t.Errorf("unrelated images reported: %+v", got)
	}
	if RuleDoc(RuleAttackToolArtex) != AttackToolsDoc || RuleDoc(RuleAttackToolArtexBackdoor) != AttackToolsDoc {
		t.Error("attack tool rules have no doc link")
	}
}

func TestRepoAttackTools(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":             "// fork\nmodule github.com/Autumn-27/ARTEX\n\ngo 1.24\n",
		"docker-compose.yml": "services:\n  console:\n    image: \"tomicdd/artex:latest\"\n    ports: [\"8787:8787\"]\n",
		"Dockerfile": "FROM --platform=linux/amd64 golang:1.24 AS build\nRUN <<EOF\nfrom artex import console\nEOF\n" +
			"RUN python -c 'x' \\\n    from artex\nFROM congdonglinux/artex\n",
	})
	scan := Repo(context.Background(), dir)
	got := byRule(scan.Found)
	if len(got[RuleAttackToolArtex]) != 1 || got[RuleAttackToolArtex][0].Path != "go.mod" || got[RuleAttackToolArtex][0].Line != 2 {
		t.Errorf("go.mod finding: %+v", got[RuleAttackToolArtex])
	}
	bd := got[RuleAttackToolArtexBackdoor]
	if len(bd) != 2 {
		t.Fatalf("backdoored image findings = %+v", bd)
	}
	for _, f := range bd {
		if f.Path != "docker-compose.yml" && f.Path != "Dockerfile" || f.Line == 0 || !strings.HasPrefix(f.Fix, "Remove ") {
			t.Errorf("finding = %+v", f)
		}
	}

	// A Compose merge key is not a heredoc: the image after it is still read.
	compose := t.TempDir()
	writeTree(t, compose, map[string]string{"compose.yaml": "x-base: &base\n  restart: always\nservices:\n  c:\n    <<: *base\n    image: tomicdd/artex\n"})
	if got := byRule(Repo(context.Background(), compose).Found); len(got[RuleAttackToolArtexBackdoor]) != 1 {
		t.Errorf("compose with a merge key: %+v", got)
	}

	clean := t.TempDir()
	writeTree(t, clean, map[string]string{"go.mod": "module github.com/acme/web\n", "Dockerfile": "FROM nginx:1.27\n"})
	if s := Repo(context.Background(), clean); len(s.Found) != 0 {
		t.Errorf("clean repo: %+v", s.Found)
	}
}

var (
	artexOnce sync.Once
	artexBin  []byte
	artexErr  string
)

// artexBinary builds a tiny linux/amd64 program whose module path is
// ARTEX's, offline (no dependencies).
func artexBinary(t *testing.T) []byte {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command")
	}
	artexOnce.Do(func() {
		dir, err := os.MkdirTemp("", "artex-fixture")
		if err != nil {
			artexErr = err.Error()
			return
		}
		defer os.RemoveAll(dir)
		_ = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module github.com/Autumn-27/ARTEX\n\ngo 1.22\n"), 0o600)
		_ = os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o600)
		cmd := exec.Command("go", "build", "-trimpath", "-o", "artex", ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=-mod=mod", "GOPROXY=off", "GOWORK=off")
		if out, err := cmd.CombinedOutput(); err != nil {
			artexErr = string(out)
			return
		}
		artexBin, _ = os.ReadFile(filepath.Join(dir, "artex"))
	})
	if artexBin == nil {
		t.Fatalf("build fixture: %s", artexErr)
	}
	return artexBin
}

func TestHostAttackTools(t *testing.T) {
	bin := artexBinary(t)
	benign := gobintest.Build(t).Plain
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/passwd":               "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n",
		"home/deploy/ARTEX/go.mod": "module github.com/Autumn-27/ARTEX\n",
		"opt/web/go.mod":           "module github.com/acme/web\n",
	})
	for p, data := range map[string][]byte{"app/artex": bin, "opt/tools/console": bin, "usr/local/bin/app": benign,
		"home/deploy/go/bin/artex": bin, "opt/artex/bin/artex": bin, "tmp/x": bin,
		"usr/local/bin/artex": []byte("#!/bin/sh\necho not the tool\n")} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	scan := Host(context.Background(), root, nil)
	got := map[string]string{}
	for _, f := range scan.Found {
		if f.Category == model.ConfigAttackTool {
			got[f.Path] = f.Rule
		}
	}
	want := map[string]string{"/app/artex": RuleAttackToolArtex, "/opt/tools/console": RuleAttackToolArtex,
		"/home/deploy/ARTEX/go.mod": RuleAttackToolArtex, "/home/deploy/go/bin/artex": RuleAttackToolArtex,
		"/opt/artex/bin/artex": RuleAttackToolArtex, "/tmp/x": RuleAttackToolArtex}
	if len(got) != len(want) {
		t.Fatalf("attack tool findings = %v, want %v", got, want)
	}
	for p, r := range want {
		if got[p] != r {
			t.Errorf("%s: rule %q, want %q", p, got[p], r)
		}
	}
}

// A walk cut short by its limits is not complete, so nothing found before
// is resolved as gone.
func TestHostAttackToolsCapped(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"})
	dir := filepath.Join(root, "usr", "local", "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= maxAttackToolExec; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("tool%04d", i)), []byte("\x7fELF not really"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	scan := Host(context.Background(), root, nil)
	if scan.Complete || !strings.Contains(scan.Reason, "attack tools") {
		t.Errorf("capped walk: complete=%v reason=%q", scan.Complete, scan.Reason)
	}
}

func TestWithoutCategory(t *testing.T) {
	s := &model.ConfigScan{Found: append(ImageAttackTools("tomicdd/artex"), model.ConfigFinding{Rule: "x", Category: model.ConfigSSH})}
	s.WithoutCategory(model.ConfigAttackTool)
	if len(s.Found) != 1 || s.Found[0].Category != model.ConfigSSH {
		t.Errorf("found = %+v", s.Found)
	}
	var none *model.ConfigScan
	none.WithoutCategory(model.ConfigAttackTool) // no panic
}
