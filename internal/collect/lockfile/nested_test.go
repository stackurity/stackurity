package lockfile

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

// A repository with coding-agent worktrees (.claude/worktrees/*), a nested
// clone and a nested worktree elsewhere counted the same lockfiles once per
// checkout. Only the repository's own lockfiles (and its submodules') are
// scanned; each nested checkout is reported once as skipped; paths git
// ignores are left out when git is available.
func TestSkipsNestedCheckouts(t *testing.T) {
	root := t.TempDir()
	write := func(rel, data string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package-lock.json", npmV3Lock)
	write("api/composer.lock", composerLockJSON)
	// Coding-agent worktrees: a .git file pointing into this repository.
	for _, wt := range []string{"a", "b", "c"} {
		write(".claude/worktrees/"+wt+"/.git", "gitdir: "+root+"/.git/worktrees/"+wt+"\n")
		write(".claude/worktrees/"+wt+"/package-lock.json", npmV3Lock)
		write(".claude/worktrees/"+wt+"/api/composer.lock", composerLockJSON)
	}
	// A clone checked out inside the repository, and a worktree outside .claude.
	write("tools/other/.git/HEAD", "ref: refs/heads/main\n")
	write("tools/other/package-lock.json", npmV1Lock)
	write("wt/feature/.git", "gitdir: /elsewhere/repo/.git/worktrees/feature\n")
	write("wt/feature/package-lock.json", npmV1Lock)
	// A submodule is part of the checkout.
	write("libs/ui/.git", "gitdir: ../../.git/modules/libs/ui\n")
	write("libs/ui/package-lock.json", npmV1Lock)

	_, git := exec.LookPath("git")
	if git == nil {
		for _, args := range [][]string{{"init", "-q"}, {"config", "user.email", "t@example.com"}, {"config", "user.name", "t"}} {
			if out, err := exec.Command("git", append([]string{"-C", root}, args...)...).CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v %s", args, err, out)
			}
		}
		write(".gitignore", "build/\n*.generated.lock.json\n")
		write("build/package-lock.json", npmV1Lock)
	}

	b, err := ScanDirWith(context.Background(), root, model.AssetRef{Kind: model.AssetRepository, Name: "r",
		Identifiers: []model.Identifier{{Scheme: "test", Value: "r"}}}, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	locs := map[string]int{}
	for _, o := range b.Observations {
		locs[o.Location]++
	}
	var paths []string
	for p := range locs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if got := strings.Join(paths, ","); got != "api/composer.lock,libs/ui/package-lock.json,package-lock.json" {
		t.Errorf("lockfiles scanned: %s", got)
	}
	var nested []string
	ignored := 0
	for _, c := range b.Coverage {
		switch {
		case strings.HasPrefix(c.Scope, "nested-checkout:"):
			if c.Status != "skipped" || !strings.HasPrefix(c.Reason, "nested checkout") {
				t.Errorf("coverage %+v", c)
			}
			nested = append(nested, strings.TrimPrefix(c.Scope, "nested-checkout:"))
		case c.Scope == "gitignored":
			ignored++
		}
	}
	sort.Strings(nested)
	if got := strings.Join(nested, ","); got != ".claude/worktrees/a,.claude/worktrees/b,.claude/worktrees/c,tools/other,wt/feature" {
		t.Errorf("nested checkouts reported: %s", got)
	}
	if git == nil && ignored != 1 {
		t.Errorf("git-ignored paths: %d coverage items, want 1: %+v", ignored, b.Coverage)
	}
	if !b.Complete {
		t.Errorf("skipping other checkouts must not make the scan incomplete: %+v", b.Coverage)
	}
	if err := b.Validate(); err != nil {
		t.Error(err)
	}
}
