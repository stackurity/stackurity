package leaks

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func write(t *testing.T, root, rel, data string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDir(t *testing.T) {
	root := t.TempDir()
	write(t, root, "app/billing.py", "KEY = '"+stripeKey+"'\n")
	write(t, root, "node_modules/lib/x.js", ghToken)
	write(t, root, "third_party/aws/config/x.php", ghToken)
	write(t, root, "app/billing_test.py", ghToken)
	write(t, root, "logo.png", ghToken)
	write(t, root, "blob.bin", "\x00"+ghToken)
	if err := os.Symlink("/etc", filepath.Join(root, "etc")); err != nil {
		t.Fatal(err)
	}
	res := Dir(context.Background(), root, Options{})
	if !res.Complete || len(res.Leaks) != 1 || res.Leaks[0].Path != "app/billing.py" {
		t.Fatalf("got %+v", res)
	}
}

func TestDirSkip(t *testing.T) {
	root := t.TempDir()
	write(t, root, "site/.env", "STRIPE="+stripeKey+"\n")
	write(t, root, "site/phpmyadmin/config.inc.php", ghToken)
	res := Dir(context.Background(), root, Options{Skip: func(rel string) bool { return rel == "site/phpmyadmin" }})
	if len(res.Leaks) != 1 || res.Leaks[0].Path != "site/.env" {
		t.Fatalf("got %+v", res.Leaks)
	}
}

// In a Git checkout only tracked files are read: an ignored .env is the
// developer's, not the repository's.
func TestRepoTrackedOnly(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	write(t, root, ".gitignore", ".env\n")
	write(t, root, ".env", "STRIPE="+stripeKey+"\n")
	write(t, root, "src/app.js", "const t = '"+ghToken+"';\n")
	write(t, root, "untracked.js", "const t = '"+ghToken+"';\n")
	for _, args := range [][]string{{"init", "-q"}, {"add", ".gitignore", "src/app.js"}} {
		cmd := exec.Command(git, append([]string{"-C", root}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	res := Repo(context.Background(), root)
	if !res.Complete || len(res.Leaks) != 1 || res.Leaks[0].Path != "src/app.js" {
		t.Fatalf("got %+v", res)
	}
	// Not a checkout: everything is read.
	if err := os.RemoveAll(filepath.Join(root, ".git")); err != nil {
		t.Fatal(err)
	}
	if res := Repo(context.Background(), root); len(res.Leaks) != 3 {
		t.Fatalf("without git: got %+v", res.Leaks)
	}
}

// A checkout's own configuration must not run a program when it is
// scanned: core.fsmonitor names one that git ls-files would start.
func TestRepoRunsNothing(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	ran := filepath.Join(t.TempDir(), "ran")
	write(t, root, "a.js", "x")
	write(t, root, "monitor.sh", "#!/bin/sh\ntouch "+ran+"\n")
	if err := os.Chmod(filepath.Join(root, "monitor.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "a.js"}, {"config", "core.fsmonitor", filepath.Join(root, "monitor.sh")}} {
		if out, err := exec.Command(git, append([]string{"-C", root}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	Repo(context.Background(), root)
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("the checkout's core.fsmonitor program ran")
	}
}
