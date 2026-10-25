package gitrepo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestValidate(t *testing.T) {
	for _, bad := range []string{"http://x/y", "ssh://git@x/y", "file:///etc", "https://user:pw@github.com/a/b", "ext::sh -c x"} {
		if (Config{URL: bad}).Validate() == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	if (Config{URL: "https://github.com/a/b", Ref: "--upload-pack=x"}).Validate() == nil {
		t.Error("option-like ref should be rejected")
	}
	if err := (Config{URL: "https://github.com/a/b.git", Ref: "main"}).Validate(); err != nil {
		t.Error(err)
	}
}

func TestNormalize(t *testing.T) {
	if got := NormalizeURL("https://GitHub.com/Acme/Shop.git/"); got != "https://github.com/Acme/Shop" {
		t.Errorf("got %q", got)
	}
	if got := RepoName("https://github.com/acme/shop.git"); got != "acme/shop" {
		t.Errorf("got %q", got)
	}
}

// TestCloneRejectsFileTransport makes sure the protocol allow-list holds
// even if validation is bypassed.
func TestCloneRejectsFileTransport(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	src := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = src
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
	}
	run("init", "-q")
	_ = os.WriteFile(filepath.Join(src, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"":{}}}`), 0o644)
	run("add", ".")
	run("commit", "-qm", "x")

	s := &Scanner{WorkDir: t.TempDir()}
	dest := filepath.Join(t.TempDir(), "src")
	err := s.clone(context.Background(), Config{URL: "file://" + src}, "", dest)
	if err == nil {
		t.Fatal("file:// clone must be blocked by protocol.allow")
	}
	if _, statErr := os.Stat(filepath.Join(dest, "package-lock.json")); statErr == nil {
		t.Fatal("file transport cloned content")
	}
}
