package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

// stackurity scan inside a Git checkout records its origin remote,
// normalised and without the token a clone URL can carry, and keeps the
// directory name as an identity so a repository scanned before by name
// keeps its asset.
func TestScanRecordsGitRemote(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := filepath.Join(t.TempDir(), "commmerce_chat")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x.io", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x.io")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	git("init", "-q")
	git("remote", "add", "origin", "https://x-access-token:"+testToken+"@github.com/Acme/commmerce_chat.git")
	if err := os.WriteFile(filepath.Join(dir, "pubspec.yaml"), []byte("name: commmerce_chat\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "pubspec.yaml")
	git("commit", "-q", "-m", "x")

	scan := func(args ...string) model.ObservationBatch {
		t.Helper()
		out := filepath.Join(t.TempDir(), "batch.json")
		if _, err := runScan(t, append([]string{dir, "--no-packs", "--no-leaks", "--output", out}, args...)...); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), testToken) || strings.Contains(string(data), "x-access-token") {
			t.Fatal("the batch holds the remote's credentials")
		}
		var b model.ObservationBatch
		if err := json.Unmarshal(data, &b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	b := scan()
	want := []model.Identifier{{Scheme: "name:repository", Value: "commmerce_chat"}, {Scheme: "git-url", Value: "https://github.com/Acme/commmerce_chat"}}
	if len(b.Asset.Identifiers) != 2 || b.Asset.Identifiers[0] != want[0] || b.Asset.Identifiers[1] != want[1] {
		t.Errorf("identifiers %v", b.Asset.Identifiers)
	}
	a := b.Asset.Attributes
	if a["git_url"] != "https://github.com/Acme/commmerce_chat" || len(a["git_commit"]) != 40 || a["package_names"] != "pub:commmerce_chat" {
		t.Errorf("attributes %v", a)
	}

	// --git-url still decides the identity on its own, as CI uses it.
	b = scan("--git-url", "https://github.com/acme/other.git")
	if len(b.Asset.Identifiers) != 1 || b.Asset.Identifiers[0].Value != "https://github.com/acme/other" || b.Asset.Attributes["git_url"] != "https://github.com/acme/other" {
		t.Errorf("with --git-url: %v %v", b.Asset.Identifiers, b.Asset.Attributes)
	}

	// One project inside the checkout (a monorepo's) records the remote,
	// but is not identified by it: its sibling projects stay apart.
	sub := filepath.Join(dir, "web")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	subOut := filepath.Join(t.TempDir(), "batch.json")
	if _, err := runScan(t, sub, "--no-packs", "--no-leaks", "--output", subOut); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(subOut)
	var sb model.ObservationBatch
	if err := json.Unmarshal(data, &sb); err != nil || len(sb.Asset.Identifiers) != 1 || sb.Asset.Identifiers[0].Value != "web" ||
		sb.Asset.Attributes["git_url"] != "https://github.com/Acme/commmerce_chat" {
		t.Errorf("subdirectory: %v %v (%v)", sb.Asset.Identifiers, sb.Asset.Attributes, err)
	}

	// Outside a checkout: the name, as before.
	plain := t.TempDir()
	out := filepath.Join(t.TempDir(), "batch.json")
	if _, err := runScan(t, plain, "--no-packs", "--no-leaks", "--output", out); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(out)
	var p model.ObservationBatch
	if err := json.Unmarshal(data, &p); err != nil || len(p.Asset.Identifiers) != 1 || p.Asset.Identifiers[0].Scheme != "name:repository" || p.Asset.Attributes["git_url"] != "" {
		t.Errorf("plain directory: %v %v (%v)", p.Asset.Identifiers, p.Asset.Attributes, err)
	}
}
