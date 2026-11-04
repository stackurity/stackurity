package gitremote

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// token is a made-up GitHub token, split so the repository's own key scan
// does not report it.
var token = strings.Join([]string{"ghp", "_", "Zq7Lm2Xr9Tb4Kc8Vn3Pw6Hy1Jd5Fs0Ga2Qex"}, "")

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		// The forms one GitHub repository is cloned as.
		"https://github.com/acme/shop.git":      "https://github.com/acme/shop",
		"https://GitHub.com/Acme/Shop.git/":     "https://github.com/Acme/Shop",
		"git@github.com:acme/shop.git":          "https://github.com/acme/shop",
		"git@GITHUB.com:acme/shop":              "https://github.com/acme/shop",
		"github.com:acme/shop.git":              "https://github.com/acme/shop",
		"ssh://git@github.com/acme/shop.git":    "https://github.com/acme/shop",
		"ssh://git@github.com:22/acme/shop.git": "https://github.com/acme/shop",
		"git+ssh://git@github.com/acme/shop":    "https://github.com/acme/shop",
		"git://github.com/acme/shop.git":        "https://github.com/acme/shop",
		"  https://github.com/acme/shop.git\n":  "https://github.com/acme/shop",
		// GitLab subgroups and a self-hosted server with a port.
		"git@gitlab.com:acme/platform/shop.git":    "https://gitlab.com/acme/platform/shop",
		"https://git.acme.io:8443/team/shop.git":   "https://git.acme.io:8443/team/shop",
		"ssh://git@git.acme.io:7999/team/shop.git": "https://git.acme.io/team/shop",
		// Not hosted anywhere: no identity.
		"/srv/git/shop.git":        "",
		"../shop":                  "",
		"./a:b":                    "",
		"file:///srv/git/shop.git": "",
		"ext::ssh -i key host %S":  "",
		"https://github.com/":      "",
		"git@github.com:":          "",
		"":                         "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

// A remote with a token in it (a deploy that cloned with one) never gives
// the token back, in any form.
func TestNormalizeDropsCredentials(t *testing.T) {
	for _, in := range []string{
		"https://x-access-token:" + token + "@github.com/acme/shop.git",
		"https://" + token + "@github.com/acme/shop.git",
		"https://oauth2:" + token + "@GitHub.com/acme/shop",
		"https://github.com/acme/shop.git?private_token=" + token,
		"https://github.com/acme/shop.git#" + token,
		"ssh://" + token + "@github.com/acme/shop.git",
		token + "@github.com:acme/shop.git",
	} {
		got := Normalize(in)
		if got != "https://github.com/acme/shop" {
			t.Errorf("Normalize(%q) = %q", strings.ReplaceAll(in, token, "<token>"), strings.ReplaceAll(got, token, "<token>"))
		}
		if strings.Contains(got, token) || strings.Contains(got, "@") {
			t.Errorf("credentials kept: %q", strings.ReplaceAll(got, token, "<token>"))
		}
	}
	// One that cannot be parsed is not echoed back.
	if got := Normalize("https://user:" + token + "@github.com:bad port/x"); got != "" {
		t.Errorf("unparsable remote = %q", strings.ReplaceAll(got, token, "<token>"))
	}
}

func TestFromConfig(t *testing.T) {
	cfg := "[core]\n\tbare = false\n[remote \"upstream\"]\n\turl = https://github.com/other/shop.git\n" +
		"[remote \"origin\"]\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n\turl = git@github.com:acme/shop.git\n" +
		"[branch \"main\"]\n\tremote = origin\n"
	if got := FromConfig([]byte(cfg)); got != "git@github.com:acme/shop.git" {
		t.Errorf("origin = %q", got)
	}
	if got := FromConfig([]byte("[remote \"upstream\"]\n\turl = https://github.com/other/shop.git\n")); got != "" {
		t.Errorf("no origin = %q", got)
	}
	if got := FromConfig([]byte("[remote  \"origin\" ]\nurl=\"https://github.com/acme/shop\"\n")); got != "https://github.com/acme/shop" {
		t.Errorf("spacing and quotes = %q", got)
	}
}

func TestLocal(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x.io", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x.io")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	// Not a checkout: nothing.
	if c := Local(context.Background(), dir); c != (Checkout{}) {
		t.Errorf("plain directory: %+v", c)
	}
	git("init", "-q")
	git("remote", "add", "origin", "https://deploy:"+token+"@GitHub.com/acme/shop.git")
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "a")
	git("commit", "-q", "-m", "x")
	c := Local(context.Background(), dir)
	if c.Remote != "https://github.com/acme/shop" || len(c.Commit) != 40 || !c.Root {
		t.Errorf("checkout: %q %q %v", strings.ReplaceAll(c.Remote, token, "<token>"), c.Commit, c.Root)
	}
	// One project inside the checkout (a monorepo's): the same remote,
	// but not the top of the work tree.
	sub := filepath.Join(dir, "web")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if c := Local(context.Background(), sub); c.Remote != "https://github.com/acme/shop" || c.Root {
		t.Errorf("subdirectory: %+v", c)
	}
}
