package gitlab

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidPathAndCloneURL(t *testing.T) {
	c := &Client{Base: "https://gitlab.example.com"}
	for _, p := range []string{"acme/shop", "acme/backend/api", "a_b/c.d-e", "Acme/Shop"} {
		if !ValidPath(p) {
			t.Errorf("%q refused", p)
		}
		if u, err := c.CloneURL(p); err != nil || u != "https://gitlab.example.com/"+p+".git" {
			t.Errorf("%q: %q %v", p, u, err)
		}
	}
	for _, p := range []string{"", "acme", "/acme/shop", "acme/shop/", "acme//shop", "acme/../x", "acme/./x", "acme/.x", "acme/-x",
		"acme/x.git", "acme/x.atom", "acme/x?private_token=1", "acme/x#y", "acme/x y", "acme/x@evil.com", "acme\\x", "acme/%2e%2e",
		"https://evil.example/x", strings.Repeat("a/", 22) + "a", "acme/" + strings.Repeat("x", 300)} {
		if _, err := c.CloneURL(p); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
	if !InGroup("acme/shop", "acme") || !InGroup("Acme/backend/api", "acme") || InGroup("acmex/shop", "acme") || InGroup("acme", "acme") ||
		InGroup("other/acme/shop", "acme") {
		t.Fatal("InGroup")
	}
}

func TestParseBase(t *testing.T) {
	for in, want := range map[string]string{"": "https://gitlab.com", "https://GitLab.Example.com/": "https://gitlab.example.com",
		"https://example.com/gitlab/": "https://example.com/gitlab"} {
		if got, err := ParseBase(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"http://gitlab.example.com", "https://u:p@gitlab.example.com", "https://gitlab.example.com/?x=1", "gitlab.example.com"} {
		if _, err := ParseBase(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestHasScopes(t *testing.T) {
	tk := &Token{Scope: "read_repository read_api"}
	if !tk.HasScopes(ReadScopes) || tk.HasScopes(SetupScopes) {
		t.Fatal("read scopes")
	}
	if (&Token{Scope: "read_api read_repository api"}).HasScopes(ReadScopes) {
		t.Fatal("a token with more scopes than asked was accepted")
	}
}

func TestPushEvent(t *testing.T) {
	var p PushEvent
	_ = json.Unmarshal([]byte(`{"ref":"refs/heads/main","after":"abc","project":{"id":1,"default_branch":"main"},"total_commits_count":1,
		"commits":[{"added":[],"removed":[],"modified":["docs/README.md"]}]}`), &p)
	if !p.ToDefaultBranch("") || p.TouchesInventory(nil) {
		t.Fatal("README push")
	}
	p.Commits[0].Modified = []string{"web/package-lock.json"}
	if !p.TouchesInventory(nil) {
		t.Fatal("lockfile push")
	}
	p.Commits[0].Modified = []string{"README.md"}
	p.TotalCommits = 21
	if !p.TouchesInventory(nil) {
		t.Fatal("a push with unlisted commits counts as changing lockfiles")
	}
	p.After = zeroSHA
	if p.ToDefaultBranch("") {
		t.Fatal("a deleted branch")
	}
}
