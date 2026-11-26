package main

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestProblem(t *testing.T) {
	after := Since.Add(time.Hour)
	for _, c := range []struct {
		name string
		c    Commit
		ok   bool
	}{
		{"signed", Commit{Email: "ana@example.com", Date: after, Message: "Fix\n\nSigned-off-by: Ana <ana@example.com>\n"}, true},
		{"signed, other case", Commit{Email: "Ana@Example.com", Date: after, Message: "Fix\n\nsigned-off-by: Ana <ana@example.com>"}, true},
		{"signed among trailers", Commit{Email: "a@x.io", Date: after, Message: "Fix\n\nSigned-off-by: A <a@x.io>\nCo-Authored-By: Claude <noreply@anthropic.com>"}, true},
		{"unsigned", Commit{Email: "a@x.io", Date: after, Message: "Fix"}, false},
		{"someone else's sign-off", Commit{Email: "a@x.io", Date: after, Message: "Fix\n\nSigned-off-by: B <b@x.io>"}, false},
		{"co-author is not a sign-off", Commit{Email: "a@x.io", Date: after, Message: "Fix\n\nCo-Authored-By: A <a@x.io>"}, false},
		{"before the check", Commit{Email: "a@x.io", Date: Since.Add(-time.Second), Message: "Fix"}, true},
		{"dependabot", Commit{Author: "dependabot[bot]", Email: "49699333+dependabot[bot]@users.noreply.github.com", Date: after, Message: "Bump"}, true},
	} {
		if got := Problem(c.c); (got == "") != c.ok {
			t.Errorf("%s: Problem = %q", c.name, got)
		}
	}
}

func TestParseGitLog(t *testing.T) {
	dir := t.TempDir()
	git := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(cmd.Environ(), "GIT_AUTHOR_NAME=Ana", "GIT_AUTHOR_EMAIL=ana@example.com", "GIT_COMMITTER_NAME=Ana",
			"GIT_COMMITTER_EMAIL=ana@example.com", "GIT_AUTHOR_DATE=2027-01-02T03:04:05Z", "GIT_COMMITTER_DATE=2027-01-02T03:04:05Z")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q", "-b", "main")
	git("commit", "-q", "--allow-empty", "-m", "base")
	base := git("rev-parse", "HEAD")
	git("commit", "-q", "--allow-empty", "-s", "-m", "signed\n\nbody line")
	git("commit", "-q", "--allow-empty", "-m", "unsigned")
	out := git("log", "--no-merges", "--format=%H%x1f%an%x1f%ae%x1f%aI%x1f%s%x1f%B%x1e", base+"..HEAD")
	cs, err := parse([]byte(out))
	if err != nil || len(cs) != 2 {
		t.Fatalf("parse: %v %d", err, len(cs))
	}
	if cs[0].Subject != "unsigned" || Problem(cs[0]) == "" {
		t.Errorf("unsigned commit passed: %+v", cs[0])
	}
	if cs[1].Subject != "signed" || Problem(cs[1]) != "" {
		t.Errorf("signed commit failed: %+v %q", cs[1], Problem(cs[1]))
	}
}
