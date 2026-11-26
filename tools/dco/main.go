// Command dco checks that every commit of a pull request is signed off
// under the Developer Certificate of Origin (CONTRIBUTING.md, "Sign-off"):
// its message has a "Signed-off-by:" trailer with the author's email.
//
//	go run ./tools/dco origin/main HEAD
//
// Merge commits, bots' commits (dependabot and other GitHub Apps) and
// commits made before the check existed (Since) are skipped. Exits 1 and
// lists the commits to fix, with how to fix them, when any is not signed
// off.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Since is when sign-off became checked: commits authored before it were
// made under the old, unchecked rule and are not rewritten.
var Since = time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)

// Commit is what the check needs from one commit.
type Commit struct {
	Hash, Author, Email, Subject, Message string
	Date                                  time.Time
}

// Problem says why a commit fails, or "" when it passes or is skipped.
func Problem(c Commit) string {
	if c.Date.Before(Since) || isBot(c.Author, c.Email) {
		return ""
	}
	want := strings.ToLower(strings.TrimSpace(c.Email))
	var found []string
	sc := bufio.NewScanner(strings.NewReader(c.Message))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		k, v, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "Signed-off-by") {
			continue
		}
		v = strings.TrimSpace(v)
		found = append(found, v)
		if i, j := strings.LastIndex(v, "<"), strings.LastIndex(v, ">"); i >= 0 && j > i && strings.ToLower(strings.TrimSpace(v[i+1:j])) == want {
			return ""
		}
	}
	if len(found) == 0 {
		return "no Signed-off-by line"
	}
	return fmt.Sprintf("Signed-off-by (%s) does not match the author's email <%s>", strings.Join(found, "; "), c.Email)
}

func isBot(name, email string) bool {
	return strings.HasSuffix(name, "[bot]") || strings.Contains(email, "[bot]@users.noreply.github.com")
}

// fieldSep and recordSep separate fields and records in git log's output.
const fieldSep, recordSep = "\x1f", "\x1e"

// parse reads `git log --format=%H%x1f%an%x1f%ae%x1f%aI%x1f%s%x1f%B%x1e`.
func parse(out []byte) ([]Commit, error) {
	var cs []Commit
	for _, rec := range bytes.Split(out, []byte(recordSep)) {
		r := strings.TrimLeft(string(rec), "\n")
		if strings.TrimSpace(r) == "" {
			continue
		}
		f := strings.SplitN(r, fieldSep, 6)
		if len(f) != 6 {
			return nil, fmt.Errorf("unexpected git log record %q", r)
		}
		d, err := time.Parse(time.RFC3339, f[3])
		if err != nil {
			return nil, err
		}
		cs = append(cs, Commit{Hash: f[0], Author: f[1], Email: f[2], Date: d, Subject: f[4], Message: f[5]})
	}
	return cs, nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: dco BASE HEAD")
		os.Exit(2)
	}
	out, err := exec.Command("git", "log", "--no-merges", "--format=%H"+"%x1f%an%x1f%ae%x1f%aI%x1f%s%x1f%B%x1e", os.Args[1]+".."+os.Args[2]).Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "git log:", err)
		os.Exit(2)
	}
	cs, err := parse(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	bad := 0
	for _, c := range cs {
		if p := Problem(c); p != "" {
			bad++
			fmt.Printf("%.10s %s: %s\n", c.Hash, c.Subject, p)
		}
	}
	if bad > 0 {
		fmt.Printf("\n%d of %d commits are not signed off (Developer Certificate of Origin, CONTRIBUTING.md).\n", bad, len(cs))
		fmt.Println("Fix: git rebase --signoff " + os.Args[1] + " && git push --force-with-lease")
		fmt.Println("Next time: git commit -s")
		os.Exit(1)
	}
	fmt.Printf("%d commits checked: all signed off (or exempt).\n", len(cs))
}
