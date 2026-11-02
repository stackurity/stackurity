// Command release does the file changes of a release in one step, checks
// them the way CI and the release workflow will, and opens the pull request.
// See RELEASING.md.
//
//	go run ./tools/release prepare v0.15.0   # release PR: CHANGELOG, charts, server.json, docs, upgrade matrix
//	go run ./tools/release next v0.15.0      # after the tag is published: add it to the upgrade matrix
//
// prepare, from a clean checkout:
//
//  1. fetches origin and creates the branch release-X.Y.Z from origin/main;
//  2. renames CHANGELOG.md's "## Unreleased" to "## X.Y.Z" and puts a fresh,
//     empty "## Unreleased" above it;
//  3. sets version and appVersion in both Helm charts, the version in
//     server.json, and every image and chart reference in README.md,
//     docs/install.md and docs/kubernetes.md;
//  4. adds the previous release to the release-checks upgrade matrix if it
//     is not there yet;
//  5. runs tools/changelog and the releaselint and docslint tests with
//     STACKURITY_RELEASE_TAG set, as the release workflow does;
//  6. commits, pushes and opens the pull request with gh. Its body lists the
//     notes' entries and the migrations added since the previous tag.
//
// Flags: -dry-run only prints what would change; -no-pr stops after the
// commit; -base picks another starting point than origin/main.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  go run ./tools/release prepare [-dry-run] [-no-pr] [-base origin/main] vX.Y.Z
  go run ./tools/release next [-dry-run] [-no-pr] vX.Y.Z
See RELEASING.md.
`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dry := fs.Bool("dry-run", false, "print what would change; touch nothing")
	noPR := fs.Bool("no-pr", false, "commit on the new branch but do not push or open a pull request")
	base := fs.String("base", "origin/main", "commit to branch from")
	skipChecks := fs.Bool("skip-checks", false, "do not run the changelog, releaselint and docslint checks (CI still runs them)")
	_ = fs.Parse(os.Args[2:])
	if fs.NArg() != 1 {
		usage()
	}
	v, err := parseVersion(fs.Arg(0))
	if err != nil {
		fail(err)
	}
	r := &run{dry: *dry, noPR: *noPR, base: *base, skipChecks: *skipChecks}
	switch cmd {
	case "prepare":
		err = r.prepare(v)
	case "next":
		err = r.next(v)
	default:
		usage()
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "release:", err)
	os.Exit(1)
}

type run struct {
	dry, noPR, skipChecks bool
	quiet                 bool // tests: do not print each file
	base                  string
	changed               []string // files written
}

// Files a release changes, relative to the repository root.
const (
	changelogFile = "CHANGELOG.md"
	serverJSON    = "server.json"
	matrixFile    = ".github/workflows/release-checks.yml"
)

var (
	chartFiles = []string{"deploy/helm/stackurity/Chart.yaml", "deploy/helm/stackurity-reporter/Chart.yaml"}
	docFiles   = []string{"README.md", "docs/install.md", "docs/kubernetes.md"}
)

func (r *run) prepare(v version) error {
	if err := r.start("release-" + v.String()); err != nil {
		return err
	}
	cl, err := os.ReadFile(changelogFile)
	if err != nil {
		return err
	}
	prev, err := latestReleased(string(cl))
	if err != nil {
		return err
	}
	if !prev.less(v) {
		return fmt.Errorf("%s is not newer than the newest release in CHANGELOG.md, %s", v, prev)
	}
	newCL, err := releaseChangelog(string(cl), v)
	if err != nil {
		return err
	}
	r.write(changelogFile, newCL, fmt.Sprintf("Unreleased -> %s, fresh empty Unreleased above it", v))

	for _, f := range chartFiles {
		if err := r.edit(f, func(s string) (string, string, error) {
			out, err := setChartVersion(s, v)
			return out, "version and appVersion " + v.String(), err
		}); err != nil {
			return err
		}
	}
	if err := r.edit(serverJSON, func(s string) (string, string, error) {
		out, err := setServerJSONVersion(s, v)
		return out, "version " + v.String(), err
	}); err != nil {
		return err
	}
	for _, f := range docFiles {
		if err := r.edit(f, func(s string) (string, string, error) {
			out, n := setDocVersions(s, v)
			return out, fmt.Sprintf("%d image/chart references -> %s", n, v), nil
		}); err != nil {
			return err
		}
	}
	if err := r.edit(matrixFile, func(s string) (string, string, error) {
		out, added, err := addUpgradeSource(s, prev)
		if !added {
			return out, "", err
		}
		return out, "upgrade matrix gains " + prev.String(), err
	}); err != nil {
		return err
	}
	if r.dry {
		fmt.Println("dry run: nothing written")
		return nil
	}
	if err := r.checks(v); err != nil {
		return err
	}
	notes, err := output("go", "run", "./tools/changelog", "-version", "v"+v.String())
	if err != nil {
		return err
	}
	migrations, _ := output("git", "diff", "--name-only", "--diff-filter=A", "v"+prev.String()+"..HEAD", "--", "internal/db/migrations")
	body := prBody(v, prev, notes, strings.Fields(migrations), r.changed)
	msg := fmt.Sprintf("Release %s\n\nCHANGELOG Unreleased -> %s (fresh Unreleased above it); both charts,\nserver.json and the install docs name %s; upgrade matrix includes %s.\nMade with go run ./tools/release prepare v%s.\n", v, v, v, prev, v)
	return r.finish("Release "+v.String(), msg, body)
}

// next adds a published release to the upgrade matrix, so the next
// release's checks upgrade from it. Run it once the tag's release workflow
// has published the image.
func (r *run) next(v version) error {
	if !r.dry {
		if _, err := output("gh", "release", "view", "v"+v.String(), "--json", "tagName"); err != nil {
			return fmt.Errorf("v%s is not published yet (gh release view failed); wait for the release workflow: %w", v, err)
		}
	}
	if err := r.start("release-checks-" + v.String()); err != nil {
		return err
	}
	added := false
	if err := r.edit(matrixFile, func(s string) (string, string, error) {
		out, a, err := addUpgradeSource(s, v)
		added = a
		if !a {
			return out, "", err
		}
		return out, "upgrade matrix gains " + v.String(), err
	}); err != nil {
		return err
	}
	if !added {
		fmt.Printf("%s is already in the upgrade matrix; nothing to do\n", v)
		return nil
	}
	if r.dry {
		fmt.Println("dry run: nothing written")
		return nil
	}
	if !r.skipChecks {
		if err := runCmd(nil, "go", "test", "-count=1", "./tools/releaselint"); err != nil {
			return err
		}
	}
	body := fmt.Sprintf("Adds %s, now published, to the release-checks upgrade matrix, so every later release is tested as an upgrade from it (releaselint requires it once a change lands under Unreleased).\n\nMade with `go run ./tools/release next v%s`.\n", v, v)
	return r.finish("release-checks: upgrade from "+v.String(), "release-checks: upgrade from "+v.String()+"\n", body)
}

// start checks the checkout and creates the branch.
func (r *run) start(branch string) error {
	if _, err := os.Stat(changelogFile); err != nil {
		return errors.New("run from the repository root (CHANGELOG.md not found)")
	}
	if r.dry {
		fmt.Printf("dry run: would create branch %s from %s\n", branch, r.base)
		return nil
	}
	if st, err := output("git", "status", "--porcelain", "--untracked-files=no"); err != nil {
		return err
	} else if strings.TrimSpace(st) != "" {
		return fmt.Errorf("the checkout has uncommitted changes; commit or stash them first:\n%s", st)
	}
	if remote, _, ok := strings.Cut(r.base, "/"); ok {
		if err := runCmd(nil, "git", "fetch", "--tags", "--quiet", remote); err != nil {
			return err
		}
	}
	return runCmd(nil, "git", "switch", "-c", branch, r.base)
}

// edit applies change to a file and writes it if it changed.
func (r *run) edit(path string, change func(string) (out, what string, err error)) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out, what, err := change(string(b))
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if out == string(b) {
		return nil
	}
	r.write(path, out, what)
	return nil
}

func (r *run) write(path, content, what string) {
	if !r.quiet {
		fmt.Printf("%-45s %s\n", path, what)
	}
	if r.dry {
		return
	}
	info, err := os.Stat(path)
	mode := os.FileMode(0o644)
	if err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		fail(err)
	}
	r.changed = append(r.changed, path)
}

// checks runs what the release workflow runs before it publishes anything.
func (r *run) checks(v version) error {
	if r.skipChecks {
		fmt.Println("checks skipped (-skip-checks); CI runs them on the pull request")
		return nil
	}
	fmt.Println("checking: tools/changelog, releaselint and docslint with STACKURITY_RELEASE_TAG=v" + v.String())
	if err := runCmd(nil, "go", "run", "./tools/changelog", "-check"); err != nil {
		return err
	}
	if _, err := output("go", "run", "./tools/changelog", "-version", "v"+v.String()); err != nil {
		return err
	}
	env := append(os.Environ(), "STACKURITY_RELEASE_TAG=v"+v.String())
	return runCmd(env, "go", "test", "-count=1", "./tools/releaselint", "./tools/docslint")
}

// finish commits the changed files, then pushes and opens the pull request.
func (r *run) finish(title, msg, body string) error {
	args := append([]string{"add", "--"}, r.changed...)
	if err := runCmd(nil, "git", args...); err != nil {
		return err
	}
	if err := runCmd(nil, "git", "commit", "-q", "-m", msg); err != nil {
		return err
	}
	if r.noPR {
		fmt.Println("committed; -no-pr: push and open the pull request yourself. PR body:\n\n" + body)
		return nil
	}
	branch, err := output("git", "branch", "--show-current")
	if err != nil {
		return err
	}
	if err := runCmd(nil, "git", "push", "-q", "-u", "origin", strings.TrimSpace(branch)); err != nil {
		return err
	}
	f := filepath.Join(os.TempDir(), "release-pr-body.md")
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		return err
	}
	defer os.Remove(f)
	return runCmd(nil, "gh", "pr", "create", "--base", "main", "--title", title, "--body-file", f)
}

func prBody(v, prev version, notes string, migrations, files []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Release %s (previous: %s).\n\n", v, prev)
	b.WriteString(releaseNotesSummary(notes))
	b.WriteString("\n\n**Migrations since v" + prev.String() + "**\n\n")
	if len(migrations) == 0 {
		b.WriteString("None: rolling back is the previous image on the same database.\n")
	} else {
		for _, m := range migrations {
			fmt.Fprintf(&b, "- `%s`\n", strings.TrimPrefix(m, "internal/db/migrations/"))
		}
		b.WriteString("\nThe previous release refuses the migrated database: rolling back means restoring the pre-release dump.\n")
	}
	b.WriteString("\n**Files**\n\n")
	for _, f := range files {
		fmt.Fprintf(&b, "- `%s`\n", f)
	}
	fmt.Fprintf(&b, `
Made with `+"`go run ./tools/release prepare v%s`"+`; tools/changelog, releaselint and docslint passed locally with STACKURITY_RELEASE_TAG=v%s.

**Gates before tagging** (RELEASING.md)

- [ ] CI green on this pull request
- [ ] Licensed edition: last night's rehearsal passed for the main commit this branches from, or a rehearsal of this commit
- [ ] Merge, tag v%s on the merge commit, tag the matching stackurity-pro commit
- [ ] After the release is published: `+"`go run ./tools/release next v%s`"+`
`, v, v, v, v)
	return b.String()
}

func runCmd(env []string, name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdout, c.Stderr, c.Env = os.Stdout, os.Stderr, env
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func output(name string, args ...string) (string, error) {
	var out, errb bytes.Buffer
	c := exec.Command(name, args...)
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}
