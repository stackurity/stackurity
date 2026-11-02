package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const changelog = "# Changelog\n\nIntro naming `## Unreleased`.\n\n## Unreleased\n\n### Added\n\n- **New thing.** Detail.\n\n" +
	"```\n## 9.9.9\n```\n\n## 0.14.0\n\n### Fixed\n\n- **Old fix.**\n"

func TestReleaseChangelog(t *testing.T) {
	v, _ := parseVersion("v0.15.0")
	got, err := releaseChangelog(changelog, v)
	if err != nil {
		t.Fatal(err)
	}
	want := "# Changelog\n\nIntro naming `## Unreleased`.\n\n## Unreleased\n\n## 0.15.0\n\n### Added\n\n- **New thing.** Detail.\n\n" +
		"```\n## 9.9.9\n```\n\n## 0.14.0\n\n### Fixed\n\n- **Old fix.**\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	// Releasing the result again: its Unreleased is empty.
	if _, err := releaseChangelog(got, version{0, 16, 0}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty Unreleased: %v", err)
	}
	if p, err := latestReleased(got); err != nil || p != v {
		t.Errorf("latestReleased = %v, %v", p, err)
	}
}

func TestReleaseChangelogRefuses(t *testing.T) {
	cases := map[string]struct {
		doc, version, want string
	}{
		"no unreleased":   {"## 0.14.0\n\n- a\n", "0.15.0", "no \"## Unreleased\""},
		"two unreleased":  {"## Unreleased\n- a\n## Unreleased\n- b\n## 0.14.0\n- c\n", "0.15.0", "two"},
		"not newer":       {changelog, "0.14.0", "already has"},
		"older":           {changelog, "0.13.9", "not newer"},
		"version first":   {"## 0.14.0\n- a\n## Unreleased\n- b\n", "0.15.0", "must be the first"},
		"whitespace only": {"## Unreleased\n\n  \n## 0.14.0\n- a\n", "0.15.0", "empty"},
	}
	for name, c := range cases {
		v, err := parseVersion(c.version)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := releaseChangelog(c.doc, v); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want it to mention %q", name, err, c.want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	for _, bad := range []string{"0.15", "v0.15.0-rc.1", "main", ""} {
		if _, err := parseVersion(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if v, err := parseVersion("v1.2.3"); err != nil || v.String() != "1.2.3" {
		t.Errorf("v1.2.3 -> %v %v", v, err)
	}
	if !(version{0, 9, 9}).less(version{0, 10, 0}) || (version{0, 10, 0}).less(version{0, 9, 9}) {
		t.Error("less compares numerically")
	}
}

func TestSetChartVersion(t *testing.T) {
	chart := "apiVersion: v2\nname: stackurity\nversion: 0.14.0\nappVersion: \"0.14.0\"\ndependencies:\n  - name: x\n    version: 1.0.0\n"
	got, err := setChartVersion(chart, version{0, 15, 0})
	if err != nil {
		t.Fatal(err)
	}
	want := "apiVersion: v2\nname: stackurity\nversion: 0.15.0\nappVersion: \"0.15.0\"\ndependencies:\n  - name: x\n    version: 1.0.0\n"
	if got != want {
		t.Errorf("got:\n%s", got)
	}
	if _, err := setChartVersion("name: x\n", version{0, 15, 0}); err == nil {
		t.Error("chart without version accepted")
	}
}

func TestSetServerJSONVersion(t *testing.T) {
	doc := "{\n  \"name\": \"x\",\n  \"version\": \"0.14.0\",\n  \"packages\": [{\"version\": \"1.0.0\"}]\n}\n"
	got, err := setServerJSONVersion(doc, version{0, 15, 0})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"version": "0.15.0"`) || !strings.Contains(got, `{"version": "1.0.0"}`) {
		t.Errorf("got:\n%s", got)
	}
}

func TestSetDocVersions(t *testing.T) {
	doc := "STACKURITY_IMAGE=ghcr.io/stackurity/stackurity:0.14.0 and stackurity/stackurity:0.14.0\n" +
		"helm install x oci://ghcr.io/stackurity/charts/stackurity --version 0.14.0\n" +
		"cosign verify ghcr.io/stackurity/charts/stackurity-reporter:0.13.9\n" +
		"upgrade.sh ghcr.io/stackurity/stackurity:0.14.0 stackurity:mybuild\n" +
		"unrelated: postgres:17.11 and stackurity-ee:v0.14.0\n"
	got, n := setDocVersions(doc, version{0, 15, 0})
	if n != 5 {
		t.Errorf("changed %d references, want 5", n)
	}
	if strings.Contains(got, "stackurity/stackurity:0.14.0") || strings.Contains(got, "reporter:0.13.9") || strings.Contains(got, "--version 0.14.0") {
		t.Errorf("left an old reference:\n%s", got)
	}
	if !strings.Contains(got, "postgres:17.11") || !strings.Contains(got, "stackurity-ee:v0.14.0") {
		t.Errorf("changed an unrelated reference:\n%s", got)
	}
	if _, n := setDocVersions(got, version{0, 15, 0}); n != 0 {
		t.Errorf("second run changed %d", n)
	}
}

func TestAddUpgradeSource(t *testing.T) {
	wf := "matrix:\n  from: [\"0.13.8\", \"0.13.9\"]\n"
	got, added, err := addUpgradeSource(wf, version{0, 14, 0})
	if err != nil || !added || got != "matrix:\n  from: [\"0.13.8\", \"0.13.9\", \"0.14.0\"]\n" {
		t.Errorf("got %q %v %v", got, added, err)
	}
	if again, added, _ := addUpgradeSource(got, version{0, 14, 0}); added || again != got {
		t.Error("added twice")
	}
	if _, _, err := addUpgradeSource("matrix: {}\n", version{0, 14, 0}); err == nil {
		t.Error("workflow without a matrix accepted")
	}
}

func TestReleaseNotesSummary(t *testing.T) {
	notes := "### Security\n\n- **A fix.** Long text.\n\n### Added\n\n- **Feature one.** Text.\n- Plain entry.\n"
	want := "**Security**\n\n- A fix.\n\n**Added**\n\n- Feature one.\n- Plain entry."
	if got := releaseNotesSummary(notes); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// The edits applied to the repository's own files leave them as releaselint
// wants them: run prepare's edits on a copy and the lint tests against it.
func TestPrepareOnRepositoryCopy(t *testing.T) {
	if testing.Short() {
		t.Skip("copies the repository's release files and runs go test")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	cl := read(changelogFile)
	prev, err := latestReleased(cl)
	if err != nil {
		t.Fatal(err)
	}
	next := version{prev.major, prev.minor + 1, 0}
	// A changelog with something to release, as main has between releases.
	if !hasEntries(cl) {
		cl = strings.Replace(cl, "## "+prev.String(), "## Unreleased\n\n### Fixed\n\n- **Test entry.**\n\n## "+prev.String(), 1)
	}
	dir := t.TempDir()
	files := append([]string{changelogFile, serverJSON, matrixFile, "go.mod", "go.sum"}, append(chartFiles, docFiles...)...)
	for _, f := range files {
		content := read(f)
		if f == changelogFile {
			content = cl
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The lint test files themselves, run against the copy.
	lint, _ := filepath.Glob(filepath.Join(root, "tools", "releaselint", "*_test.go"))
	if err := os.MkdirAll(filepath.Join(dir, "tools", "releaselint"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range append(lint, filepath.Join(root, "tools", "releaselint", "doc.go")) {
		if strings.HasSuffix(f, "packs_test.go") {
			continue // needs internal/packs; not touched by a release
		}
		b, _ := os.ReadFile(f)
		if err := os.WriteFile(filepath.Join(dir, "tools", "releaselint", filepath.Base(f)), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	wd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)
	r := &run{quiet: true}
	edits := []struct {
		path string
		fn   func(string) (string, string, error)
	}{
		{changelogFile, func(s string) (string, string, error) { o, err := releaseChangelog(s, next); return o, "", err }},
		{serverJSON, func(s string) (string, string, error) { o, err := setServerJSONVersion(s, next); return o, "", err }},
		{matrixFile, func(s string) (string, string, error) { o, _, err := addUpgradeSource(s, prev); return o, "", err }},
	}
	for _, f := range chartFiles {
		edits = append(edits, struct {
			path string
			fn   func(string) (string, string, error)
		}{f, func(s string) (string, string, error) { o, err := setChartVersion(s, next); return o, "", err }})
	}
	for _, f := range docFiles {
		edits = append(edits, struct {
			path string
			fn   func(string) (string, string, error)
		}{f, func(s string) (string, string, error) { o, _ := setDocVersions(s, next); return o, "", nil }})
	}
	for _, e := range edits {
		if err := r.edit(e.path, e.fn); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "test", "-count=1", "./tools/releaselint")
	cmd.Env = append(os.Environ(), "STACKURITY_RELEASE_TAG=v"+next.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("releaselint on the prepared copy (v%s):\n%s", next, out)
	}
}

func hasEntries(cl string) bool {
	_, after, ok := strings.Cut(cl, "\n## Unreleased\n")
	if !ok {
		return false
	}
	body, _, _ := strings.Cut(after, "\n## ")
	return strings.TrimSpace(body) != ""
}
