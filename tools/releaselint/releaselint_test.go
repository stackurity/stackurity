package releaselint

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", path))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// latest is the first released version heading in CHANGELOG.md ("## 0.4.0");
// an "Unreleased" heading is skipped.
func latest(t *testing.T) string {
	m := regexp.MustCompile(`(?m)^## (\d+\.\d+\.\d+)\s*$`).FindStringSubmatch(read(t, "CHANGELOG.md"))
	if m == nil {
		t.Fatal("CHANGELOG.md has no released version heading")
	}
	return m[1]
}

// TestVersionReferences fails when documentation or the chart names a
// version other than the newest release, so a release cannot ship docs that
// point at an older one. STACKURITY_RELEASE_TAG (set by the release workflow)
// must also match that release.
func TestVersionReferences(t *testing.T) {
	v := latest(t)
	if tag := os.Getenv("STACKURITY_RELEASE_TAG"); tag != "" {
		base, _, _ := strings.Cut(strings.TrimPrefix(tag, "v"), "-")
		if base != v {
			t.Errorf("tag %s does not match the newest CHANGELOG.md release %s", tag, v)
		}
	}
	chart := read(t, "deploy/helm/stackurity/Chart.yaml")
	for _, want := range []string{"version: " + v, `appVersion: "` + v + `"`} {
		if !strings.Contains(chart, want) {
			t.Errorf("deploy/helm/stackurity/Chart.yaml: want %q", want)
		}
	}
	// Image, chart and helm --version references in the install docs and README.
	ref := regexp.MustCompile(`(?:stackurity/stackurity:|charts/stackurity:|charts/stackurity --version )v?(\d+\.\d+\.\d+)`)
	for _, f := range []string{"README.md", "docs/install.md", "docs/kubernetes.md"} {
		for _, m := range ref.FindAllStringSubmatch(read(t, f), -1) {
			if m[1] != v {
				t.Errorf("%s: %q names %s, the newest release is %s", f, m[0], m[1], v)
			}
		}
	}
	// The README's status line carries no version, so it cannot go stale.
	if regexp.MustCompile(`(?m)^> \*\*Status:\*\*.*\bv?\d+\.\d+\b`).MatchString(read(t, "README.md")) {
		t.Error("README.md: the status line names a version; link to the latest release instead")
	}
}

// TestUpgradeMatrixHasOneSource: the supported upgrade sources are listed
// only in the release-checks workflow; prose elsewhere points at it.
func TestUpgradeMatrixHasOneSource(t *testing.T) {
	wf := read(t, ".github/workflows/release-checks.yml")
	if !regexp.MustCompile(`from: \[("\d+\.\d+\.\d+"(, )?)+\]`).MatchString(wf) {
		t.Fatal("release-checks.yml: no from: list of versions")
	}
	if !strings.Contains(read(t, "docs/install.md"), "release-checks.yml") {
		t.Error("docs/install.md should point at release-checks.yml for the upgrade sources")
	}
}

// TestUpgradeMatrixHasNewestRelease fails when the newest published release
// is not a source in the release-checks upgrade matrix, so every later
// release is tested as an upgrade from it. With an "Unreleased" heading in
// CHANGELOG.md, that is the first version below it. Without one, the change
// is a release that renamed Unreleased to its version and cannot be in the
// matrix before it is published, so the version before it must be.
func TestUpgradeMatrixHasNewestRelease(t *testing.T) {
	changelog := read(t, "CHANGELOG.md")
	versions := regexp.MustCompile(`(?m)^## (\d+\.\d+\.\d+)\s*$`).FindAllStringSubmatch(changelog, -1)
	published := 0
	if !regexp.MustCompile(`(?m)^## Unreleased\s*$`).MatchString(changelog) {
		published = 1
	}
	if len(versions) <= published {
		return // nothing published yet to upgrade from
	}
	v := versions[published][1]
	m := regexp.MustCompile(`from: \[([^\]]*)\]`).FindStringSubmatch(read(t, ".github/workflows/release-checks.yml"))
	if m == nil {
		t.Fatal("release-checks.yml: no from: list of versions")
	}
	if !strings.Contains(m[1], `"`+v+`"`) {
		t.Errorf("release-checks.yml: the upgrade matrix (from: [%s]) does not include %s, the newest published release in CHANGELOG.md; add it", m[1], v)
	}
}
