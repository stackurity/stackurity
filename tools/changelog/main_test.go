package main

import (
	"os"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/tools/internal/fragments"
)

const doc = `# Changelog

Intro.

## Unreleased

### Added

- Next thing.

## 0.4.0

### Security

- Fixed a vulnerability.

` + "```" + `
## not a heading, inside a code block
` + "```" + `

## 0.3.1

### Fixed

- A bug.
`

func TestSection(t *testing.T) {
	got, err := Section(doc, "v0.4.0")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "### Security\n") || !strings.Contains(got, "## not a heading") || strings.Contains(got, "A bug") {
		t.Errorf("0.4.0 notes:\n%s", got)
	}
	if got, err := Section(doc, "0.3.1"); err != nil || got != "### Fixed\n\n- A bug.\n" {
		t.Errorf("0.3.1: %q %v", got, err)
	}
	// A release candidate uses the section of its release.
	if got, err := Section(doc, "v0.4.0-rc.1"); err != nil || !strings.Contains(got, "Fixed a vulnerability") {
		t.Errorf("rc: %q %v", got, err)
	}
	for _, v := range []string{"v0.5.0", "v0.3", "main", "Unreleased"} {
		if _, err := Section(doc, v); err == nil {
			t.Errorf("%s: no error", v)
		}
	}
	if _, err := Section("## 1.0.0\n\n## 0.9.0\n- x\n", "1.0.0"); err == nil {
		t.Error("empty section accepted")
	}
}

func TestCheck(t *testing.T) {
	if err := Check(doc); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"## 0.4\n- x\n", "## 0.4.0\n- x\n## 0.4.0\n- y\n", "## 0.4.0\n\n## 0.3.0\n- y\n",
		"## Unreleased\n- a\n## Unreleased\n- b\n## 0.3.0\n- y\n"} {
		if Check(bad) == nil {
			t.Errorf("accepted:\n%s", bad)
		}
	}
}

func TestUnreleased(t *testing.T) {
	f, err := fragments.Parse("changelog.d/x.md", "### Security\n\n- **Patched.**\n\n### Added\n\n- Another thing.\n")
	if err != nil {
		t.Fatal(err)
	}
	// Fragments and the entries written directly under Unreleased.
	got, err := Unreleased(doc, []fragments.Fragment{f})
	want := "### Security\n\n- **Patched.**\n\n### Added\n\n- Next thing.\n- Another thing.\n"
	if err != nil || got != want {
		t.Errorf("got:\n%s\nwant:\n%s (%v)", got, want, err)
	}
	// Without fragments: the Unreleased section as written.
	if got, err := Unreleased(doc, nil); err != nil || got != "### Added\n\n- Next thing.\n" {
		t.Errorf("no fragments: %q %v", got, err)
	}
	// An empty Unreleased with fragments, and with none.
	empty := "## Unreleased\n\n## 0.4.0\n\n- x\n"
	if got, err := Unreleased(empty, []fragments.Fragment{f}); err != nil || !strings.HasPrefix(got, "### Security\n") {
		t.Errorf("fragments only: %q %v", got, err)
	}
	if got, err := Unreleased(empty, nil); err != nil || got != "" {
		t.Errorf("nothing: %q %v", got, err)
	}
	// Fragments are not part of a released version's notes.
	if got, err := Section(doc, "0.3.1"); err != nil || got != "### Fixed\n\n- A bug.\n" {
		t.Errorf("0.3.1: %q %v", got, err)
	}
}

// The repository's own changelog stays valid, and every released version
// has notes the release workflow can publish.
func TestRepositoryChangelog(t *testing.T) {
	b, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(string(b)); err != nil {
		t.Fatal(err)
	}
	if _, err := fragments.Load("../../" + fragments.Dir); err != nil {
		t.Fatal(err)
	}
	for _, s := range sections(string(b)) {
		if versionRE.MatchString(s.name) {
			if _, err := Section(string(b), "v"+s.name); err != nil {
				t.Error(err)
			}
		}
	}
}
