package fragments

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	f, err := Parse("x.md", "<!-- one PR -->\n\n### Fixed\n\n- **A.** Text.\n  More.\n\n### Security\n\n- **B.**\n\n```\n## inside a code block\n### also inside\n```\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Sections) != 2 || f.Sections[0].Name != "Fixed" || f.Sections[0].Body != "- **A.** Text.\n  More." ||
		f.Sections[1].Name != "Security" || !strings.Contains(f.Sections[1].Body, "### also inside") {
		t.Errorf("parsed %+v", f.Sections)
	}
	for name, c := range map[string]struct{ doc, want string }{
		"no heading":      {"- **A.**\n", "before the first"},
		"empty file":      {"\n\n", "no \"### Section\""},
		"unknown section": {"### Fixes\n\n- a\n", "unknown section"},
		"empty section":   {"### Added\n\n### Fixed\n\n- a\n", "Added section is empty"},
		"release heading": {"### Added\n\n- a\n\n## 0.20.0\n", "### Section\" headings only"},
	} {
		if _, err := Parse("x.md", c.doc); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want it to mention %q", name, err, c.want)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	if fs, err := Load(filepath.Join(dir, "missing")); err != nil || len(fs) != 0 {
		t.Errorf("missing dir: %v %v", fs, err)
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("README.md", "# How to\n\nNot a fragment.\n")
	write("notes.txt", "ignored")
	if fs, err := Load(dir); err != nil || len(fs) != 0 {
		t.Errorf("README only: %v %v", fs, err)
	}
	write("b.md", "### Added\n\n- b\n")
	write("a.md", "### Fixed\n\n- a\n")
	fs, err := Load(dir)
	if err != nil || len(fs) != 2 || filepath.Base(fs[0].Path) != "a.md" {
		t.Fatalf("load: %+v %v", fs, err)
	}
	write("bad.md", "- no heading\n")
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "bad.md") {
		t.Errorf("bad fragment: %v", err)
	}
}

func TestMerge(t *testing.T) {
	a, _ := Parse("a.md", "### Fixed\n\n- fix a\n\n### Added\n\n- add a\n")
	b, _ := Parse("b.md", "### Security\n\n- sec b\n\n### Fixed\n\n- fix b\n")
	// No fragments: the body is unchanged, whatever its layout.
	if got, _ := Merge("\n### Fixed\n- x\n\n", nil); got != "\n### Fixed\n- x\n\n" {
		t.Errorf("no fragments: %q", got)
	}
	// Only fragments.
	got, err := Merge("\n", []Fragment{a, b})
	want := "### Security\n\n- sec b\n\n### Added\n\n- add a\n\n### Fixed\n\n- fix a\n- fix b\n"
	if err != nil || got != want {
		t.Errorf("fragments only:\n%s\nwant:\n%s", got, want)
	}
	// Direct entries come first in their section; an unknown direct section
	// and text before the first heading are kept.
	got, err = Merge("\nIntro.\n\n### Notes\n\n- n\n\n### Fixed\n\n- fix direct\n\n", []Fragment{a, b})
	want = "Intro.\n\n### Security\n\n- sec b\n\n### Added\n\n- add a\n\n### Fixed\n\n- fix direct\n- fix a\n- fix b\n\n### Notes\n\n- n\n"
	if err != nil || got != want {
		t.Errorf("direct and fragments:\n%s\nwant:\n%s", got, want)
	}
}

// The repository's own fragments parse.
func TestRepositoryFragments(t *testing.T) {
	if _, err := Load(filepath.Join("..", "..", "..", Dir)); err != nil {
		t.Fatal(err)
	}
}
