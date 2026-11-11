package trustbadge_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The launch gate in docs/trust-badge.md names the tests behind each
// automated item. A renamed or deleted test would leave an item looking
// checked when nothing checks it, so every name must be a test function in
// the repository. The counsel item is outside the code and is kept in the
// list so it can't be dropped silently.
func TestLaunchGateNamesRealTests(t *testing.T) {
	root := filepath.Join("..", "..")
	doc, err := os.ReadFile(filepath.Join(root, "docs", "trust-badge.md"))
	if err != nil {
		t.Fatal(err)
	}
	gate := string(doc)
	start := strings.Index(gate, "## Launch gate")
	if start < 0 {
		t.Fatal("docs/trust-badge.md has no launch gate")
	}
	gate = gate[start:]
	if end := strings.Index(gate[3:], "\n## "); end >= 0 {
		gate = gate[:end+3]
	}
	names := regexp.MustCompile("`(Test[A-Za-z0-9_]+)`").FindAllStringSubmatch(gate, -1)
	if len(names) < 15 {
		t.Fatalf("only %d tests named in the launch gate", len(names))
	}
	defined := map[string]bool{}
	fn := regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range fn.FindAllStringSubmatch(string(b), -1) {
			defined[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range names {
		if !defined[m[1]] {
			t.Errorf("the launch gate names %s, which is not a test", m[1])
		}
	}
	if !regexp.MustCompile(`(?m)^\| Counsel's written sign-off.*\| \*\*`).MatchString(gate) {
		t.Error("the launch gate no longer lists counsel's sign-off")
	}
}
