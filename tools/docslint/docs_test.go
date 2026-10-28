package docslint

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repo is the repository root, relative to this package.
var repo = filepath.Join("..", "..")

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repo, path))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// userDocs is README.md and docs/*.md (not docs/design, which records how
// things were built rather than how to use them), keyed by path.
func userDocs(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(repo, "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{"README.md": read(t, "README.md")}
	for _, f := range files {
		rel, _ := filepath.Rel(repo, f)
		out[filepath.ToSlash(rel)] = read(t, rel)
	}
	return out
}

// allowlist reads one of this package's exception files: one entry per
// line, optionally followed by two spaces and a reason; blank lines and lines
// starting with # are comments. With needReason, an entry without a reason
// fails the test.
func allowlist(t *testing.T, name string, needReason bool) map[string]bool {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, reason, _ := strings.Cut(line, "  ")
		if needReason && strings.TrimSpace(reason) == "" {
			t.Errorf("%s:%d: %q needs a reason after two spaces", name, n, entry)
		}
		if out[entry] {
			t.Errorf("%s:%d: %q is listed twice", name, n, entry)
		}
		out[entry] = true
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
