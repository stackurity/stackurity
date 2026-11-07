// Package fragments reads changelog.d, where each pull request adds its
// CHANGELOG.md entries as a file of its own instead of editing the shared
// "## Unreleased" section, so parallel pull requests do not conflict.
//
// A fragment is changelog.d/<slug>.md: one or more "### Section" headings
// (Security, Added, Changed, Fixed, Upgrading, Removed), each followed by
// its entries, exactly as they would appear under "## Unreleased":
//
//	### Fixed
//
//	- **Short title.** What changed and who notices.
//
// changelog.d/README.md explains the format and is not a fragment. The
// fragments, together with anything still written directly under
// "## Unreleased", are the next release's notes; go run ./tools/release
// prepare merges them into the release section and deletes the files.
package fragments

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// Dir is the fragments directory, relative to the repository root.
const Dir = "changelog.d"

// Order is the order of the subsections in a release, as CHANGELOG.md's
// header gives it: Security first, because installations treat a release
// with that heading as a security release.
var Order = []string{"Security", "Added", "Changed", "Fixed", "Upgrading", "Removed"}

// Section is one "### Name" heading and the text under it.
type Section struct {
	Name string
	Body string // trimmed; never empty
}

// Fragment is one file in changelog.d.
type Fragment struct {
	Path     string
	Sections []Section
}

// Parse reads a fragment's content. It must start with a "### Section"
// heading (blank lines and HTML comments before it are allowed), name only
// known sections, have something under each, and contain no "## " heading,
// which would end the release section it is merged into.
func Parse(path, content string) (Fragment, error) {
	f := Fragment{Path: path}
	pre, secs, err := split(content)
	if err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	if strings.TrimSpace(stripComments(pre)) != "" {
		return f, fmt.Errorf("%s: text before the first \"### Section\" heading; start with one of: ### %s", path, strings.Join(Order, ", ### "))
	}
	if len(secs) == 0 {
		return f, fmt.Errorf("%s: no \"### Section\" heading; start with one of: ### %s", path, strings.Join(Order, ", ### "))
	}
	for _, s := range secs {
		if !slices.Contains(Order, s.Name) {
			return f, fmt.Errorf("%s: unknown section %q; use one of %s", path, s.Name, strings.Join(Order, ", "))
		}
		if s.Body == "" {
			return f, fmt.Errorf("%s: the %s section is empty", path, s.Name)
		}
	}
	f.Sections = secs
	return f, nil
}

// Load parses every fragment in dir (every *.md but README.md), sorted by
// file name. A missing directory has no fragments.
func Load(dir string) ([]Fragment, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []Fragment
	var errs []error
	for _, p := range paths {
		if strings.EqualFold(filepath.Base(p), "README.md") {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		f, err := Parse(p, string(b))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, f)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

// Merge returns the body of a release section: body (what is written
// directly under "## Unreleased") with the fragments' entries added. Each
// section's entries keep their order, those written directly first and then
// each fragment's in file order; the sections follow Order, and any other
// "### " section written directly comes after them. Text before the first
// "### " heading of body stays at the top. Without fragments body is
// returned unchanged.
func Merge(body string, frags []Fragment) (string, error) {
	if len(frags) == 0 {
		return body, nil
	}
	pre, secs, err := split(body)
	if err != nil {
		return "", fmt.Errorf("## Unreleased: %w", err)
	}
	entries := map[string][]string{}
	var names []string // in output order: Order first, then others as found
	add := func(name, text string) {
		if text == "" {
			return
		}
		if _, ok := entries[name]; !ok {
			names = append(names, name)
		}
		entries[name] = append(entries[name], text)
	}
	for _, s := range secs {
		add(s.Name, s.Body)
	}
	for _, f := range frags {
		for _, s := range f.Sections {
			add(s.Name, s.Body)
		}
	}
	rank := func(n string) int {
		if i := slices.Index(Order, n); i >= 0 {
			return i
		}
		return len(Order)
	}
	sort.SliceStable(names, func(i, j int) bool { return rank(names[i]) < rank(names[j]) })

	var b strings.Builder
	if p := strings.TrimSpace(pre); p != "" {
		b.WriteString(p + "\n\n")
	}
	for _, n := range names {
		fmt.Fprintf(&b, "### %s\n\n%s\n\n", n, strings.Join(entries[n], "\n"))
	}
	return strings.TrimRight(b.String(), "\n") + "\n", nil
}

// split cuts markdown into the text before the first "### " heading and the
// sections after it, ignoring headings inside code blocks. A "## " heading
// is an error: it would start a new release section.
func split(content string) (pre string, secs []Section, err error) {
	var cur *Section
	var lines, preLines []string
	flush := func() {
		if cur != nil {
			cur.Body = strings.TrimSpace(strings.Join(lines, "\n"))
			secs = append(secs, *cur)
		}
	}
	inFence := false
	for _, l := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			inFence = !inFence
		}
		switch {
		case !inFence && strings.HasPrefix(l, "### "):
			flush()
			cur, lines = &Section{Name: strings.TrimSpace(l[4:])}, nil
		case !inFence && (strings.HasPrefix(l, "## ") || strings.HasPrefix(l, "# ")):
			return "", nil, fmt.Errorf("heading %q: use \"### Section\" headings only", strings.TrimSpace(l))
		case cur != nil:
			lines = append(lines, l)
		default:
			preLines = append(preLines, l)
		}
	}
	flush()
	return strings.Join(preLines, "\n"), secs, nil
}

func stripComments(s string) string {
	for {
		i := strings.Index(s, "<!--")
		if i < 0 {
			return s
		}
		j := strings.Index(s[i:], "-->")
		if j < 0 {
			return s[:i]
		}
		s = s[:i] + s[i+j+3:]
	}
}
