// Command changelog prints the CHANGELOG.md section for a release, which the
// release workflow publishes as the release notes:
//
//	go run ./tools/changelog -version v0.4.0 > notes.md
//
// It fails when the section is missing or empty, so every release has notes.
// A prerelease tag (v0.4.0-rc.1) uses its own section when there is one,
// otherwise the section of the release it leads to (0.4.0).
//
// With -check it only validates CHANGELOG.md: every "## " heading is
// "Unreleased" or a version, no version appears twice, and no released
// section is empty.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
)

func main() {
	file := flag.String("file", "CHANGELOG.md", "changelog to read")
	ver := flag.String("version", "", "release tag or version, e.g. v0.4.0")
	check := flag.Bool("check", false, "only validate the changelog")
	flag.Parse()
	b, err := os.ReadFile(*file)
	if err != nil {
		fail(err)
	}
	if *check {
		if err := Check(string(b)); err != nil {
			fail(err)
		}
		return
	}
	if *ver == "" {
		fail(errors.New("-version is required"))
	}
	notes, err := Section(string(b), *ver)
	if err != nil {
		fail(err)
	}
	fmt.Print(notes)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "changelog:", err)
	os.Exit(1)
}

var versionRE = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

type section struct {
	name string // the heading's first word, without "v" or brackets
	body string
}

func sections(doc string) []section {
	var out []section
	var cur *section
	var body []string
	flush := func() {
		if cur != nil {
			cur.body = strings.TrimSpace(strings.Join(body, "\n"))
			out = append(out, *cur)
		}
	}
	inFence := false
	for _, line := range strings.Split(strings.ReplaceAll(doc, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
		}
		if !inFence && strings.HasPrefix(line, "## ") {
			flush()
			f := strings.Fields(line[3:])
			name := ""
			if len(f) > 0 {
				name = strings.TrimPrefix(strings.Trim(f[0], "[]"), "v")
			}
			cur, body = &section{name: name}, nil
			continue
		}
		if cur != nil {
			body = append(body, line)
		}
	}
	flush()
	return out
}

// Section returns the notes for a version (with or without "v").
func Section(doc, ver string) (string, error) {
	v := strings.TrimPrefix(strings.TrimSpace(ver), "v")
	if !versionRE.MatchString(v) {
		return "", fmt.Errorf("%q is not a release version", ver)
	}
	want := []string{v}
	if base, _, pre := strings.Cut(v, "-"); pre {
		want = append(want, base)
	}
	all := sections(doc)
	for _, w := range want {
		for _, s := range all {
			if s.name == w {
				if s.body == "" {
					return "", fmt.Errorf("the section for %s in CHANGELOG.md is empty", w)
				}
				return s.body + "\n", nil
			}
		}
	}
	return "", fmt.Errorf("CHANGELOG.md has no \"## %s\" section; add the release notes before tagging", v)
}

// Check validates the whole changelog.
func Check(doc string) error {
	seen := map[string]bool{}
	var errs []error
	for _, s := range sections(doc) {
		switch {
		case strings.EqualFold(s.name, "Unreleased"):
			continue
		case !versionRE.MatchString(s.name):
			errs = append(errs, fmt.Errorf("heading %q is neither Unreleased nor a version", s.name))
		case seen[s.name]:
			errs = append(errs, fmt.Errorf("version %s appears twice", s.name))
		case s.body == "":
			errs = append(errs, fmt.Errorf("the section for %s is empty", s.name))
		}
		seen[s.name] = true
	}
	return errors.Join(errs...)
}
