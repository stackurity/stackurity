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
// "Unreleased" or a version, no version (and not Unreleased) appears twice,
// and no released section is empty; and every fragment in changelog.d
// parses (see changelog.d/README.md).
//
// With -unreleased it prints what the next release's notes will be: the
// "## Unreleased" section with the changelog.d fragments merged in, as
// go run ./tools/release prepare will write them.
//
//	go run ./tools/changelog -unreleased
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/stackurity/stackurity/tools/internal/fragments"
)

func main() {
	file := flag.String("file", "CHANGELOG.md", "changelog to read")
	ver := flag.String("version", "", "release tag or version, e.g. v0.4.0")
	check := flag.Bool("check", false, "only validate the changelog and the changelog.d fragments")
	unreleased := flag.Bool("unreleased", false, "print the Unreleased notes with the changelog.d fragments merged in")
	dir := flag.String("fragments", fragments.Dir, "changelog fragments directory")
	flag.Parse()
	b, err := os.ReadFile(*file)
	if err != nil {
		fail(err)
	}
	if *check {
		err := Check(string(b))
		if _, ferr := fragments.Load(*dir); ferr != nil {
			err = errors.Join(err, ferr)
		}
		if err != nil {
			fail(err)
		}
		return
	}
	if *unreleased {
		frags, err := fragments.Load(*dir)
		if err != nil {
			fail(err)
		}
		notes, err := Unreleased(string(b), frags)
		if err != nil {
			fail(err)
		}
		fmt.Print(notes)
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

// Unreleased returns the next release's notes: the "## Unreleased" section
// (missing is the same as empty) with the fragments merged in. It is empty
// when there is nothing to release.
func Unreleased(doc string, frags []fragments.Fragment) (string, error) {
	body := ""
	for _, s := range sections(doc) {
		if strings.EqualFold(s.name, "Unreleased") {
			body = s.body
			break
		}
	}
	notes, err := fragments.Merge(body, frags)
	if err != nil {
		return "", err
	}
	if notes = strings.TrimSpace(notes); notes == "" {
		return "", nil
	}
	return notes + "\n", nil
}

// Check validates the whole changelog.
func Check(doc string) error {
	seen := map[string]bool{}
	var errs []error
	for _, s := range sections(doc) {
		switch {
		case strings.EqualFold(s.name, "Unreleased"):
			if seen["Unreleased"] {
				errs = append(errs, errors.New(`"## Unreleased" appears twice (a merge left one behind); merge them into the first`))
			}
			seen["Unreleased"] = true
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
