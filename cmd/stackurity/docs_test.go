package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// docSections is README.md and docs/*.md, the user documentation, split at
// each Markdown heading.
func docSections(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, filepath.Join("..", "..", "README.md"))
	var sections []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var cur strings.Builder
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "#") {
				sections = append(sections, cur.String())
				cur.Reset()
			}
			cur.WriteString(l + "\n")
		}
		sections = append(sections, cur.String())
	}
	return sections
}

// TestCLIDocumented fails when a command or flag of the stackurity binary is
// not mentioned in README.md or docs/*.md, so a new command or flag ships
// with its documentation. A command counts as documented when its full name
// ("stackurity sbom import") appears. A flag that only one command has
// counts when one section (the text under one heading) names both the
// command ("sbom import") and the flag ("--asset-name"); a flag several
// commands share (--server, --token-file, --project) is documented once for
// all of them, so it only has to appear somewhere. A persistent flag is
// checked on the command that defines it.
func TestCLIDocumented(t *testing.T) {
	sections := docSections(t)
	all := strings.Join(sections, "")
	root := newRootCmd()
	var walk func(c *cobra.Command, visit func(*cobra.Command))
	walk = func(c *cobra.Command, visit func(*cobra.Command)) {
		if c.Hidden {
			return
		}
		visit(c)
		for _, s := range c.Commands() {
			walk(s, visit)
		}
	}
	// How many commands define each flag.
	defined := map[string]int{}
	walk(root, func(c *cobra.Command) {
		c.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) { defined[f.Name]++ })
		c.PersistentFlags().VisitAll(func(f *pflag.Flag) { defined[f.Name]++ })
	})
	mentioned := func(cmd, flag string) bool {
		if defined[strings.TrimPrefix(flag, "--")] > 1 {
			return strings.Contains(all, flag)
		}
		for _, s := range sections {
			if strings.Contains(s, cmd) && strings.Contains(s, flag) {
				return true
			}
		}
		return false
	}
	walk(root, func(c *cobra.Command) {
		path := c.CommandPath()
		if c.HasParent() {
			if !strings.Contains(all, path) {
				t.Errorf("%q is not documented in README.md or docs/*.md", path)
			}
			name := strings.TrimPrefix(path, "stackurity ")
			check := func(f *pflag.Flag) {
				if !f.Hidden && !mentioned(name, "--"+f.Name) {
					t.Errorf("%s --%s: no section of README.md or docs/*.md names both %q and --%s", path, f.Name, name, f.Name)
				}
			}
			c.LocalNonPersistentFlags().VisitAll(check)
			c.PersistentFlags().VisitAll(check)
		}
	})
}
