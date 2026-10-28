package eedeps

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

// TestGoModKeepsLicensedModules fails when go.mod or go.sum no longer
// provides a package deps.go imports, so a go mod tidy (or a Dependabot
// update) that drops one fails CI here instead of breaking the licensed
// build, which this repository's CI does not compile.
func TestGoModKeepsLicensedModules(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "deps.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	mod, err := modfile.Parse("go.mod", b, nil)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := os.ReadFile("../../go.sum")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Imports) == 0 {
		t.Fatal("deps.go imports nothing")
	}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		var found string
		for _, r := range mod.Require {
			if (path == r.Mod.Path || strings.HasPrefix(path, r.Mod.Path+"/")) && len(r.Mod.Path) > len(found) {
				found = r.Mod.Path + " " + r.Mod.Version
			}
		}
		switch {
		case found == "":
			t.Errorf("go.mod requires no module providing %s, which stackurity-pro imports (tools/eedeps/deps.go): run go get for it and keep the require", path)
		case !strings.Contains(string(sum), found+" h1:"):
			t.Errorf("go.sum has no checksum for %s (needed for %s): run go mod tidy", found, path)
		}
	}
}
