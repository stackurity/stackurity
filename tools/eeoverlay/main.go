// Command eeoverlay writes a Go build overlay that adds the licensed
// edition's files (the private stackurity-pro repository, laid out like this
// one) to the core packages:
//
//	go run ./tools/eeoverlay -pro ../stackurity-pro > ee-overlay.json
//	go build -tags ee -overlay ee-overlay.json ./cmd/stackurity
//
// It only adds files: a pro file whose path already exists in the core is an
// error, so the licensed build can never silently replace core code. Packages
// that exist only in stackurity-pro get an empty directory in the core
// checkout, because go test and go vet run in each package's directory.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	pro := flag.String("pro", "../stackurity-pro", "checkout of stackurity-pro")
	core := flag.String("core", ".", "checkout of the core")
	flag.Parse()
	coreAbs, err := filepath.Abs(*core)
	check(err)
	proAbs, err := filepath.Abs(*pro)
	check(err)
	replace := map[string]string{}
	err = filepath.WalkDir(proAbs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		rel, err := filepath.Rel(proAbs, p)
		if err != nil {
			return err
		}
		target := filepath.Join(coreAbs, rel)
		if _, err := os.Stat(target); err == nil {
			return fmt.Errorf("%s exists in the core; the licensed edition may only add files", rel)
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(string(src), "//go:build ee") {
			return fmt.Errorf("%s must start with //go:build ee", rel)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		replace[target] = p
		return nil
	})
	check(err)
	if len(replace) == 0 {
		check(fmt.Errorf("no Go files under %s", proAbs))
	}
	out, _ := json.MarshalIndent(map[string]any{"Replace": replace}, "", "  ")
	fmt.Println(string(out))
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "eeoverlay:", err)
		os.Exit(1)
	}
}
