package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/packs"
	"github.com/stackurity/stackurity/internal/store"
)

// sourceCatalog reads the manifests of the official packs' sources
// (packs/*/pack.json), so the suggestion rules are tested against every
// pack, including those whose signed archives are not built yet.
func sourceCatalog(t *testing.T) []packs.CatalogEntry {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "packs", "*", "pack.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("pack manifests: %v", err)
	}
	var cat []packs.CatalogEntry
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var m packs.Manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if err := m.Validate(); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		cat = append(cat, packs.CatalogEntry{Manifest: m})
	}
	return cat
}

// Home names the pack that reads a repository's files when the core reports
// them as unsupported: the real fixtures of each pack are scanned without
// packs, their unsupported coverage counted the way Store.UnsupportedFiles
// does (by the scope's first part), and matched against the catalogue.
func TestHomeSuggestsPackForFiles(t *testing.T) {
	cat := sourceCatalog(t)
	for fixture, want := range map[string]string{
		"swift/testdata/penny-bot-v1":           "swift",
		"swift/testdata/signal-ios":             "swift",
		"hex/testdata/plausible":                "hex",
		"cpp/testdata/rippled-conan2":           "cpp",
		"cpp/testdata/multipass-vcpkg":          "cpp",
		"cpp/testdata/joequake-vcpkg-installed": "cpp",
	} {
		_, cov, err := lockfile.Scan(os.DirFS(filepath.Join("..", "..", "packs", fixture)))
		if err != nil {
			t.Fatal(err)
		}
		counts := map[string]int64{}
		for _, c := range cov {
			if c.Status == "unsupported" {
				kind, _, _ := strings.Cut(c.Scope, ":")
				counts[kind]++
			}
		}
		sug := suggestFrom(cat, counts, nil)
		if len(sug) != 1 || sug[0].ID != want || sug[0].Files != 1 {
			t.Errorf("%s: suggestions %+v (unsupported %v), want %s", fixture, sug, counts, want)
		}
		// Installed and enabled, it is no longer suggested; disabled, it is.
		if s := suggestFrom(cat, counts, map[string]store.InstalledPack{want: {ID: want, Enabled: true}}); len(s) != 0 {
			t.Errorf("%s: suggested although installed: %+v", fixture, s)
		}
		if s := suggestFrom(cat, counts, map[string]store.InstalledPack{want: {ID: want}}); len(s) != 1 {
			t.Errorf("%s: not suggested while disabled: %+v", fixture, s)
		}
	}
}
