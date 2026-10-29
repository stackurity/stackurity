package lockfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Every file an official pack reads by exact name is reported as
// unsupported without the pack, under a scope the pack handles, so Home can
// name the pack that would read it.
func TestPackFilesReportedUnsupported(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "packs", "*", "pack.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("pack manifests: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var m struct {
			Files   []string `json:"files"`
			Handles []string `json:"handles"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		for _, name := range m.Files {
			if strings.ContainsAny(name, "*?[") {
				continue // a pattern (*.jar): read only by the pack
			}
			scope, ok := unsupported[name]
			kind, _, _ := strings.Cut(scope, ":")
			if !ok || !slices.Contains(m.Handles, kind) {
				t.Errorf("%s: %s is reported as %q, which the pack's handles %v do not cover", f, name, scope, m.Handles)
			}
		}
	}
}
