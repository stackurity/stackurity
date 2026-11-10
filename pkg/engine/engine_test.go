package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The engine works offline from a directory and caller-supplied advisories.
func TestOfflineScanAndMatch(t *testing.T) {
	dir := t.TempDir()
	lock := `{"name":"demo","lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"4.17.20"}},"node_modules/lodash":{"version":"4.17.20"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("ANTHROPIC_API_KEY=sk-ant-api03-"+"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJ-AAAAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := ScanDir(context.Background(), dir, "demo", "test")
	if err != nil {
		t.Fatal(err)
	}
	var lodash *Observation
	for i := range b.Observations {
		if b.Observations[i].Version == "4.17.20" {
			lodash = &b.Observations[i]
		}
	}
	if lodash == nil {
		t.Fatalf("lodash not found in %+v", b.Observations)
	}
	tg, ok := OSVTarget(lodash.Purl, lodash.Version, lodash.Evidence)
	if !ok || tg.Ecosystem != "npm" || tg.Name != "lodash" {
		t.Fatalf("target %+v %v", tg, ok)
	}
	a := Affected{Ranges: []Range{{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "4.17.21"}}}}}
	m, err := CheckAffected(a, tg)
	if err != nil || !m.Affected || m.FixedVersion != "4.17.21" {
		t.Fatalf("match %+v %v", m, err)
	}
	res := DirLeaks(context.Background(), dir, nil)
	if len(res.Leaks) == 0 || res.Leaks[0].Rule != "anthropic-key" {
		t.Fatalf("leaks %+v", res.Leaks)
	}
}
