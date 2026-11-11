package intel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/collect/linux"
	"github.com/stackurity/stackurity/internal/lifecycle"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
)

// pythonCycles are some of endoflife.date's python release cycles, with
// their end-of-life dates.
func pythonCycles() []store.LifecycleCycle {
	day := func(s string) *time.Time { t, _ := time.Parse("2006-01-02", s); return &t }
	return []store.LifecycleCycle{
		{Product: "python", ProductLabel: "Python", Cycle: "3.13", EOLUntil: day("2029-10-31")},
		{Product: "python", ProductLabel: "Python", Cycle: "3.12", EOLUntil: day("2028-10-31")},
		{Product: "python", ProductLabel: "Python", Cycle: "3.9", EOLUntil: day("2025-10-31"), IsEOL: true},
		{Product: "python", ProductLabel: "Python", Cycle: "3.8", EOLUntil: day("2024-10-07"), IsEOL: true, Latest: "3.8.20"},
	}
}

// pythonImageObservation reads a python:3.8-slim style root the way an
// image is read (nothing run) and returns its python runtime observation.
func pythonImageObservation(t *testing.T, header bool) model.Observation {
	t.Helper()
	root := t.TempDir()
	put := func(p, data string, mode os.FileMode) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(full, mode)
	}
	put("etc/os-release", "ID=debian\nVERSION_ID=12\n", 0o644)
	put("var/lib/dpkg/status", "Package: libc6\nStatus: install ok installed\nVersion: 2.36-9\n\n", 0o644)
	put("var/lib/dpkg/info/libc6:amd64.list", "/.\n/usr/bin/ldd\n", 0o644)
	put("usr/local/bin/python3.8", "\x7fELF", 0o755)
	if err := os.Symlink("python3.8", filepath.Join(root, "usr/local/bin/python3")); err != nil {
		t.Fatal(err)
	}
	put("usr/local/lib/python3.8/os.py", "", 0o644)
	if header {
		put("usr/local/include/python3.8/patchlevel.h", "#define PY_VERSION              \"3.8.20\"\n", 0o644)
	}
	c := linux.New("test")
	c.Root = root
	c.RunVersion = nil
	c.LookPath = func(string) (string, error) { return "", os.ErrNotExist }
	osBatch, err := c.Collect(context.Background(), "image", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range c.CollectSoftware(context.Background(), osBatch, nil).Observations {
		if o.Evidence["kind"] == "runtime" {
			return o
		}
	}
	t.Fatal("no python runtime")
	return model.Observation{}
}

// Python read from an image's files, without running it, reaches the
// lifecycle matcher with a version, so an ended release line is flagged:
// the exact release from patchlevel.h, and the release line alone (3.8)
// from the standard library's directory. Without a version (as before)
// there is no release line to match.
func TestImagePythonEndOfLife(t *testing.T) {
	lr := &lifecycleResolver{lifecycle.Resolver{Names: map[string]bool{"python": true}}}
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		header       bool
		version      string
		verification string
		rule         string
	}{
		{true, "3.8.20", "confirmed", "version_prefix"},
		{false, "3.8", "needs_validation", "exact_cycle"},
	} {
		o := pythonImageObservation(t, c.header)
		if o.Version != c.version {
			t.Fatalf("header=%v: version = %q, want %q", c.header, o.Version, c.version)
		}
		m, ok := lr.resolve("generic", "pkg:generic/python", o.Version, o.Evidence["kind"])
		if !ok || m.product != "python" {
			t.Fatalf("%s: not resolved to python: %+v", o.Version, m)
		}
		cyc := matchCycle(pythonCycles(), m.cycleVersion)
		if cyc == nil || cyc.Cycle != "3.8" {
			t.Fatalf("%s: release line = %+v", o.Version, cyc)
		}
		row := store.EvalRow{Type: "generic", PurlKey: "pkg:generic/python", Purl: o.Purl, Version: o.Version,
			Confidence: string(o.Confidence), Evidence: o.Evidence}
		f := eolFinding(row, cyc, now)
		if f == nil || f.Key != "python:3.8" || f.Title != "Python 3.8 is end-of-life since 2024-10-07" || f.Verification != c.verification {
			t.Errorf("%s: finding = %+v", o.Version, f)
		}
		if got := eolMatch(o.Version, m.cycleVersion, cyc.Cycle)["rule"]; got != c.rule {
			t.Errorf("%s: match rule = %v, want %s", o.Version, got, c.rule)
		}
	}
	// A supported release line is not flagged.
	if f := eolFinding(store.EvalRow{Version: "3.12"}, matchCycle(pythonCycles(), "3.12"), now); f != nil {
		t.Errorf("3.12 flagged: %+v", f)
	}
	// No version, no release line: nothing to flag (the bug this fixes).
	if cyc := matchCycle(pythonCycles(), ""); cyc != nil {
		t.Errorf("an unversioned python matched %+v", cyc)
	}
}
