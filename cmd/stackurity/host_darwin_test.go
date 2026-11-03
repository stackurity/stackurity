//go:build darwin

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// On a Mac the agent reads macOS; with --root it reads the Linux
// filesystem mounted there, as before it could read macOS.
func TestHostCollectorDarwin(t *testing.T) {
	collect, err := hostCollector(&hostOptions{root: "/"})
	if err != nil {
		t.Fatal(err)
	}
	bs, err := collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != 2 || bs[0].Collector.ID != "macos-agent" || bs[1].Collector.ID != "macos-software" || bs[0].Asset.Attributes["os"] != "macos" {
		t.Fatalf("batches: %d %+v", len(bs), bs[0].Collector)
	}
	for _, b := range bs {
		if err := b.Validate(); err != nil {
			t.Error(err)
		}
	}

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=alpine\nVERSION_ID=3.20.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	collect, err = hostCollector(&hostOptions{root: root})
	if err != nil {
		t.Fatal(err)
	}
	bs, err = collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bs[0].Collector.ID != "linux-agent" || bs[0].Asset.Attributes["os"] != "alpine" {
		t.Errorf("--root: %+v %+v", bs[0].Collector, bs[0].Asset.Attributes)
	}
}
