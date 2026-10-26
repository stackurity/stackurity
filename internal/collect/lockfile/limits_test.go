package lockfile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

func scanLimits(t *testing.T, ctx context.Context, root string) (*model.ObservationBatch, error) {
	t.Helper()
	return ScanDirWith(ctx, root, model.AssetRef{Kind: model.AssetRepository, Name: "r",
		Identifiers: []model.Identifier{{Scheme: "git-url", Value: "https://x/r"}}}, "test", nil)
}

func coverage(b *model.ObservationBatch, scope string) *model.CoverageItem {
	for i := range b.Coverage {
		if b.Coverage[i].Scope == scope {
			return &b.Coverage[i]
		}
	}
	return nil
}

const limitsLock = `{"lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/lodash":{"version":"4.17.21"}}}`

// Untrusted trees are walked within limits: too many entries or too deep
// stops that part, says so, and leaves the batch incomplete so nothing
// unscanned is marked removed.
func TestWalkLimits(t *testing.T) {
	root := t.TempDir()
	deep := root
	for i := 0; i < MaxWalkDepth+2; i++ {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "package-lock.json"), []byte(limitsLock), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := scanLimits(t, context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if c := coverage(b, "depth"); c == nil || c.Status != "partial" || b.Complete || len(b.Observations) != 0 {
		t.Fatalf("depth: %+v complete=%v obs=%d", b.Coverage, b.Complete, len(b.Observations))
	}

	defer func(n int) { walkEntries = n }(walkEntries)
	walkEntries = 10
	wide := t.TempDir()
	for i := 0; i < 30; i++ {
		_ = os.WriteFile(filepath.Join(wide, fmt.Sprintf("f%02d", i)), nil, 0o600)
	}
	if b, err = scanLimits(t, context.Background(), wide); err != nil {
		t.Fatal(err)
	}
	if c := coverage(b, "walk"); c == nil || c.Status != "partial" || b.Complete || !strings.Contains(c.Reason, "stopped after 10") {
		t.Fatalf("entries: %+v", b.Coverage)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
}

// The scan's deadline stops the walk too.
func TestWalkStopsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanLimits(t, ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

// A giant lockfile is skipped and said so, without being read.
func TestOversizedLockfile(t *testing.T) {
	root := t.TempDir()
	f, err := os.Create(filepath.Join(root, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxLockfileSize + 1); err != nil { // sparse: no real disk used
		t.Fatal(err)
	}
	f.Close()
	b, err := scanLimits(t, context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if c := coverage(b, "lockfile:package-lock.json"); c == nil || c.Status != "skipped" || !strings.Contains(c.Reason, "64 MiB") {
		t.Fatalf("%+v", b.Coverage)
	}
}

// Thousands of unsupported files keep the batch within the coverage limit
// instead of making the server refuse all of it.
func TestCoverageIsCapped(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < model.MaxCoverageItems+200; i++ {
		d := filepath.Join(root, fmt.Sprintf("m%04d", i))
		_ = os.Mkdir(d, 0o700)
		_ = os.WriteFile(filepath.Join(d, "pom.xml"), []byte("<project/>"), 0o600)
	}
	_ = os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(limitsLock), 0o600)
	b, err := scanLimits(t, context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Coverage) != model.MaxCoverageItems || coverage(b, "coverage-limit") == nil {
		t.Fatalf("%d coverage items", len(b.Coverage))
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(b.Observations) != 1 {
		t.Errorf("observations: %d", len(b.Observations))
	}
}
