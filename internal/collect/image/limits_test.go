package image

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/collect/limits"
	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/tenant"
)

// An image whose layers grow past the size limit is stopped, and the error
// says why.
func TestImageScanSizeLimit(t *testing.T) {
	defer netguard.SetResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("140.82.112.3")}, nil
	})()
	bin := filepath.Join(t.TempDir(), "syft")
	script := "#!/bin/sh\nhead -c 3145728 /dev/zero > \"$TMPDIR/layer\"\nsleep 30\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	s := &Scanner{Syft: bin, WorkDir: t.TempDir(), MaxBytes: 1 << 20}
	start := time.Now()
	_, err := s.Scan(tenant.WithWorkspace(context.Background(), 2), Config{Image: "ghcr.io/acme/huge:1"}, "")
	if !errors.Is(err, limits.ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 15*time.Second {
		t.Errorf("took %v: syft was not stopped", time.Since(start))
	}
}
