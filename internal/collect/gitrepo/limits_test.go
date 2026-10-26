package gitrepo

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

// A repository that grows past the size limit while it is cloned is
// stopped, and the error says why.
func TestCloneSizeLimit(t *testing.T) {
	defer netguard.SetResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("140.82.112.3")}, nil
	})()
	bin := filepath.Join(t.TempDir(), "git")
	// Writes 3 MiB into the destination (the last argument), then hangs.
	script := "#!/bin/sh\nfor a; do d=$a; done\nmkdir -p \"$d\"\nhead -c 3145728 /dev/zero > \"$d/big\"\nsleep 30\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	s := &Scanner{WorkDir: t.TempDir(), Git: bin, MaxBytes: 1 << 20}
	start := time.Now()
	_, err := s.Scan(tenant.WithWorkspace(context.Background(), 2), Config{URL: "https://github.com/acme/huge.git"}, "")
	if !errors.Is(err, limits.ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 15*time.Second {
		t.Errorf("took %v: the clone was not stopped", time.Since(start))
	}
}
