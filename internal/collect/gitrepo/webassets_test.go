package gitrepo

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/tenant"
)

// A static or PHP site's repository has no manifest, only copies of the
// libraries it serves: each is reported by its banner, and the batch stays
// complete.
func TestScanReportsVendoredLibraries(t *testing.T) {
	defer netguard.SetResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("140.82.112.3")}, nil
	})()
	bin := filepath.Join(t.TempDir(), "git")
	script := "#!/bin/sh\nfor a; do [ \"$a\" = clone ] && c=1; d=$a; done\n[ -n \"$c\" ] || exit 0\n" +
		"mkdir -p \"$d/js\" \"$d/.git\"\n" +
		"printf '/*! jQuery v3.6.0 | (c) OpenJS Foundation and other contributors | jquery.org/license */\\n' > \"$d/js/jquery-3.6.0.min.js\"\n" +
		"printf '/*!\\n  * Bootstrap v5.1.3 (https://getbootstrap.com/)\\n  */\\n' > \"$d/js/bootstrap.bundle.min.js\"\n" +
		"printf '<?php echo 1; ?>\\n' > \"$d/index.php\"\nprintf 'x' > \"$d/.git/config\"\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	s := &Scanner{WorkDir: t.TempDir(), Git: bin, NoLeaks: true}
	b, err := s.Scan(tenant.WithWorkspace(context.Background(), 2), Config{URL: "https://github.com/acme/site.git"}, "")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, o := range b.Observations {
		got[o.Purl] = o.Location
	}
	for purl, loc := range map[string]string{"pkg:npm/jquery@3.6.0": "js/jquery-3.6.0.min.js", "pkg:npm/bootstrap@5.1.3": "js/bootstrap.bundle.min.js"} {
		if got[purl] != loc {
			t.Errorf("%s at %q, want %q (all: %v)", purl, got[purl], loc, got)
		}
	}
	if !b.Complete {
		t.Errorf("batch incomplete: %+v", b.Coverage)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
}
