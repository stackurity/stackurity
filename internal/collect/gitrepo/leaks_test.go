package gitrepo

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/tenant"
)

// A key committed to the repository is reported with the batch, by its
// path in the repository and without its value.
func TestScanReportsLeaks(t *testing.T) {
	defer netguard.SetResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("140.82.112.3")}, nil
	})()
	token := strings.Join([]string{"ghp", "_", "Zq7Lm2Xr9Tb4Kc8Vn3Pw6Hy1Jd5Fs0Ga2Qex"}, "")
	bin := filepath.Join(t.TempDir(), "git")
	// "Clones" into the destination (the last argument); fails anything else.
	// The temporary directory's name has "clone" in it too, so the
	// subcommand is looked for among the arguments, not in all of them.
	script := "#!/bin/sh\nfor a; do [ \"$a\" = clone ] && c=1; d=$a; done\n[ -n \"$c\" ] || exit 1\n" +
		"mkdir -p \"$d/src\" \"$d/.git\"\nprintf \"const t = '" + token + "';\\n\" > \"$d/src/deploy.js\"\nprintf 'x' > \"$d/.git/config\"\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, off := range []bool{false, true} {
		s := &Scanner{WorkDir: t.TempDir(), Git: bin, NoLeaks: off}
		b, err := s.Scan(tenant.WithWorkspace(context.Background(), 2), Config{URL: "https://github.com/acme/shop.git"}, "")
		if err != nil {
			t.Fatal(err)
		}
		if off {
			if b.Leaks != nil {
				t.Errorf("NoLeaks: got %+v", b.Leaks)
			}
			continue
		}
		if b.Leaks == nil || len(b.Leaks.Found) != 1 || b.Leaks.Found[0].Path != "src/deploy.js" || b.Leaks.Found[0].Severity != "critical" {
			t.Fatalf("leaks %+v", b.Leaks)
		}
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(b.Leaks.Found[0].Preview+b.Leaks.Found[0].Fingerprint, token[4:30]) {
			t.Error("the batch holds the token")
		}
	}
}
