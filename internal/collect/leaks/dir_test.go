package leaks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, root, rel, data string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDir(t *testing.T) {
	root := t.TempDir()
	write(t, root, "app/billing.py", "KEY = '"+stripeKey+"'\n")
	write(t, root, "node_modules/lib/x.js", ghToken)
	write(t, root, "third_party/aws/config/x.php", ghToken)
	write(t, root, "app/billing_test.py", ghToken)
	write(t, root, "logo.png", ghToken)
	write(t, root, "blob.bin", "\x00"+ghToken)
	if err := os.Symlink("/etc", filepath.Join(root, "etc")); err != nil {
		t.Fatal(err)
	}
	res := Dir(context.Background(), root)
	if !res.Complete || len(res.Leaks) != 1 || res.Leaks[0].Path != "app/billing.py" {
		t.Fatalf("got %+v", res)
	}
}
