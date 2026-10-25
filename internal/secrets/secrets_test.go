package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestResolve(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "gh"), []byte("tok123\n"), 0o600)
	t.Setenv("STACKURITY_SECRET_GH", "envtok")
	t.Setenv("STACKURITY_DATABASE_URL", "postgres://secret")
	r := Resolver{AllowedDir: dir, EnvPrefix: "STACKURITY_SECRET_"}

	if v, err := r.Resolve(context.Background(), "file:"+filepath.Join(dir, "gh")); err != nil || v != "tok123" {
		t.Errorf("file = %q %v", v, err)
	}
	if v, err := r.Resolve(context.Background(), "env:STACKURITY_SECRET_GH"); err != nil || v != "envtok" {
		t.Errorf("env = %q %v", v, err)
	}
	for _, bad := range []string{
		"env:STACKURITY_DATABASE_URL",
		"file:/etc/passwd",
		"file:" + dir + "/../x",
		"file:relative",
		"vault:x",
		"plain",
	} {
		if _, err := r.Resolve(context.Background(), bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	if v, err := r.Resolve(context.Background(), ""); err != nil || v != "" {
		t.Error("empty ref means no secret")
	}
}
