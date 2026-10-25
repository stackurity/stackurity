package image

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/tenant"
)

// fakeSyft records its environment and fails, echoing the registry
// credential the way a verbose error could.
func fakeSyft(t *testing.T) (bin, envFile string) {
	t.Helper()
	dir := t.TempDir()
	envFile = filepath.Join(dir, "env")
	bin = filepath.Join(dir, "syft")
	script := "#!/bin/sh\nenv > " + envFile + "\necho \"GET failed: auth $SYFT_REGISTRY_AUTH_PASSWORD $(printf '%s' \"$SYFT_REGISTRY_AUTH_USERNAME:$SYFT_REGISTRY_AUTH_PASSWORD\" | base64)\" >&2\nexit 1\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, envFile
}

func TestImageScanRefusesInternalRegistries(t *testing.T) {
	defer netguard.Set(netguard.FromEnv())
	netguard.Set(netguard.Config{Mode: "default"})
	defer netguard.SetResolver(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		switch host {
		case "localhost":
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		case "registry.attacker.example":
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("140.82.112.3")}, nil
	})()
	bin, envFile := fakeSyft(t)
	s := &Scanner{Syft: bin, WorkDir: t.TempDir()}
	ws2 := tenant.WithWorkspace(context.Background(), 2)
	for _, ref := range []string{"localhost:5000/app:1", "127.0.0.1:5000/app:1", "10.0.0.8/app:1", "169.254.169.254/latest:x",
		"registry.attacker.example/app:1", "2130706433:443/app:1", "0x7f000001:5000/app:1", "100.64.0.1/a/b"} {
		os.Remove(envFile)
		_, err := s.Scan(ws2, Config{Image: ref}, "")
		if !errors.Is(err, netguard.ErrBlocked) && !errors.Is(err, netguard.ErrAmbiguousHost) {
			t.Errorf("%s: %v", ref, err)
		}
		if _, statErr := os.Stat(envFile); statErr == nil {
			t.Errorf("%s: syft ran", ref)
		}
	}
}

// TestImageScanUsesGuardedProxy: Syft resolves names itself, so for a
// workspace kept off private networks it is sent through the guarded proxy
// (every connection checked at dial time), with no other proxy settings.
func TestImageScanUsesGuardedProxy(t *testing.T) {
	defer netguard.Set(netguard.FromEnv())
	netguard.Set(netguard.Config{Mode: "default"})
	defer netguard.SetResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("140.82.112.3")}, nil
	})()
	bin, envFile := fakeSyft(t)
	s := &Scanner{Syft: bin, WorkDir: t.TempDir()}
	const secret = "dckr_pat_SuperSecretValue123"
	_, err := s.Scan(tenant.WithWorkspace(context.Background(), 2), Config{Image: "ghcr.io/acme/app:1", Username: "bot"}, secret)
	if err == nil {
		t.Fatal("the fake syft fails")
	}
	basic := base64.StdEncoding.EncodeToString([]byte("bot:" + secret))
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), strings.TrimRight(basic, "=")) {
		t.Errorf("credential in error: %v", err)
	}
	env, _ := os.ReadFile(envFile)
	if !strings.Contains(string(env), "HTTPS_PROXY=http://127.0.0.1:") || !strings.Contains(string(env), "\nNO_PROXY=\n") {
		t.Errorf("syft not sent through the guarded proxy:\n%s", env)
	}
	if !strings.Contains(string(env), "SYFT_REGISTRY_AUTH_AUTHORITY=ghcr.io") {
		t.Errorf("credential not limited to the image's registry:\n%s", env)
	}

	os.Remove(envFile)
	_, _ = s.Scan(tenant.WithWorkspace(context.Background(), 1), Config{Image: "ghcr.io/acme/app:1"}, "")
	env, _ = os.ReadFile(envFile)
	if strings.Contains(string(env), "PROXY") {
		t.Errorf("default workspace (private access) was proxied:\n%s", env)
	}
}
