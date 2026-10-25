package gitrepo

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/tenant"
)

// fakeGit writes a git stand-in that records its arguments and environment
// and fails with output echoing the credential, as a hostile server's
// error page or a verbose git could.
func fakeGit(t *testing.T) (bin, argsFile, envFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile, envFile = filepath.Join(dir, "args"), filepath.Join(dir, "env")
	bin = filepath.Join(dir, "git")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\nenv > " + envFile +
		"\necho \"fatal: unable to access: $GIT_CONFIG_VALUE_0 token=$TOKEN_ECHO\" >&2\nexit 128\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile, envFile
}

func TestValidateRefusesNonHTTPSAndHiddenCredentials(t *testing.T) {
	for _, bad := range []string{
		"http://github.com/a/b", "ssh://git@github.com/a/b", "git://github.com/a/b", "git@github.com:a/b.git",
		"file:///etc", "ext::sh -c touch% /tmp/x", "fd::17", "https:///a/b",
		"https://user:pw@github.com/a/b", "https://token@github.com/a/b",
		"https://gitlab.example/a/b.git?private_token=glpat-secret", "https://github.com/a/b#frag", "https://github.com/a/b?",
		"https://2130706433/a/b", "https://0x7f.1/a/b", "https://0177.0.0.1/a/b", "https://127.1/a/b",
		"https://169.254.169.254./a/b", " https://github.com/a/b", "-uhttps://github.com/a/b",
	} {
		if (Config{URL: bad}).Validate() == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, ref := range []string{"--upload-pack=touch /tmp/x", "-c", "main branch", "a\nb"} {
		if (Config{URL: "https://github.com/a/b", Ref: ref}).Validate() == nil {
			t.Errorf("ref %q accepted", ref)
		}
	}
}

// TestCloneRefusesInternalDestinations runs the clone for a workspace that
// may not reach private networks: git must never start for an internal
// destination, however it is written or resolved.
func TestCloneRefusesInternalDestinations(t *testing.T) {
	defer netguard.Set(netguard.FromEnv())
	netguard.Set(netguard.Config{Mode: "default"})
	var lookups atomic.Int32
	defer netguard.SetResolver(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		switch host {
		case "metadata.attacker.example":
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		case "rebind.attacker.example":
			if lookups.Add(1) == 1 {
				return []netip.Addr{netip.MustParseAddr("140.82.112.3")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		case "localhost":
			return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	})()
	bin, argsFile, _ := fakeGit(t)
	s := &Scanner{WorkDir: t.TempDir(), Git: bin}
	ws2 := tenant.WithWorkspace(context.Background(), 2)
	for _, u := range []string{
		"https://127.0.0.1/a/b", "https://[::1]/a/b", "https://localhost/a/b", "https://10.0.0.5/a/b",
		"https://169.254.169.254/latest/meta-data", "https://[fd00:ec2::254]/a", "https://[fe80::1%25eth0]/a/b",
		"https://[::ffff:127.0.0.1]/a/b", "https://100.64.0.1/a/b", "https://metadata.attacker.example/a/b",
		"https://2130706433/a/b", "https://0x7f000001/a/b",
	} {
		os.Remove(argsFile)
		_, err := s.Scan(ws2, Config{URL: u}, "")
		if err == nil || !(errors.Is(err, netguard.ErrBlocked) || errors.Is(err, netguard.ErrAmbiguousHost)) {
			t.Errorf("%s: %v", u, err)
		}
		if _, statErr := os.Stat(argsFile); statErr == nil {
			t.Errorf("%s: git ran", u)
		}
	}

	// A rebinding name is resolved once and git is pinned to that answer,
	// so a second, internal answer is never used.
	os.Remove(argsFile)
	_, _ = s.Scan(ws2, Config{URL: "https://rebind.attacker.example/a/b"}, "")
	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal("git did not run for a public answer")
	}
	if !strings.Contains(string(args), "http.curloptResolve=rebind.attacker.example:443:140.82.112.3") {
		t.Errorf("git was not pinned to the checked address:\n%s", args)
	}
	if lookups.Load() != 1 {
		t.Errorf("the name was resolved %d times", lookups.Load())
	}
}

// TestCloneHardening checks what git is told: only https, no redirects,
// hooks, symlinks or LFS, the URL after "--", and the credential only in
// the environment and never in arguments or errors.
func TestCloneHardening(t *testing.T) {
	defer netguard.SetResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("140.82.112.3")}, nil
	})()
	bin, argsFile, envFile := fakeGit(t)
	s := &Scanner{WorkDir: t.TempDir(), Git: bin}
	const token = "ghp_S3cretTokenValue1234567890"
	_, err := s.Scan(tenant.WithWorkspace(context.Background(), 2), Config{URL: "https://github.com/acme/shop.git", Ref: "main"}, token)
	if err == nil {
		t.Fatal("the fake git fails")
	}
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), basic) || strings.Contains(err.Error(), strings.TrimRight(basic, "=")) {
		t.Errorf("credential in error: %v", err)
	}
	argsB, _ := os.ReadFile(argsFile)
	args := string(argsB)
	for _, want := range []string{"protocol.allow=never", "protocol.https.allow=always", "http.followRedirects=false",
		"core.hooksPath=/dev/null", "core.symlinks=false", "filter.lfs.smudge=", "--no-recurse-submodules", "--depth\n1",
		"--\nhttps://github.com/acme/shop.git\n"} {
		if !strings.Contains(args, want) {
			t.Errorf("git arguments lack %q:\n%s", want, args)
		}
	}
	if strings.Contains(args, token) || strings.Contains(args, basic) {
		t.Error("credential passed as an argument (visible in the process list)")
	}
	envB, _ := os.ReadFile(envFile)
	env := string(envB)
	if !strings.Contains(env, "GIT_CONFIG_VALUE_0=Authorization: Basic "+basic) {
		t.Error("credential not passed through the environment")
	}
	for _, bad := range []string{"STACKURITY_", "DATABASE_URL", "HTTPS_PROXY", "GIT_SSH"} {
		if strings.Contains(env, bad) {
			t.Errorf("git inherited %s", bad)
		}
	}
	if !strings.Contains(env, "GIT_CONFIG_NOSYSTEM=1") || !strings.Contains(env, "GIT_TERMINAL_PROMPT=0") {
		t.Errorf("git environment not locked down:\n%s", env)
	}
}
