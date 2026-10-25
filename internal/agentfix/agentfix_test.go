package agentfix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type call struct {
	env  []string
	argv []string
}

func fake(responses map[string]string, fail map[string]bool) (Runner, *[]call) {
	var calls []call
	return func(ctx context.Context, env []string, name string, args ...string) (string, error) {
		argv := append([]string{name}, args...)
		calls = append(calls, call{env, argv})
		key := strings.Join(argv, " ")
		for prefix, out := range responses {
			if strings.HasPrefix(key, prefix) {
				if fail[prefix] {
					return out, errors.New("exit status 1")
				}
				return out, nil
			}
		}
		return "", nil
	}, &calls
}

func fixer(allow ...string) *Fixer {
	f := New(allow)
	f.Installed = func(pkg string) (string, bool) {
		v, ok := map[string]string{"libssl3": "3.0.11-1~deb12u1", "nginx": "1.22.1-9"}[pkg]
		return v, ok
	}
	return f
}

var upgrade = Action{ID: 1, Kind: "package_upgrade", Package: "libssl3", Manager: "apt", FromVersion: "3.0.11-1~deb12u1",
	ToVersion: "3.0.11-1~deb12u2", HealthUnits: []string{"nginx.service"}}

func TestApplyAptHappyPath(t *testing.T) {
	f := fixer("libssl*")
	run, calls := fake(map[string]string{"apt-get install -s": "Inst libssl3 [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security)",
		"systemctl is-active": "active\n"}, nil)
	f.Run = run
	r := f.Apply(context.Background(), upgrade)
	if r.Phase != "applied" || r.Health["nginx.service"] != "active" {
		t.Fatalf("report = %+v", r)
	}
	var cmds []string
	for _, c := range *calls {
		cmds = append(cmds, strings.Join(c.argv, " "))
	}
	all := strings.Join(cmds, "\n")
	if !strings.Contains(all, "apt-get install -s -q -y --only-upgrade --no-install-recommends libssl3=3.0.11-1~deb12u2") {
		t.Errorf("dry run missing:\n%s", all)
	}
	if !strings.Contains(all, "--only-upgrade") || strings.Contains(all, "--allow-unauthenticated") || strings.Contains(all, "--force-yes") {
		t.Errorf("unsafe or missing flags:\n%s", all)
	}
	for _, c := range *calls {
		for _, a := range c.argv {
			if strings.ContainsAny(a, ";|&$`") {
				t.Errorf("shell metacharacter reached argv: %q", a)
			}
		}
	}
}

func TestRefusals(t *testing.T) {
	f := fixer("libssl*", "nginx")
	cases := map[string]Action{
		"not allowlisted":  {Kind: "package_upgrade", Package: "bash", Manager: "apt", ToVersion: "5.2"},
		"injection name":   {Kind: "package_upgrade", Package: "libssl3; rm -rf /", Manager: "apt", ToVersion: "1"},
		"option name":      {Kind: "package_upgrade", Package: "-oDebug=1", Manager: "apt", ToVersion: "1"},
		"injection ver":    {Kind: "package_upgrade", Package: "libssl3", Manager: "apt", ToVersion: "1 --allow-unauthenticated"},
		"bad manager":      {Kind: "package_upgrade", Package: "libssl3", Manager: "sh", ToVersion: "1"},
		"bad unit":         {Kind: "package_upgrade", Package: "libssl3", Manager: "apt", ToVersion: "3.0.11-1~deb12u2", HealthUnits: []string{"x;reboot"}},
		"not installed":    {Kind: "package_upgrade", Package: "libssl1.1", Manager: "apt", ToVersion: "1.1.1w"},
		"stale plan":       {Kind: "package_upgrade", Package: "nginx", Manager: "apt", FromVersion: "1.18.0-6", ToVersion: "1.22.1-9+deb12u1"},
		"unknown kind":     {Kind: "run_script", Package: "nginx", Manager: "apt", ToVersion: "1"},
		"apt remove trick": {Kind: "package_rollback", Package: "libssl3", Manager: "apt", ToVersion: "1.0-"},
		"trailing plus":    {Kind: "package_rollback", Package: "libssl3", Manager: "apt", ToVersion: "1.0+"},
	}
	for name, a := range cases {
		run, calls := fake(nil, nil)
		f.Run = run
		r := f.Apply(context.Background(), a)
		if r.Phase != "failed" || len(*calls) != 0 {
			t.Errorf("%s: phase=%s calls=%d err=%s", name, r.Phase, len(*calls), r.Error)
		}
	}
}

func TestDryRunRemovalsAreRefused(t *testing.T) {
	f := fixer("libssl*")
	run, calls := fake(map[string]string{"apt-get install -s": "Remv openssh-server [1:9.2p1-2]\nInst libssl3"}, nil)
	f.Run = run
	r := f.Apply(context.Background(), upgrade)
	if r.Phase != "failed" || !strings.Contains(r.Error, "removed") {
		t.Fatalf("report = %+v", r)
	}
	for _, c := range *calls {
		if c.argv[0] == "apt-get" && c.argv[1] == "install" && c.argv[2] != "-s" {
			t.Fatal("apply ran despite removals in dry run")
		}
	}
}

func TestDryRunFailureStops(t *testing.T) {
	f := fixer("libssl*")
	run, calls := fake(map[string]string{"apt-get install -s": "E: Version '3.0.11-1~deb12u2' for 'libssl3' was not found"},
		map[string]bool{"apt-get install -s": true})
	f.Run = run
	if r := f.Apply(context.Background(), upgrade); r.Phase != "failed" || !strings.Contains(r.DryRun, "not found") {
		t.Fatalf("report = %+v", r)
	}
	if n := len(*calls); n != 2 {
		t.Errorf("expected update + dry run only, got %d calls", n)
	}
}

func TestDnfAndApkCommands(t *testing.T) {
	f := fixer("openssl*", "musl")
	f.Installed = nil
	run, calls := fake(map[string]string{"dnf upgrade --assumeno": "Operation aborted."}, map[string]bool{"dnf upgrade --assumeno": true})
	f.Run = run
	r := f.Apply(context.Background(), Action{Kind: "package_upgrade", Package: "openssl-libs", Manager: "dnf", ToVersion: "1:3.0.7-25.el9"})
	if r.Phase != "applied" {
		t.Fatalf("dnf: %+v", r)
	}
	last := (*calls)[len(*calls)-1].argv
	if strings.Join(last, " ") != "dnf upgrade -y -q openssl-libs-1:3.0.7-25.el9" {
		t.Errorf("dnf apply = %v", last)
	}
	run, calls = fake(nil, nil)
	f.Run = run
	f.Apply(context.Background(), Action{Kind: "package_upgrade", Package: "musl", Manager: "apk", ToVersion: "1.2.4_git20230717-r5"})
	if got := strings.Join((*calls)[len(*calls)-1].argv, " "); got != "apk upgrade musl" {
		t.Errorf("apk apply = %s", got)
	}
}

func TestAllowlistFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "allow")
	_ = os.WriteFile(p, []byte("# security packages\nlibssl*\nopenssl\n\n"), 0o600)
	got, err := LoadAllowlist(p)
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	_ = os.WriteFile(p, []byte("[bad\n"), 0o600)
	if _, err := LoadAllowlist(p); err == nil {
		t.Error("invalid glob accepted")
	}
}

func TestRollbackRefusesRemovals(t *testing.T) {
	f := fixer("libssl*")
	run, _ := fake(map[string]string{"apt-get install -s": "Remv openssh-server [1:9.2p1-2]"}, nil)
	f.Run = run
	r := f.Apply(context.Background(), Action{Kind: "package_rollback", Package: "libssl3", Manager: "apt", ToVersion: "3.0.11-1~deb12u1"})
	if r.Phase != "failed" || !strings.Contains(r.Error, "removed") {
		t.Fatalf("rollback with removals = %+v", r)
	}
}
