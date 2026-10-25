//go:build pkgmanagers

// Real dnf, yum and zypper runs, as root inside a throwaway container. Never run
// this on a host you care about: it installs, upgrades and downgrades
// packages. testdata/pkgmanagers.sh builds the binary, prepares the
// containers and runs it.
//
// Environment: STK_PM (dnf, yum or zypper), STK_PKG and STK_OLD, STK_MID,
// STK_NEW (three versions of a real repository package, oldest first, with
// STK_OLD installed), and a "stkdemo" repository holding the packages that
// testdata/pkgmanagers.sh builds.
package agentfix

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// installed mirrors the agent's inventory: epoch:version-release, with a
// zero epoch left out.
func installed(pkg string) (string, bool) {
	out, err := exec.Command("rpm", "-q", "--qf", "%{EPOCH}:%{VERSION}-%{RELEASE}\n", pkg).Output()
	if err != nil {
		return "", false
	}
	v := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	v = strings.TrimPrefix(strings.TrimPrefix(v, "(none):"), "0:")
	return v, true
}

func TestRealPackageManager(t *testing.T) {
	pm := os.Getenv("STK_PM")
	if pm == "" || os.Geteuid() != 0 {
		t.Skip("set STK_PM and run as root in a container (see testdata/pkgmanagers.sh)")
	}
	pkg, old, mid, newest := os.Getenv("STK_PKG"), os.Getenv("STK_OLD"), os.Getenv("STK_MID"), os.Getenv("STK_NEW")
	f := New([]string{pkg, "stk-*"})
	f.Installed = installed
	ctx := context.Background()
	step := func(name string, a Action, wantPhase, wantErr, wantVersion string) {
		t.Helper()
		a.Manager = pm
		before, _ := installed(a.Package)
		r := f.Apply(ctx, a)
		now, _ := installed(a.Package)
		t.Logf("%s: %s %s -> %s: phase=%s error=%q installed %s -> %s", name, a.Kind, a.FromVersion, a.ToVersion, r.Phase, r.Error, before, now)
		if r.Phase != wantPhase || !strings.Contains(r.Error, wantErr) || now != wantVersion {
			t.Errorf("%s: want phase %s, error containing %q, installed %s\ndry run:\n%s\noutput:\n%s", name, wantPhase, wantErr, wantVersion, r.DryRun, r.Output)
		}
	}
	up := func(p, from, to string) Action {
		return Action{Kind: "package_upgrade", Package: p, FromVersion: from, ToVersion: to}
	}
	back := func(p, from, to string) Action {
		return Action{Kind: "package_rollback", Package: p, FromVersion: from, ToVersion: to}
	}

	// A real package with several versions in the distribution's repository.
	step("upgrade", up(pkg, old, mid), "applied", "", mid)
	step("rollback", back(pkg, mid, old), "applied", "", old)
	step("missing version", up(pkg, old, old+".99"), "failed", "", old)
	step("upgrade to a newer version", up(pkg, old, newest), "applied", "", newest)
	step("repeat (already there)", up(pkg, old, newest), "applied", "", newest)
	step("upgrade that is a downgrade", up(pkg, newest, mid), "failed", "", newest)
	step("rollback that is an upgrade", back(pkg, "", "999:1-1"), "failed", "", newest)

	// Built test packages: stk-demo has epoch 1; 1.0-3 obsoletes
	// stk-victim; 1.0-4 comes from another vendor; stk-needy (installed
	// late) requires stk-demo 1.0-2 exactly.
	step("epoch upgrade", up("stk-demo", "1:1.0-1", "1:1.0-2"), "applied", "", "1:1.0-2")
	step("upgrade that removes a package", up("stk-demo", "1:1.0-2", "1:1.0-3"), "failed", "", "1:1.0-2")
	if v, ok := installed("stk-victim"); !ok {
		t.Errorf("stk-victim was removed (%s)", v)
	}
	if pm != "yum" { // yum 3 has no notion of vendor changes
		step("vendor change", up("stk-demo", "1:1.0-2", "1:1.0-4"), "failed", "", "1:1.0-2")
	}
	install := map[string][]string{"dnf": {"dnf", "-y", "install", "stk-needy"}, "yum": {"yum", "-y", "install", "stk-needy"}, "zypper": {"zypper", "--non-interactive", "install", "stk-needy"}}[pm]
	if out, err := exec.Command(install[0], install[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("install stk-needy: %v\n%s", err, out)
	}
	step("rollback that breaks a dependent", back("stk-demo", "1:1.0-2", "1:1.0-1"), "failed", "", "1:1.0-2")
	if _, ok := installed("stk-needy"); !ok {
		t.Error("stk-needy was removed")
	}
}
