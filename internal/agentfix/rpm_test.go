package agentfix

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Outputs in testdata were captured from yum 3.4.3 (Amazon Linux 2) and
// zypper 1.14.76 (openSUSE Leap 15.5); see testdata/pkgmanagers.sh.
func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("exit status %d", int(e)) }
func (e exitStatus) ExitCode() int { return int(e) }

type reply struct {
	out  string
	code int
}

// fakeExit answers by command prefix with output and an exit code.
func fakeExit(responses map[string]reply) (Runner, *[]string) {
	var calls []string
	return func(ctx context.Context, env []string, name string, args ...string) (string, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		calls = append(calls, key)
		for prefix, r := range responses {
			if strings.HasPrefix(key, prefix) {
				if r.code != 0 {
					return r.out, exitStatus(r.code)
				}
				return r.out, nil
			}
		}
		return "", nil
	}, &calls
}

func rpmFixer(versions map[string]string) *Fixer {
	f := New([]string{"tar", "less", "stk-*"})
	f.Installed = func(pkg string) (string, bool) { v, ok := versions[pkg]; return v, ok }
	return f
}

func applied(calls []string, prefix string) bool {
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func TestYum(t *testing.T) {
	f := rpmFixer(map[string]string{"tar": "2:1.26-35.amzn2.0.2", "stk-demo": "1:1.0-2"})
	up := Action{Kind: "package_upgrade", Package: "tar", Manager: "yum", FromVersion: "2:1.26-35.amzn2.0.2", ToVersion: "2:1.26-35.amzn2.0.3"}

	run, calls := fakeExit(map[string]reply{"yum upgrade --assumeno": {fixture(t, "yum-upgrade.txt"), 1}})
	f.Run = run
	if r := f.Apply(context.Background(), up); r.Phase != "applied" {
		t.Fatalf("upgrade: %+v", r)
	}
	want := []string{"yum upgrade --assumeno tar-1.26-35.amzn2.0.3", "yum upgrade -y tar-1.26-35.amzn2.0.3"}
	if strings.Join(*calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("commands = %q", *calls)
	}

	back := Action{Kind: "package_rollback", Package: "tar", Manager: "yum", FromVersion: "2:1.26-35.amzn2.0.2", ToVersion: "2:1.26-35.amzn2.0.1"}
	run, calls = fakeExit(map[string]reply{"yum downgrade --assumeno": {fixture(t, "yum-downgrade.txt"), 1}})
	f.Run = run
	if r := f.Apply(context.Background(), back); r.Phase != "applied" || !applied(*calls, "yum downgrade -y tar-1.26-35.amzn2.0.1") {
		t.Fatalf("rollback: %+v %q", r, *calls)
	}

	refused := map[string]struct {
		a     Action
		out   string
		code  int
		error string
	}{
		"obsoletes": {Action{Kind: "package_upgrade", Package: "stk-demo", Manager: "yum", ToVersion: "1:1.0-3"},
			fixture(t, "yum-obsolete.txt"), 1, "replaced"},
		"downgrade in an upgrade": {up, fixture(t, "yum-downgrade.txt"), 1, "downgrade"},
		"other version":           {Action{Kind: "package_upgrade", Package: "tar", Manager: "yum", ToVersion: "2:1.26-35.amzn2.0.4"}, fixture(t, "yum-upgrade.txt"), 1, "not 2:1.26-35.amzn2.0.4"},
		"wrong epoch":             {Action{Kind: "package_upgrade", Package: "tar", Manager: "yum", ToVersion: "1.26-35.amzn2.0.3"}, fixture(t, "yum-upgrade.txt"), 1, "not 1.26-35.amzn2.0.3"},
		"no match": {up, "Loaded plugins: ovl, priorities\nNo Match for argument: tar-1.26-35.amzn2.0.3\nNo package tar-1.26-35.amzn2.0.3 available.\nNo packages marked for update\n",
			0, "No Match"},
		"nothing to do":      {up, "Loaded plugins: ovl\nNothing to do\n", 0, "nothing to do"},
		"dependency problem": {up, "Error: Package: stk-needy-1.0-1.noarch (@stkdemo)\n           Requires: stk-demo = 1:1.0-2\n", 1, "stk-needy"},
		"unreadable table": {up, strings.Replace(fixture(t, "yum-upgrade.txt"), " tar        aarch64", " tar aarch64 x\nstray", 1), 1,
			"unreadable row"},
		"removal": {up, strings.Replace(fixture(t, "yum-upgrade.txt"), "\nTransaction Summary",
			"Removing for dependencies:\n bash   aarch64   4.2.46-34.amzn2   @amzn2-core   3.5 M\n\nTransaction Summary", 1), 1, "removed"},
		"assumeno without the abort message": {up, fixture(t, "yum-upgrade.txt")[:400], 1, "exit status 1"},
	}
	for name, c := range refused {
		run, calls := fakeExit(map[string]reply{"yum upgrade --assumeno": {c.out, c.code}, "yum downgrade --assumeno": {c.out, c.code}})
		f.Run = run
		r := f.Apply(context.Background(), c.a)
		if r.Phase != "failed" || !strings.Contains(r.Error, c.error) || applied(*calls, "yum upgrade -y") || applied(*calls, "yum downgrade -y") {
			t.Errorf("%s: phase=%s error=%q calls=%q", name, r.Phase, r.Error, *calls)
		}
	}

	// Already at the target (a repeated action): nothing to do is fine.
	f = rpmFixer(map[string]string{"tar": "2:1.26-35.amzn2.0.3"})
	run, _ = fakeExit(map[string]reply{"yum upgrade --assumeno": {"Loaded plugins: ovl\nNothing to do\n", 0}})
	f.Run = run
	if r := f.Apply(context.Background(), up); r.Phase != "applied" {
		t.Errorf("repeat: %+v", r)
	}
}

func TestZypper(t *testing.T) {
	f := rpmFixer(map[string]string{"less": "590-150400.3.3.1", "stk-demo": "1:1.0-2"})
	up := Action{Kind: "package_upgrade", Package: "less", Manager: "zypper", FromVersion: "590-150400.3.3.1", ToVersion: "590-150400.3.6.2"}
	run, calls := fakeExit(map[string]reply{"zypper --non-interactive --xmlout install --dry-run": {fixture(t, "zypper-upgrade.xml"), 0}})
	f.Run = run
	if r := f.Apply(context.Background(), up); r.Phase != "applied" {
		t.Fatalf("upgrade: %+v", r)
	}
	want := []string{"zypper --non-interactive --xmlout install --dry-run --no-recommends less=590-150400.3.6.2",
		"zypper --non-interactive install --no-recommends less=590-150400.3.6.2"}
	if strings.Join(*calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("commands = %q", *calls)
	}

	// Rollback uses --oldpackage and keeps a non-zero epoch.
	down := strings.NewReplacer("to-upgrade>", "to-downgrade>", `edition="590-150400.3.6.2"`, `edition="1:1.0-1"`, `name="less"`, `name="stk-demo"`).
		Replace(fixture(t, "zypper-upgrade.xml"))
	back := Action{Kind: "package_rollback", Package: "stk-demo", Manager: "zypper", FromVersion: "1:1.0-2", ToVersion: "1:1.0-1"}
	run, calls = fakeExit(map[string]reply{"zypper --non-interactive --xmlout": {down, 0}})
	f.Run = run
	if r := f.Apply(context.Background(), back); r.Phase != "applied" ||
		!applied(*calls, "zypper --non-interactive install --no-recommends --oldpackage stk-demo=1:1.0-1") {
		t.Fatalf("rollback: %+v %q", r, *calls)
	}

	// A large transaction is read in full, even though the report is clipped.
	big := strings.Replace(fixture(t, "zypper-upgrade.xml"), "<to-upgrade>",
		"<to-install>"+strings.Repeat(`<solvable type="package" name="dep" edition="1-1"><description>`+strings.Repeat("x", 500)+"</description></solvable>\n", 60)+"</to-install>\n<to-upgrade>", 1)
	run, _ = fakeExit(map[string]reply{"zypper --non-interactive --xmlout": {big, 0}})
	f.Run = run
	if r := f.Apply(context.Background(), up); r.Phase != "applied" || len(r.DryRun) > 17000 {
		t.Errorf("large transaction: phase=%s error=%q dry run %d bytes", r.Phase, r.Error, len(r.DryRun))
	}

	demo := Action{Kind: "package_upgrade", Package: "stk-demo", Manager: "zypper", FromVersion: "1:1.0-2", ToVersion: "1:1.0-3"}
	refused := map[string]struct {
		a     Action
		out   string
		code  int
		error string
	}{
		"removal":        {demo, fixture(t, "zypper-remove.xml"), 0, "removed (to-remove: stk-victim)"},
		"vendor change":  {Action{Kind: "package_upgrade", Package: "stk-demo", Manager: "zypper", ToVersion: "1:1.0-4"}, fixture(t, "zypper-vendor.xml"), 0, "vendor"},
		"other version":  {Action{Kind: "package_upgrade", Package: "less", Manager: "zypper", ToVersion: "590-150400.3.9.1"}, fixture(t, "zypper-upgrade.xml"), 0, "not 590-150400.3.9.1"},
		"downgrade":      {up, strings.ReplaceAll(fixture(t, "zypper-upgrade.xml"), "to-upgrade>", "to-downgrade>"), 0, "unexpected changes (to-downgrade: less)"},
		"unknown list":   {up, strings.ReplaceAll(fixture(t, "zypper-upgrade.xml"), "to-upgrade>", "to-reinstall>"), 0, "unexpected changes"},
		"arch change":    {up, strings.Replace(fixture(t, "zypper-upgrade.xml"), "</install-summary>", `<to-change-arch><solvable type="package" name="less" edition="590-150400.3.6.2"/></to-change-arch></install-summary>`, 1), 0, "architecture"},
		"product":        {up, strings.Replace(fixture(t, "zypper-upgrade.xml"), `type="package"`, `type="product"`, 1), 0, "product"},
		"not found":      {up, "<?xml version='1.0'?>\n<stream>\n</stream>\n", 104, "exit 104"},
		"locked":         {up, "", 7, "locked"},
		"repos skipped":  {up, fixture(t, "zypper-upgrade.xml"), 106, "skipped"},
		"nothing to do":  {up, "<?xml version='1.0'?>\n<stream>\n<install-summary packages-to-change=\"0\">\n</install-summary>\n<message type=\"info\">The selected package 'less-590' has lower version</message></stream>", 0, "nothing to do"},
		"truncated":      {up, fixture(t, "zypper-upgrade.xml")[:900], 0, "cannot read"},
		"not XML":        {up, "Loading repository data...\n", 0, "no XML"},
		"two summaries":  {up, strings.Replace(fixture(t, "zypper-upgrade.xml"), "</stream>", "<install-summary></install-summary></stream>", 1), 0, "one zypper install summary"},
		"error message":  {up, strings.Replace(fixture(t, "zypper-upgrade.xml"), "<install-summary", `<message type="error">Problem: nothing provides x</message><install-summary`, 1), 0, "nothing provides"},
		"no target":      {up, strings.ReplaceAll(fixture(t, "zypper-upgrade.xml"), `name="less"`, `name="lesspipe"`), 0, "does not change less"},
		"version format": {Action{Kind: "package_upgrade", Package: "less", Manager: "zypper", ToVersion: "590"}, "", 0, "version-release"},
	}
	for name, c := range refused {
		run, calls := fakeExit(map[string]reply{"zypper --non-interactive --xmlout": {c.out, c.code}})
		f.Run = run
		r := f.Apply(context.Background(), c.a)
		if r.Phase != "failed" || !strings.Contains(r.Error, c.error) || applied(*calls, "zypper --non-interactive install") {
			t.Errorf("%s: phase=%s error=%q calls=%q", name, r.Phase, r.Error, *calls)
		}
	}

	// Exit codes of the real run: 102 is success with a reboot needed.
	for code, phase := range map[int]string{0: "applied", 102: "applied", 103: "failed", 107: "failed", 8: "failed", 4: "failed"} {
		run, _ := fakeExit(map[string]reply{
			"zypper --non-interactive --xmlout": {fixture(t, "zypper-upgrade.xml"), 0},
			"zypper --non-interactive install":  {"", code}})
		f.Run = run
		r := f.Apply(context.Background(), up)
		if r.Phase != phase || (code == 102 && !strings.Contains(r.Output, "reboot")) {
			t.Errorf("apply exit %d: %+v", code, r)
		}
	}
}

func TestRPMVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{{"1.0-1", "0:1.0-1", true}, {"2:1.0-1", "2:1.0-1", true}, {"1.0-1", "1:1.0-1", false}, {"1.0-1", "1.0-2", false}} {
		if got := sameVersion("zypper", c.a, c.b); got != c.same {
			t.Errorf("sameVersion(%s, %s) = %v", c.a, c.b, got)
		}
	}
	if sameVersion("apt", "1.0-1", "0:1.0-1") {
		t.Error("apt versions are compared as written")
	}
	// Inventory leaves out a zero epoch that advisories spell out; that is
	// not a stale plan.
	f := rpmFixer(map[string]string{"tar": "1.26-35"})
	if err := f.Validate(Action{Kind: "package_upgrade", Package: "tar", Manager: "yum", FromVersion: "0:1.26-35", ToVersion: "0:1.26-36"}); err != nil {
		t.Error(err)
	}
	if err := f.Validate(Action{Kind: "package_upgrade", Package: "tar", Manager: "yum", FromVersion: "1.26-34", ToVersion: "1.26-36"}); err == nil {
		t.Error("stale plan accepted")
	}
	for _, v := range []string{"1.26", "1:2:1.26-3", "1.26-3-4", "a:1.26-3"} {
		if err := f.Validate(Action{Kind: "package_upgrade", Package: "tar", Manager: "yum", ToVersion: v}); err == nil {
			t.Errorf("version %q accepted for yum", v)
		}
	}
}
