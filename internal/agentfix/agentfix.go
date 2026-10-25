// Package agentfix applies approved package upgrades on a host. It is only
// active when the agent runs with --remediate, and it refuses anything not
// also allowed by a local allowlist file, so a compromised server cannot
// widen what the agent changes.
//
// Every change: validate -> confirm the package is installed -> dry run ->
// apply through the package manager (which verifies repository signatures;
// no flag that weakens verification is ever passed) -> health checks.
package agentfix

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"time"
)

type Action struct {
	ID          int64    `json:"id"`
	Kind        string   `json:"kind"` // package_upgrade, package_rollback
	Package     string   `json:"package"`
	Manager     string   `json:"manager"` // apt, dnf, yum, zypper, apk
	FromVersion string   `json:"from_version"`
	ToVersion   string   `json:"to_version"`
	HealthUnits []string `json:"health_units"`
}

type Report struct {
	Phase  string            `json:"phase"` // applied, failed
	DryRun string            `json:"dry_run"`
	Output string            `json:"output"`
	Error  string            `json:"error"`
	Health map[string]string `json:"health"`
}

// Runner executes a command without a shell. Tests replace it.
type Runner func(ctx context.Context, env []string, name string, args ...string) (string, error)

func execRunner(ctx context.Context, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// clip shortens command output for the report. Dry runs are parsed from the
// full output, never from a clipped copy.
func clip(s string) string {
	if len(s) > 16000 {
		s = s[:8000] + "\n…\n" + s[len(s)-8000:]
	}
	return s
}

type Fixer struct {
	Allow     []string // package globs from the local allowlist
	Run       Runner
	Installed func(pkg string) (string, bool) // current version from the package DB
	Timeout   time.Duration
}

// LoadAllowlist reads one package glob per line (# comments allowed). An
// empty or missing file allows nothing.
func LoadAllowlist(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := path.Match(line, "x"); err != nil {
			return nil, fmt.Errorf("invalid pattern %q", line)
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func New(allow []string) *Fixer {
	return &Fixer{Allow: allow, Run: execRunner, Timeout: 20 * time.Minute}
}

// Strict shapes for anything that reaches a command line.
var (
	pkgRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{0,127}$`)
	// No trailing '-' or '+': apt treats "pkg=ver-" as "remove pkg".
	verRE     = regexp.MustCompile(`^[0-9]([A-Za-z0-9.+~:_-]{0,126}[A-Za-z0-9~_.])?$`)
	unitRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:-]{0,127}$`)
	managerOK = map[string]bool{"apt": true, "dnf": true, "yum": true, "zypper": true, "apk": true}
	// yum and zypper get version-release (rpm allows neither '-' nor ':'
	// inside either part) after an optional numeric epoch.
	rpmVerRE = regexp.MustCompile(`^([0-9]+:)?[A-Za-z0-9._+~]+-[A-Za-z0-9._+~]+$`)
)

func (f *Fixer) Validate(a Action) error {
	if a.Kind != "package_upgrade" && a.Kind != "package_rollback" {
		return fmt.Errorf("unsupported action kind %q", a.Kind)
	}
	if !managerOK[a.Manager] {
		return fmt.Errorf("unsupported package manager %q", a.Manager)
	}
	if !pkgRE.MatchString(a.Package) {
		return fmt.Errorf("refusing package name %q", a.Package)
	}
	if !verRE.MatchString(a.ToVersion) || (a.FromVersion != "" && !verRE.MatchString(a.FromVersion)) {
		return fmt.Errorf("refusing version %q", a.ToVersion)
	}
	if a.Manager == "yum" || a.Manager == "zypper" {
		if !rpmVerRE.MatchString(a.ToVersion) || (a.FromVersion != "" && !rpmVerRE.MatchString(a.FromVersion)) {
			return fmt.Errorf("refusing version %q: %s needs [epoch:]version-release", a.ToVersion, a.Manager)
		}
	}
	for _, u := range a.HealthUnits {
		if !unitRE.MatchString(u) {
			return fmt.Errorf("refusing unit name %q", u)
		}
	}
	allowed := false
	for _, g := range f.Allow {
		if ok, _ := path.Match(g, a.Package); ok {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("package %q is not in the local remediation allowlist", a.Package)
	}
	if f.Installed != nil {
		cur, ok := f.Installed(a.Package)
		if !ok {
			return fmt.Errorf("package %q is not installed; refusing to install new software", a.Package)
		}
		if a.FromVersion != "" && !sameVersion(a.Manager, cur, a.FromVersion) && !sameVersion(a.Manager, cur, a.ToVersion) {
			return fmt.Errorf("installed version %s differs from the planned %s; refusing a stale plan", cur, a.FromVersion)
		}
	}
	return nil
}

// spec renders the package manager's "package at version" argument.
func spec(manager, pkg, ver string) string {
	switch manager {
	case "apt", "apk":
		return pkg + "=" + ver
	case "dnf":
		// dnf takes name-[epoch:]version-release
		return pkg + "-" + ver
	case "yum":
		// yum does not match "name-epoch:version-release", so it gets the
		// version without its epoch; the dry run check then confirms the
		// full epoch:version-release that would be installed.
		return pkg + "-" + stripEpoch(ver)
	case "zypper":
		// zypper needs the epoch when it is not zero ("name=1:2.0-3"
		// finds no package with epoch 1 if the epoch is left out).
		return pkg + "=" + ver
	}
	return pkg
}

// sameVersion compares two installed or planned versions. rpm treats a
// missing epoch as 0, and inventory leaves out a zero epoch that advisories
// spell out ("0:1.2-3").
func sameVersion(manager, a, b string) bool {
	if manager == "dnf" || manager == "yum" || manager == "zypper" {
		return withEpoch(a) == withEpoch(b)
	}
	return a == b
}

func (f *Fixer) commands(a Action) (dry, apply [][]string, env []string) {
	s := spec(a.Manager, a.Package, a.ToVersion)
	switch a.Manager {
	case "apt":
		env = []string{"DEBIAN_FRONTEND=noninteractive"}
		dry = [][]string{{"apt-get", "update", "-q"}, {"apt-get", "install", "-s", "-q", "-y", "--only-upgrade", "--no-install-recommends", s}}
		verb := []string{"apt-get", "install", "-q", "-y", "--only-upgrade", "--no-install-recommends",
			"-o", "Dpkg::Options::=--force-confold", "-o", "Dpkg::Options::=--force-confdef"}
		if a.Kind == "package_rollback" {
			verb = []string{"apt-get", "install", "-q", "-y", "--allow-downgrades", "--no-install-recommends",
				"-o", "Dpkg::Options::=--force-confold", "-o", "Dpkg::Options::=--force-confdef"}
			dry = [][]string{{"apt-get", "install", "-s", "-q", "-y", "--allow-downgrades", s}}
		}
		apply = [][]string{append(verb, s)}
	case "dnf":
		if a.Kind == "package_rollback" {
			dry = [][]string{{"dnf", "downgrade", "--assumeno", "-q", s}}
			apply = [][]string{{"dnf", "downgrade", "-y", "-q", s}}
		} else {
			dry = [][]string{{"dnf", "upgrade", "--assumeno", "-q", s}}
			apply = [][]string{{"dnf", "upgrade", "-y", "-q", s}}
		}
	case "yum":
		// yum (Amazon Linux 2): "upgrade" only changes installed packages,
		// like apt's --only-upgrade, and "downgrade" is the rollback.
		verb := "upgrade"
		if a.Kind == "package_rollback" {
			verb = "downgrade"
		}
		dry = [][]string{{"yum", verb, "--assumeno", s}}
		apply = [][]string{{"yum", verb, "-y", s}}
	case "zypper":
		// The dry run reports in XML so the transaction is read from
		// structured output; the real run prints the usual summary. Without
		// --oldpackage zypper never installs an older version.
		opts := []string{"--no-recommends"}
		if a.Kind == "package_rollback" {
			opts = append(opts, "--oldpackage")
		}
		dry = [][]string{append(append([]string{"zypper", "--non-interactive", "--xmlout", "install", "--dry-run"}, opts...), s)}
		apply = [][]string{append(append([]string{"zypper", "--non-interactive", "install"}, opts...), s)}
	case "apk":
		// "apk add pkg=ver" would pin the version in /etc/apk/world and
		// block later security updates; upgrade the package instead and let
		// the server verify the resulting version.
		dry = [][]string{{"apk", "update", "-q"}, {"apk", "upgrade", "--simulate", a.Package}}
		apply = [][]string{{"apk", "upgrade", a.Package}}
	}
	return dry, apply, env
}

// Apply runs one action end to end and returns the report to send.
func (f *Fixer) Apply(ctx context.Context, a Action) Report {
	r := Report{Health: map[string]string{}}
	if err := f.Validate(a); err != nil {
		r.Phase, r.Error = "failed", err.Error()
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, f.Timeout)
	defer cancel()
	dry, apply, env := f.commands(a)
	var dryOut strings.Builder
	var last string // full output of the final dry run command
	for i, c := range dry {
		out, err := f.Run(ctx, env, c[0], c[1:]...)
		dryOut.WriteString("$ " + strings.Join(c, " ") + "\n" + clip(out) + "\n")
		last = out
		if err := dryRunStatus(a.Manager, i == len(dry)-1, out, err); err != nil {
			r.Phase, r.DryRun, r.Error = "failed", dryOut.String(), "dry run failed: "+err.Error()
			return r
		}
		if a.Manager == "apt" && strings.Contains(out, "Remv ") {
			r.Phase, r.DryRun, r.Error = "failed", dryOut.String(), "dry run shows packages would be removed; refusing"
			return r
		}
	}
	r.DryRun = dryOut.String()
	if err := f.checkTransaction(a, last); err != nil {
		r.Phase, r.Error = "failed", "dry run: "+err.Error()+"; refusing"
		return r
	}
	var out strings.Builder
	for _, c := range apply {
		o, err := f.Run(ctx, env, c[0], c[1:]...)
		out.WriteString("$ " + strings.Join(c, " ") + "\n" + clip(o) + "\n")
		note, err := applyStatus(a.Manager, err)
		if note != "" {
			out.WriteString(note + "\n")
		}
		if err != nil {
			r.Phase, r.Output, r.Error = "failed", out.String(), "apply failed: "+err.Error()
			return r
		}
	}
	r.Output = out.String()
	for _, u := range a.HealthUnits {
		o, _ := f.Run(ctx, nil, "systemctl", "is-active", u)
		state := strings.TrimSpace(o)
		if state == "" {
			state = "unknown"
		}
		r.Health[u] = state
	}
	r.Phase = "applied"
	return r
}

var ErrNoAllowlist = errors.New("remediation needs an allowlist file listing package patterns")
