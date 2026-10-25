package agentfix

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// yum (Amazon Linux 2) and zypper (SUSE) dry runs are read, not just run:
// the change goes ahead only when the dry run shows the requested package
// at exactly the planned version and nothing removed, replaced or moved to
// another vendor or architecture. Output that cannot be read is refused.

// stripEpoch turns "2:1.26-35" into "1.26-35".
func stripEpoch(v string) string {
	if e, rest, ok := strings.Cut(v, ":"); ok && e != "" && strings.Trim(e, "0123456789") == "" {
		return rest
	}
	return v
}

// withEpoch turns "1.26-35" into "0:1.26-35", so versions with and without
// an explicit zero epoch compare equal.
func withEpoch(v string) string {
	if stripEpoch(v) == v {
		return "0:" + v
	}
	return v
}

func exitCode(err error) int {
	var ec interface{ ExitCode() int }
	if errors.As(err, &ec) {
		return ec.ExitCode()
	}
	return -1
}

// zypperExit explains zypper's exit codes (zypper(8), EXIT CODES).
var zypperExit = map[int]string{
	1:   "unexpected zypper error",
	2:   "zypper rejected the command syntax",
	3:   "zypper rejected the arguments",
	4:   "libzypp reported a problem, such as a dependency conflict that needs a manual decision",
	5:   "insufficient privileges",
	6:   "no repositories are defined",
	7:   "package management is locked by another process",
	8:   "the rpm transaction failed",
	100: "zypper reported pending updates instead of acting",
	101: "zypper reported pending security updates instead of acting",
	102: "a reboot is needed to complete the update",
	103: "zypper updated itself and must be run again",
	104: "the requested package or version was not found in the enabled repositories",
	105: "zypper was interrupted by a signal",
	106: "some repositories were skipped because of errors, so not every candidate was considered",
	107: "the packages were installed but an RPM scriptlet failed",
}

func zypperError(code int) error {
	if m, ok := zypperExit[code]; ok {
		return fmt.Errorf("zypper exit %d: %s", code, m)
	}
	return fmt.Errorf("zypper exit %d", code)
}

// dryRunStatus decides whether a dry run command's exit status means it
// worked. What the transaction would do is checked separately.
func dryRunStatus(manager string, last bool, out string, err error) error {
	if err == nil {
		return nil
	}
	switch manager {
	case "dnf":
		// "dnf --assumeno" exits non-zero by design after printing the plan.
		if last && strings.Contains(out, "Operation aborted") {
			return nil
		}
	case "yum":
		// So does "yum --assumeno" (exit 1), after printing the transaction.
		if last && exitCode(err) == 1 && strings.Contains(out, "Exiting on user command") {
			return nil
		}
		if l := firstLineWith(out, "Error:"); l != "" {
			return fmt.Errorf("%v (%s)", err, l)
		}
	case "zypper":
		return zypperError(exitCode(err))
	}
	return err
}

// applyStatus decides whether the real run worked. zypper's 102 means
// success with a reboot needed; every other non-zero exit is a failure
// (107: installed, but a scriptlet failed, so the host needs a look).
func applyStatus(manager string, err error) (note string, _ error) {
	if err == nil {
		return "", nil
	}
	if manager == "zypper" {
		code := exitCode(err)
		if code == 102 {
			return "zypper exit 102: " + zypperExit[102], nil
		}
		return "", zypperError(code)
	}
	return "", err
}

// checkTransaction reads the final dry run's output. Managers without a
// parser here (apt, dnf, apk) are checked in Apply as before.
func (f *Fixer) checkTransaction(a Action, out string) error {
	at := false
	if f.Installed != nil {
		cur, ok := f.Installed(a.Package)
		at = ok && sameVersion(a.Manager, cur, a.ToVersion)
	}
	switch a.Manager {
	case "yum":
		removeSavedYumTransaction(out)
		return checkYum(a, out, at)
	case "zypper":
		return checkZypper(a, out, at)
	}
	return nil
}

// What a transaction may contain besides the requested package: new
// dependencies, and changes in the same direction as the request.
type txRules struct {
	primary string          // section/list that must hold the requested package
	allowed map[string]bool // every section/list that may appear
}

func rulesFor(manager, kind string) txRules {
	up := kind == "package_upgrade"
	switch {
	case manager == "yum" && up:
		return txRules{"Updating", map[string]bool{"Updating": true, "Updating for dependencies": true, "Installing for dependencies": true}}
	case manager == "yum":
		return txRules{"Downgrading", map[string]bool{"Downgrading": true, "Installing for dependencies": true}}
	case up:
		return txRules{"to-upgrade", map[string]bool{"to-upgrade": true, "to-install": true}}
	default:
		return txRules{"to-downgrade", map[string]bool{"to-downgrade": true, "to-install": true}}
	}
}

type txEntry struct{ group, name, version string }

// checkEntries applies the rules shared by yum and zypper.
func checkEntries(a Action, r txRules, entries []txEntry) error {
	removed, other := map[string][]string{}, map[string][]string{}
	found := false
	for _, e := range entries {
		switch {
		case strings.HasPrefix(e.group, "Removing") || strings.HasPrefix(e.group, "Erasing") || e.group == "to-remove":
			removed[e.group] = append(removed[e.group], e.name)
		case !r.allowed[e.group]:
			other[e.group] = append(other[e.group], e.name)
		case e.name == a.Package:
			if e.group != r.primary || !sameVersion(a.Manager, e.version, a.ToVersion) {
				return fmt.Errorf("%s would get %s (%s), not %s", a.Package, e.version, e.group, a.ToVersion)
			}
			found = true
		}
	}
	if len(removed) > 0 {
		return fmt.Errorf("packages would be removed (%s)", describe(removed))
	}
	if len(other) > 0 {
		return fmt.Errorf("unexpected changes (%s)", describe(other))
	}
	if !found {
		return fmt.Errorf("the transaction does not change %s to %s", a.Package, a.ToVersion)
	}
	return nil
}

func describe(m map[string][]string) string {
	var parts []string
	for g, names := range m {
		parts = append(parts, g+": "+strings.Join(names, " "))
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// --- yum

var yumSavedTx = regexp.MustCompile(`(?m)^\s*yum load-transaction (/tmp/yum_save_tx\.[A-Za-z0-9._-]+\.yumtx)\s*$`)

// removeSavedYumTransaction deletes the file "yum --assumeno" saves for a
// later "yum load-transaction", so dry runs do not pile up in /tmp.
func removeSavedYumTransaction(out string) {
	if m := yumSavedTx.FindStringSubmatch(out); m != nil {
		_ = os.Remove(m[1])
	}
}

// "---> Package tar.aarch64 2:1.26-35.amzn2.0.3 will be an update"
var yumCheckLine = regexp.MustCompile(`(?m)^-+> Package (\S+)\.[^.\s]+ (\S+) will be (.+)$`)

var yumNothing = []string{"Nothing to do", "No packages marked for update"}
var yumMissing = []string{"No Match for argument", "No package ", "available, but not installed", "Error:"}

func checkYum(a Action, out string, alreadyAt bool) error {
	entries, verbs, replacing, ok, err := parseYum(out)
	if err != nil {
		return err
	}
	if !ok {
		for _, m := range yumMissing {
			if strings.Contains(out, m) {
				return fmt.Errorf("yum cannot %s %s to %s (%q)", verb(a), a.Package, a.ToVersion, firstLineWith(out, m))
			}
		}
		for _, m := range yumNothing {
			if strings.Contains(out, m) && alreadyAt {
				return nil
			}
			if strings.Contains(out, m) {
				return fmt.Errorf("yum has nothing to do although %s is not at %s", a.Package, a.ToVersion)
			}
		}
		return errors.New("no transaction summary in the yum output")
	}
	if replacing {
		return errors.New("installed packages would be replaced (obsoleted)")
	}
	for _, v := range verbs {
		switch v {
		case "Remove", "Erase":
			return errors.New("packages would be removed (transaction summary)")
		case "Install":
		case "Upgrade":
			if a.Kind != "package_upgrade" {
				return errors.New("a rollback would upgrade packages")
			}
		case "Downgrade":
			if a.Kind != "package_rollback" {
				return errors.New("an upgrade would downgrade packages")
			}
		default:
			return fmt.Errorf("unexpected transaction summary entry %q", v)
		}
	}
	// The table leaves out packages that are obsoleted, so the dependency
	// resolution lines are read too.
	for _, m := range yumCheckLine.FindAllStringSubmatch(out, -1) {
		name, what := m[1], strings.TrimSpace(m[3])
		switch {
		case what == "obsoleted" || what == "obsoleting":
			return fmt.Errorf("installed packages would be replaced (%s will be %s)", name, what)
		case what == "erased" && (name != a.Package || a.Kind != "package_rollback"):
			return fmt.Errorf("packages would be removed (%s)", name)
		case what == "erased", what == "updated", what == "an update", what == "installed", what == "a downgrade":
		default:
			return fmt.Errorf("unexpected yum resolution %q for %s", what, name)
		}
	}
	return checkEntries(a, rulesFor("yum", a.Kind), entries)
}

func verb(a Action) string {
	if a.Kind == "package_rollback" {
		return "downgrade"
	}
	return "upgrade"
}

func firstLineWith(out, s string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, s) {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

// parseYum reads yum 3's transaction table:
//
//	 Package    Arch     Version              Repository   Size
//	=========================================================
//	Updating:
//	 tar        aarch64  2:1.26-35.amzn2.0.3  amzn2-core   851 k
//
//	Transaction Summary
//	=========================================================
//	Upgrade  1 Package
//
// ok is false when there is no transaction at all. Any line it cannot place
// is an error.
func parseYum(out string) (entries []txEntry, verbs []string, replacing, ok bool, err error) {
	lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
	summary := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == "Transaction Summary" {
			summary = i
			break
		}
	}
	if summary < 0 {
		return nil, nil, false, false, nil
	}
	start := -1
	for i := 0; i+1 < summary; i++ {
		f := strings.Fields(lines[i])
		if len(f) >= 3 && f[0] == "Package" && f[1] == "Arch" && f[2] == "Version" && strings.HasPrefix(lines[i+1], "===") {
			start = i + 2
			break
		}
	}
	if start < 0 {
		return nil, nil, false, true, errors.New("cannot find the yum transaction table")
	}
	section, pending := "", ""
	for _, l := range lines[start:summary] {
		t := strings.TrimSpace(l)
		switch {
		case t == "" || strings.HasPrefix(t, "==="):
			continue
		case !strings.HasPrefix(l, " "):
			if !strings.HasSuffix(t, ":") || pending != "" {
				return nil, nil, false, true, fmt.Errorf("unexpected line in the yum transaction table: %q", t)
			}
			section = strings.TrimSuffix(t, ":")
			continue
		}
		f := strings.Fields(l)
		if section == "" {
			return nil, nil, false, true, fmt.Errorf("package outside a section in the yum transaction table: %q", t)
		}
		if f[0] == "replacing" {
			replacing = true
			continue
		}
		if pending != "" {
			f = append([]string{pending}, f...)
			pending = ""
		} else if len(f) == 2 && strings.Trim(f[0], "0123456789.") == "" && (f[1] == "k" || f[1] == "M" || f[1] == "G") {
			continue // the size column wrapped onto its own line
		}
		if len(f) == 1 {
			pending = f[0] // a long name wraps; the rest follows on the next line
			continue
		}
		if len(f) < 4 {
			return nil, nil, false, true, fmt.Errorf("unreadable row in the yum transaction table: %q", t)
		}
		entries = append(entries, txEntry{group: section, name: f[0], version: f[2]})
	}
	if pending != "" {
		return nil, nil, false, true, fmt.Errorf("unreadable row in the yum transaction table: %q", pending)
	}
	i := summary + 1
	if i < len(lines) && strings.HasPrefix(lines[i], "===") {
		i++
	}
	for ; i < len(lines) && strings.TrimSpace(lines[i]) != ""; i++ {
		verbs = append(verbs, strings.Fields(lines[i])[0])
	}
	if len(entries) == 0 || len(verbs) == 0 {
		return nil, nil, false, true, errors.New("empty yum transaction")
	}
	return entries, verbs, replacing, true, nil
}

// --- zypper

// zypperStream is the part of "zypper --xmlout install --dry-run" output
// that is read. Every list in the summary is kept under its element name.
type zypperStream struct {
	Messages []struct {
		Type string `xml:"type,attr"`
		Text string `xml:",chardata"`
	} `xml:"message"`
	Summaries []struct {
		Lists []struct {
			XMLName   xml.Name
			Solvables []struct {
				Type    string `xml:"type,attr"`
				Name    string `xml:"name,attr"`
				Edition string `xml:"edition,attr"`
			} `xml:"solvable"`
		} `xml:",any"`
	} `xml:"install-summary"`
}

func checkZypper(a Action, out string, alreadyAt bool) error {
	i := strings.Index(out, "<stream>")
	if i < 0 {
		return errors.New("no XML in the zypper output")
	}
	var st zypperStream
	if err := xml.NewDecoder(strings.NewReader(out[i:])).Decode(&st); err != nil {
		return fmt.Errorf("cannot read the zypper output: %v", err)
	}
	for _, m := range st.Messages {
		if m.Type == "error" {
			return fmt.Errorf("zypper: %s", strings.TrimSpace(m.Text))
		}
	}
	if len(st.Summaries) != 1 {
		return fmt.Errorf("expected one zypper install summary, found %d", len(st.Summaries))
	}
	var entries []txEntry
	for _, l := range st.Summaries[0].Lists {
		for _, s := range l.Solvables {
			if s.Type != "package" {
				return fmt.Errorf("the transaction changes a %s (%s), not only packages", s.Type, s.Name)
			}
			entries = append(entries, txEntry{group: l.XMLName.Local, name: s.Name, version: s.Edition})
		}
	}
	if len(entries) == 0 {
		if alreadyAt {
			return nil
		}
		why := ""
		for _, m := range st.Messages {
			if t := strings.TrimSpace(m.Text); strings.Contains(t, a.Package) {
				why = " (" + t + ")"
				break
			}
		}
		return fmt.Errorf("zypper has nothing to do although %s is not at %s%s", a.Package, a.ToVersion, why)
	}
	changes := map[string][]string{}
	for _, e := range entries {
		switch e.group {
		case "to-change-vendor":
			changes["vendor"] = append(changes["vendor"], e.name)
		case "to-change-arch":
			changes["architecture"] = append(changes["architecture"], e.name)
		}
	}
	if len(changes) > 0 {
		return fmt.Errorf("packages would change %s", describe(changes))
	}
	return checkEntries(a, rulesFor("zypper", a.Kind), entries)
}
