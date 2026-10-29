// Package fixplan turns individual findings into actions: "install security
// updates (fixes 1,612 issues)", "upgrade Ubuntu 20.04", "upgrade lodash to
// 4.17.21". People act on the group; the findings stay available for
// anyone who wants the detail.
package fixplan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/version"
)

// Kinds of action, roughly from cheapest to most involved.
const (
	SecurityUpdates = "security_updates" // OS packages with a fix in this release
	WindowsUpdate   = "windows_update"   // a Windows host's latest cumulative update (one KB)
	OldKernels      = "old_kernels"      // installed kernels that are not running
	PackageUpgrade  = "package_upgrade"  // one application dependency
	EndOfLife       = "end_of_life"      // non-OS software past end of life
	ReleaseUpgrade  = "release_upgrade"  // OS end of life + OS issues with no free fix
	NoFix           = "no_fix"           // nothing published yet
)

// Row is one open finding with the context needed to place it.
type Row struct {
	FindingID      int64
	Kind           string // vulnerability, end_of_life
	Key            string
	AssetID        int64
	AssetName      string
	AssetKind      string
	Environment    string
	AppDir         string // deployed application's directory, when the asset is one
	OS             string // os-release ID, e.g. ubuntu
	OSVersion      string
	OSName         string
	ComponentID    int64
	PurlType       string
	Component      string // display name (namespace/name)
	Version        string
	FixedVersion   string
	Priority       string
	Severity       string
	SOS            bool
	KnownExploited bool
	KernelIdle     bool   // not_running_kernel
	RequiresPro    bool   // the only fix is in a paid channel
	Subscription   string // that channel: "Ubuntu Pro", "SUSE LTSS"
	IsOS           bool   // the operating system component itself
	EOLTitle       string // finding title for end_of_life findings
	// Windows updates (evidence of msrc:Windows findings): the update that
	// brings the fixed build ("KB5066782"), its release date, and the month
	// of the oldest update read when the host's build is older than that.
	KB            string
	KBReleased    string
	OlderThanData string
}

type Group struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Title       string `json:"title"`
	Action      string `json:"action"`
	AssetID     int64  `json:"asset_id"`
	AssetName   string `json:"asset_name"`
	AssetKind   string `json:"asset_kind"`
	Environment string `json:"environment"`
	AppDir      string `json:"app_dir,omitempty"`
	// FixKey is the same for groups that make the same change in different
	// places (jquery 3.3.1 → 3.5.0 in two apps), so a list can show them as
	// one fix. Groups that only make sense per asset use their ID.
	FixKey         string         `json:"fix_key"`
	Component      string         `json:"component,omitempty"`
	FromVersion    string         `json:"from_version,omitempty"`
	ToVersion      string         `json:"to_version,omitempty"`
	Packages       []string       `json:"packages"`
	PackageCount   int            `json:"package_count"`
	FindingCount   int            `json:"finding_count"`
	UniqueIssues   int            `json:"unique_issues"` // distinct CVE/advisory keys
	ByPriority     map[string]int `json:"by_priority"`
	BySeverity     map[string]int `json:"by_severity"`
	TopPriority    string         `json:"top_priority"`
	SOS            bool           `json:"sos"`
	KnownExploited int            `json:"known_exploited"`
	Needs          string         `json:"needs,omitempty"`
	Effort         string         `json:"effort"`
	Note           string         `json:"note,omitempty"`
	// Package upgrades: the version to move to, from release data (see
	// internal/upgrade). ToVersion stays the minimum fixed version.
	Recommended string `json:"recommended_version,omitempty"`
	// TargetVersion is the version the title and action name: the
	// recommended version when it is in the same major line as the minimum
	// fix, otherwise the minimum fixed version. Clients show it as the
	// headline and ToVersion as "fixes from".
	TargetVersion     string   `json:"target_version,omitempty"`
	ChangeType        string   `json:"change_type,omitempty"`
	RequiresMajor     bool     `json:"requires_major,omitempty"`
	RecommendedYanked bool     `json:"recommended_yanked,omitempty"`
	Rationale         []string `json:"rationale,omitempty"`
	// Places lists every asset the fix applies to, when groups are merged
	// by FixKey (see Merge); empty for a single asset's group.
	Places       []Place           `json:"places,omitempty"`
	FindingIDs   []int64           `json:"-"`
	pkgs         map[string]bool   `json:"-"`
	purlType     string            `json:"-"`
	fromVersions map[string]bool   `json:"-"`
	extra        map[string]string `json:"-"`
	keys         map[string]bool   `json:"-"`
	kbs          map[string]bool   `json:"-"` // Windows updates the findings were first fixed in
}

// Advice gives the newest supported release of an OS, for release-upgrade
// wording. Keys are "<os-release ID>:<version>", e.g. "ubuntu:20.04".
type Advice struct {
	ProductLabel string // "Ubuntu"
	EOLDate      string // when the installed release ended
	Target       string // suggested release, e.g. "24.04 LTS"
}

func manager(osID, osVersion string) (update, autoremove string) {
	switch osID {
	case "ubuntu", "debian":
		return "sudo apt update && sudo apt upgrade", "sudo apt autoremove --purge"
	case "amzn":
		if osVersion == "2" {
			return "sudo yum update", "sudo package-cleanup --oldkernels --count=1"
		}
		return "sudo dnf upgrade --refresh", "sudo dnf remove --oldinstallonly"
	case "rhel", "centos", "ol":
		if v, _, _ := strings.Cut(osVersion, "."); v == "7" {
			// Release 7 has yum, not dnf.
			return "sudo yum update", "sudo package-cleanup --oldkernels --count=1"
		}
		return "sudo dnf upgrade --refresh", "sudo dnf remove --oldinstallonly"
	case "rocky", "almalinux", "fedora":
		return "sudo dnf upgrade --refresh", "sudo dnf remove --oldinstallonly"
	case "sles", "sles_sap", "sled", "opensuse-leap":
		return "sudo zypper refresh && sudo zypper patch", "sudo zypper purge-kernels"
	case "alpine":
		return "sudo apk update && sudo apk upgrade", ""
	}
	return "Install the available package updates", "Remove kernels that are no longer booted"
}

func isOSPackage(t string) bool { return t == "deb" || t == "rpm" || t == "apk" }

// windowsFix reports whether a row is a Windows update finding with a free
// fix: the operating system row itself, with a fixed build.
func windowsFix(r Row) bool {
	return r.IsOS && r.Kind == "vulnerability" && r.FixedVersion != "" && !r.RequiresPro
}

// Build assigns every row to exactly one group and returns the groups
// (sorted by urgency) and the finding → group mapping.
func Build(rows []Row, advice map[string]Advice) ([]*Group, map[int64]string) {
	// Is the asset's OS itself end of life? Decides where OS issues without
	// a free fix go.
	osEOL := map[int64]Row{}
	for _, r := range rows {
		if r.Kind == "end_of_life" && r.IsOS {
			osEOL[r.AssetID] = r
		}
	}
	// A Windows host's cumulative updates contain every earlier fix, so
	// its findings with a free fix are one action: the newest update among
	// them (the highest fixed build), whichever update fixed each first.
	winLatest := map[int64]Row{}
	for _, r := range rows {
		if !windowsFix(r) {
			continue
		}
		cur, ok := winLatest[r.AssetID]
		if c, err := version.CompareGeneric(r.FixedVersion, cur.FixedVersion); !ok || (err == nil && c > 0) {
			winLatest[r.AssetID] = r
		}
	}
	groups := map[string]*Group{}
	assign := map[int64]string{}
	get := func(r Row, kind, key string) *Group {
		id := fmt.Sprintf("%d:%s", r.AssetID, kind)
		if key != "" {
			id += ":" + key
		}
		g := groups[id]
		if g == nil {
			g = &Group{ID: id, Kind: kind, AssetID: r.AssetID, AssetName: r.AssetName, AssetKind: r.AssetKind,
				Environment: r.Environment, AppDir: r.AppDir, ByPriority: map[string]int{}, BySeverity: map[string]int{},
				TopPriority: "P4", pkgs: map[string]bool{}, purlType: r.PurlType, fromVersions: map[string]bool{},
				extra: map[string]string{}, keys: map[string]bool{}}
			groups[id] = g
		}
		return g
	}
	for _, r := range rows {
		var g *Group
		switch {
		case r.Kind == "end_of_life" && r.IsOS:
			g = get(r, ReleaseUpgrade, "")
		case r.Kind == "end_of_life":
			g = get(r, EndOfLife, fmt.Sprint(r.ComponentID))
			g.Component, g.FromVersion, g.extra["title"] = r.Component, r.Version, r.EOLTitle
		case windowsFix(r):
			latest := winLatest[r.AssetID]
			key := latest.KB
			if key == "" {
				key = latest.FixedVersion
			}
			g = get(r, WindowsUpdate, key)
			g.Component, g.ToVersion = r.Component, latest.FixedVersion
			g.fromVersions[r.Version] = true
			g.extra["kb"], g.extra["kbdate"] = latest.KB, latest.KBReleased
			if r.OlderThanData != "" {
				g.extra["older"] = r.OlderThanData
			}
			if r.KB != "" {
				if g.kbs == nil {
					g.kbs = map[string]bool{}
				}
				g.kbs[r.KB] = true
			}
		case isOSPackage(r.PurlType) && r.KernelIdle:
			g = get(r, OldKernels, "")
		case isOSPackage(r.PurlType) && r.FixedVersion != "" && !r.RequiresPro:
			g = get(r, SecurityUpdates, "")
		case isOSPackage(r.PurlType) || (r.IsOS && r.Kind == "vulnerability"):
			// For Windows: a fix only in paid Extended Security Updates.
			if _, eol := osEOL[r.AssetID]; eol {
				g = get(r, ReleaseUpgrade, "")
			} else {
				g = get(r, NoFix, "")
			}
			if r.RequiresPro {
				g.extra["pro"] = r.Subscription
				if g.extra["pro"] == "" {
					g.extra["pro"] = "Ubuntu Pro"
				}
			}
		case r.FixedVersion != "":
			g = get(r, PackageUpgrade, fmt.Sprint(r.ComponentID))
			g.Component = r.Component
			g.fromVersions[r.Version] = true
			cmp := version.For(version.ForPurlType(r.PurlType))
			if g.ToVersion == "" {
				g.ToVersion = r.FixedVersion
			} else if c, err := cmp(r.FixedVersion, g.ToVersion); err == nil && c > 0 {
				g.ToVersion = r.FixedVersion
			}
		default:
			g = get(r, NoFix, "")
		}
		g.FindingIDs = append(g.FindingIDs, r.FindingID)
		g.FindingCount++
		if !g.keys[r.Key] {
			g.keys[r.Key] = true
			g.UniqueIssues++
		}
		g.ByPriority[r.Priority]++
		g.BySeverity[r.Severity]++
		if r.Priority < g.TopPriority {
			g.TopPriority = r.Priority
		}
		g.SOS = g.SOS || r.SOS
		if r.KnownExploited {
			g.KnownExploited++
		}
		if r.Component != "" {
			g.pkgs[r.Component] = true
		}
		if g.extra["os"] == "" {
			g.extra["os"], g.extra["osv"], g.extra["osname"] = r.OS, r.OSVersion, r.OSName
		}
		if r.Kind == "end_of_life" && r.IsOS {
			if subj, since := eolSubject(r.EOLTitle); subj != "" {
				g.extra["oslabel"], g.extra["since"] = subj, since
			}
		}
		assign[r.FindingID] = g.ID
	}
	out := make([]*Group, 0, len(groups))
	for _, g := range groups {
		describe(g, osEOL, advice)
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out, assign
}

var kindRank = map[string]int{ReleaseUpgrade: 0, SecurityUpdates: 1, WindowsUpdate: 1, PackageUpgrade: 2, EndOfLife: 3, NoFix: 4, OldKernels: 5}

func less(a, b *Group) bool {
	if a.SOS != b.SOS {
		return a.SOS
	}
	if a.TopPriority != b.TopPriority {
		return a.TopPriority < b.TopPriority
	}
	if a.KnownExploited != b.KnownExploited {
		return a.KnownExploited > b.KnownExploited
	}
	if a.FindingCount != b.FindingCount {
		return a.FindingCount > b.FindingCount
	}
	if kindRank[a.Kind] != kindRank[b.Kind] {
		return kindRank[a.Kind] < kindRank[b.Kind]
	}
	return a.ID < b.ID
}

func describe(g *Group, osEOL map[int64]Row, advice map[string]Advice) {
	g.FixKey = g.ID
	for p := range g.pkgs {
		g.Packages = append(g.Packages, p)
	}
	sort.Strings(g.Packages)
	g.PackageCount = len(g.Packages)
	if len(g.Packages) > 25 {
		g.Packages = g.Packages[:25]
	}
	n := g.FindingCount
	issues := plural(n, "finding")
	update, autoremove := manager(g.extra["os"], g.extra["osv"])
	osLabel := strings.TrimSpace(g.extra["osname"])
	if osLabel == "" {
		osLabel = strings.TrimSpace(g.extra["os"] + " " + g.extra["osv"])
	}
	switch g.Kind {
	case SecurityUpdates:
		g.Title = "Install available security updates"
		g.Action = update
		g.Effort = "low"
		g.Note = fmt.Sprintf("%s across %s are fixed by updates already published for %s.", issues, plural(g.PackageCount, "package"), osLabel)
	case WindowsUpdate:
		describeWindowsUpdate(g, osLabel)
	case OldKernels:
		g.Title = "Remove kernels that are no longer running"
		g.Action = autoremove
		g.Effort = "low"
		g.Note = fmt.Sprintf("%s affect kernels that are installed but not booted; nothing is exposed until one of them is started.", issues)
	case ReleaseUpgrade:
		a := advice[g.extra["os"]+":"+g.extra["osv"]]
		if l := g.extra["oslabel"]; l != "" {
			osLabel = l // "Ubuntu 20.04" rather than the full PRETTY_NAME
		}
		if a.EOLDate == "" {
			a.EOLDate = g.extra["since"]
		}
		g.Title = "Upgrade " + osLabel + " to a supported release"
		target := "a supported release"
		if a.Target != "" {
			target = a.Target
		}
		g.ToVersion, g.FromVersion = a.Target, g.extra["osv"]
		g.Action = fmt.Sprintf("%s is end of life", osLabel)
		if a.EOLDate != "" {
			g.Action += " (since " + a.EOLDate + ")"
		}
		g.Action += fmt.Sprintf("; upgrade to %s.", target)
		if ch := g.extra["pro"]; ch != "" {
			// The paid channel is an option, never the action.
			g.Needs = needsChannel(ch)
			g.Action += " Some of these issues are fixed in " + paidLabel(ch) + "; without it, upgrade to a supported release."
		}
		g.Effort = "high"
		g.Note = fmt.Sprintf("%s: the release itself, plus findings with no free fix for this release.", issues)
	case EndOfLife:
		subject, since := eolSubject(g.extra["title"])
		if subject == "" {
			subject = g.Component + " " + g.FromVersion
		}
		g.Title = "Upgrade " + subject + " (end of life)"
		g.Action = subject + " no longer receives security fixes"
		if since != "" {
			g.Action += " (since " + since + ")"
		}
		g.Action += "; move to a supported version."
		g.Note = fmt.Sprintf("Installed package: %s %s.", g.Component, g.FromVersion)
		g.FixKey = fmt.Sprintf("%s:%s:%s:%s", EndOfLife, g.purlType, g.Component, g.FromVersion)
		g.Effort = "medium"
	case PackageUpgrade:
		from := sortedKeys(g.fromVersions)
		g.FromVersion = strings.Join(from, ", ")
		g.TargetVersion = g.ToVersion
		g.Title = fmt.Sprintf("Upgrade %s %s → %s", g.Component, g.FromVersion, g.ToVersion)
		g.Action = fmt.Sprintf("Update %s to %s or later in the lockfile and redeploy.", g.Component, g.ToVersion)
		g.FixKey = fmt.Sprintf("%s:%s:%s:%s>%s", PackageUpgrade, g.purlType, g.Component, g.FromVersion, g.ToVersion)
		g.Effort = "medium"
		if len(from) > 0 {
			if ct, err := version.ChangeType(g.purlType, from[0], g.ToVersion); err == nil {
				g.Effort = effortOf(ct)
			}
		}
	case NoFix:
		g.Title = "Issues with no fix published yet"
		g.Action = "Watch for fixes; consider mitigations or replacing the affected components."
		g.Effort = "medium"
		if ch := g.extra["pro"]; ch != "" {
			g.Needs = needsChannel(ch)
			g.Title = "Issues with no free fix yet"
			g.Action = "Install updates when " + osLabel + " publishes free fixes; meanwhile consider mitigations or replacing the affected packages. " +
				"Fixed in " + paidLabel(ch) + "; without it, wait for the free fix or upgrade to a newer supported release."
		}
	}
}

// describeWindowsUpdate words a Windows update group: install the newest
// cumulative update among the findings, which fixes all of them.
func describeWindowsUpdate(g *Group, osLabel string) {
	kb, build := g.extra["kb"], g.ToVersion
	g.FromVersion = strings.Join(sortedKeys(g.fromVersions), ", ")
	g.TargetVersion = build
	subject, details := kb, []string{"build " + build}
	g.Title = "Install Windows update " + kb
	if kb == "" {
		subject, details = "the cumulative update for build "+build, nil
		g.Title = "Install " + subject
	}
	if d, err := time.Parse("2006-01-02", g.extra["kbdate"]); err == nil {
		details = append(details, "the "+d.Format("January 2006")+" update")
	}
	g.Action = "Install " + subject
	if len(details) > 0 {
		g.Action += " (" + strings.Join(details, ", ") + ")"
	}
	g.Action += " through Windows Update, WSUS or the Microsoft Update Catalog, then restart. " +
		"It is cumulative, so it fixes these issues whichever update first fixed them; any later cumulative update does too."
	g.Effort = "low"
	g.FixKey = fmt.Sprintf("%s:%s>%s", WindowsUpdate, kb, build)
	kbs := sortedKeys(g.kbs)
	verb := "are"
	if g.FindingCount == 1 {
		verb = "is"
	}
	g.Note = fmt.Sprintf("%s on %s %s fixed by this update", plural(g.FindingCount, "finding"), osLabel, verb)
	if len(kbs) > 1 {
		g.Note += fmt.Sprintf(" (first fixed in %s: %s)", plural(len(kbs), "update"), strings.Join(kbs, ", "))
	}
	g.Note += "."
	if m := g.extra["older"]; m != "" {
		if t, err := time.Parse("2006-01", m); err == nil {
			m = t.Format("January 2006")
		}
		g.Note += " The installed build is older than the oldest update Stackurity reads (" + m +
			"), so this update fixes more issues than are listed here."
	}
}

// Place is one asset a fix applies to, when one fix is shown for several.
type Place struct {
	GroupID      string `json:"group_id"`
	AssetID      int64  `json:"asset_id"`
	AssetName    string `json:"asset_name"`
	AssetKind    string `json:"asset_kind"`
	AppDir       string `json:"app_dir,omitempty"`
	Environment  string `json:"environment"`
	FindingCount int    `json:"finding_count"`
}

// Merge shows groups with the same FixKey as one fix: the first group (the
// most urgent, as stored) with the counts of all of them and the places they
// are in. Distinct issues are not added up: the same library at the same
// version has the same vulnerabilities everywhere.
func Merge(gs []Group) Group {
	m := gs[0]
	m.ByPriority, m.BySeverity = map[string]int{}, map[string]int{}
	m.FindingCount, m.KnownExploited = 0, 0
	for _, g := range gs {
		m.Places = append(m.Places, Place{GroupID: g.ID, AssetID: g.AssetID, AssetName: g.AssetName, AssetKind: g.AssetKind,
			AppDir: g.AppDir, Environment: g.Environment, FindingCount: g.FindingCount})
		m.FindingCount += g.FindingCount
		m.KnownExploited += g.KnownExploited
		m.UniqueIssues = max(m.UniqueIssues, g.UniqueIssues)
		m.PackageCount = max(m.PackageCount, g.PackageCount)
		m.SOS = m.SOS || g.SOS
		if g.TopPriority < m.TopPriority {
			m.TopPriority = g.TopPriority
		}
		for k, n := range g.ByPriority {
			m.ByPriority[k] += n
		}
		for k, n := range g.BySeverity {
			m.BySeverity[k] += n
		}
	}
	return m
}

func effortOf(changeType string) string {
	if e, ok := map[string]string{"distro": "low", "patch": "low", "minor": "medium", "major": "high"}[changeType]; ok {
		return e
	}
	return "medium"
}

// SetRecommendation records the recommended version for a package upgrade.
// When it is a newer stable release in the minimum fix's own major line,
// the title and action lead with it ("Upgrade ip-address 10.1.0 →
// 10.7.5") and ToVersion stays the minimum fix. A major upgrade, or a
// recommendation the registry withdrew, never becomes the headline: the
// title keeps the minimum fix and the action mentions the recommendation.
func (g *Group) SetRecommendation(recommended, changeType string, major, yanked bool, rationale []string) {
	if g.Kind != PackageUpgrade || recommended == "" {
		return
	}
	g.Recommended, g.ChangeType, g.RequiresMajor, g.RecommendedYanked, g.Rationale = recommended, changeType, major, yanked, rationale
	g.TargetVersion = g.ToVersion
	switch {
	case g.leadsWith(recommended, major, yanked):
		g.TargetVersion = recommended
		g.Title = fmt.Sprintf("Upgrade %s %s → %s", g.Component, g.FromVersion, recommended)
		g.Action = fmt.Sprintf("Update %s to %s, the newest stable release in its line, in the lockfile and redeploy. Any version from %s fixes these issues.",
			g.Component, recommended, g.ToVersion)
		if changeType != "" {
			g.Effort = effortOf(changeType)
		}
	case recommended != g.ToVersion:
		g.Action += fmt.Sprintf(" Recommended: %s, the newest stable release in its major line.", recommended)
	}
	if major {
		g.Action += " This is a major upgrade."
	}
}

// leadsWith reports whether the recommended version can head the group: a
// stable release above the minimum fix in the same major line, and not a
// major upgrade from what is installed.
func (g *Group) leadsWith(recommended string, major, yanked bool) bool {
	if major || yanked || recommended == g.ToVersion || g.ToVersion == "" {
		return false
	}
	eco := version.ForPurlType(g.purlType)
	line := version.MajorLine(eco, g.ToVersion)
	if line == "" || version.MajorLine(eco, recommended) != line {
		return false
	}
	// Below 1.0 a minor release may break things (0.21 to 0.34), so the
	// headline stays within the same 0.x minor line.
	if line == "0" && minorLine(recommended) != minorLine(g.ToVersion) {
		return false
	}
	c, err := version.For(eco)(recommended, g.ToVersion)
	return err == nil && c > 0
}

// needsChannel is the Group.Needs value for a paid channel that also
// publishes fixes for the group; the dashboard knows "ubuntu-pro" and shows
// anything else as written. It is informational: the group's action is the
// free path.
func needsChannel(ch string) string {
	if ch == "Ubuntu Pro" {
		return "ubuntu-pro"
	}
	return ch
}

// paidLabel names a paid channel as an option: "Ubuntu Pro (paid
// subscription)", "SUSE LTSS (paid subscription)".
func paidLabel(ch string) string {
	return ch + " (paid subscription)"
}

// EndedPackage is a distribution package past upstream end of life on a
// release that is itself end of life. The matcher raises no finding for it
// (the operating system's end-of-life finding covers it); the release
// upgrade lists it.
type EndedPackage struct {
	Component string // package name, e.g. php7.4-common
	Subject   string // upstream product and release, e.g. PHP 7.4
}

// AddEndedPackages adds each asset's ended packages to its release upgrade.
func AddEndedPackages(groups []*Group, byAsset map[int64][]EndedPackage) {
	for _, g := range groups {
		pkgs := byAsset[g.AssetID]
		if g.Kind != ReleaseUpgrade || len(pkgs) == 0 {
			continue
		}
		var subjects []string
		for _, p := range pkgs {
			g.pkgs[p.Component] = true
			if p.Subject != "" {
				subjects = appendUnique(subjects, p.Subject)
			}
		}
		g.Packages = sortedKeys(g.pkgs)
		g.PackageCount = len(g.Packages)
		if len(g.Packages) > 25 {
			g.Packages = g.Packages[:25]
		}
		if len(subjects) > 0 {
			sort.Strings(subjects)
			g.Note += " Packages also end of life upstream, which only the release's support kept patched: " + strings.Join(subjects, ", ") + "."
		}
	}
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// eolSubject turns "MySQL 8.0 is end-of-life since 2026-04-30" into
// ("MySQL 8.0", "2026-04-30").
func eolSubject(title string) (subject, since string) {
	subject, rest, ok := strings.Cut(title, " is end-of-life")
	if !ok {
		return "", ""
	}
	if _, d, ok := strings.Cut(rest, "since "); ok {
		since = strings.TrimSpace(d)
	}
	return strings.TrimSpace(subject), since
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return thousands(n) + " " + word + "s"
}

// thousands formats 19558 as "19,558".
func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0 && s[i-1] != '-'; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// minorLine is "0.21" for "0.21.4" (the leading two numbers), or "".
func minorLine(v string) string {
	v = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(v), "v"), "V")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	end := 0
	for end < len(parts[1]) && parts[1][end] >= '0' && parts[1][end] <= '9' {
		end++
	}
	return parts[0] + "." + parts[1][:end]
}
