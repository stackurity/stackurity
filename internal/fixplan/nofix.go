package fixplan

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/version"
)

// Issues with no fixed version still have something to do about them. For
// each application package in a NoFix group, AdviseNoFix says which of
// these applies, from stored data only:
//
//   - renamed: the advisory lists another package of the same ecosystem
//     with a fixed version (babel-traverse is fixed in @babel/traverse
//     7.23.2, lodash.pick in lodash 4.17.19): move to that package.
//   - unmaintained: the registry marks the package deprecated (its notice
//     is quoted, successor and all, never invented), or it has had no
//     release for the risk policy's unmaintained cutoff (24 months by
//     default): a fix is unlikely.
//   - no_fix_yet: none of these; no fixed release yet.
//
// Any of them may carry the advisory's own workaround, quoted. Packages
// installed inside an application's own dependency tree (not one the
// person lists themselves) get one note for the group: only an upgrade of
// the application changes them, with the command that shows which of its
// dependencies pulls each one in.

// Kinds of NoFixSection, in the order they are shown.
const (
	NoFixRenamed      = "renamed"
	NoFixUnmaintained = "unmaintained"
	NoFixYet          = "no_fix_yet"
)

// DefaultUnmaintainedMonths is the cutoff when none is given
// (risk.DefaultUnmaintainedMonths).
const DefaultUnmaintainedMonths = 24

// maxCommands bounds the commands listed for one group.
const maxCommands = 6

// NoFixFinding is what the planner knows about one application-package
// finding in a NoFix group (see store.NoFixContext).
type NoFixFinding struct {
	FindingID int64
	Key       string
	Component string // display name (namespace/name)
	PurlType  string
	Version   string
	Location  string // where it was found: an installed package's directory or a lockfile
	Direct    *bool  // listed by the project itself; nil when not known
	// AppDir, App and AppVersion describe the application asset the finding
	// is on (App is empty for other assets); AppLatest is the application's
	// newest stable release, when release data has one.
	AppDir     string
	App        string
	AppVersion string
	AppLatest  string
	// Release data for the package.
	Deprecated      string
	LatestStable    string
	LatestPublished *time.Time
	// MoveTo is another package the advisory lists with a fixed version
	// (FixedIn), in the same ecosystem; empty when there is none.
	MoveTo  string
	FixedIn string
	// Workaround is the advisory's own workaround text, from Advisory.
	Workaround string
	Advisory   string
}

// NoFixAdvice is the per-package guidance of a NoFix group.
type NoFixAdvice struct {
	// Bundled is set when packages come with the application the group is
	// on rather than being listed by the person.
	Bundled  *BundledIn     `json:"bundled,omitempty"`
	Sections []NoFixSection `json:"sections"`
}

// BundledIn says which application packages come with and how to see what
// pulls them in.
type BundledIn struct {
	App        string `json:"app"`
	AppVersion string `json:"app_version,omitempty"`
	AppDir     string `json:"app_dir,omitempty"`
	// LatestVersion is the application's newest release, when it is newer
	// than AppVersion.
	LatestVersion string `json:"latest_version,omitempty"`
	Text          string `json:"text"`
	// Commands show which top-level dependency pulls each package in, for
	// the package manager each was found with.
	Commands []string `json:"commands,omitempty"`
}

// NoFixSection is one kind of advice, with the packages it applies to.
type NoFixSection struct {
	Kind  string `json:"kind"`
	Title string `json:"title"`
	// UnmaintainedMonths is the risk policy's cutoff, on an unmaintained
	// section that has a package with no release for that long.
	UnmaintainedMonths int         `json:"unmaintained_months,omitempty"`
	Issues             int         `json:"issues"` // distinct issues across its packages
	Items              []NoFixItem `json:"items"`
}

// NoFixItem is one package at one version.
type NoFixItem struct {
	Component    string   `json:"component"`
	Version      string   `json:"version"`
	Issues       []string `json:"issues"`
	Text         string   `json:"text"`
	MoveTo       string   `json:"move_to,omitempty"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	Deprecated   string   `json:"deprecated,omitempty"`
	LastRelease  string   `json:"last_release,omitempty"` // date of the newest release, for an unmaintained package
	Workaround   string   `json:"workaround,omitempty"`
	// WorkaroundSource is the advisory the workaround is quoted from.
	WorkaroundSource string `json:"workaround_source,omitempty"`
	// Bundled: the package comes with the application (NoFixAdvice.Bundled).
	Bundled bool `json:"bundled,omitempty"`
}

var noFixTitles = map[string]string{
	NoFixRenamed:      "Fixed under another name",
	NoFixUnmaintained: "Unmaintained",
	NoFixYet:          "No fix yet",
}

// NeedsNoFixAdvice reports whether a row in a NoFix group is an
// application package, which AdviseNoFix can say more about. Operating
// system packages wait for the distribution's update.
func NeedsNoFixAdvice(r Row) bool {
	return r.Kind == "vulnerability" && !r.IsOS && !isOSPackage(r.PurlType) && r.Program == ""
}

// AdviseNoFix sets g.NoFixAdvice from its application-package findings and
// rewrites the action to say what they hold. Operating system findings in
// the same group keep the group's action, with this added.
//
// unmaintainedMonths is the workspace risk policy's cutoff: a package with
// no release for that many months is unmaintained (0: the default).
func AdviseNoFix(g *Group, fs []NoFixFinding, now time.Time, unmaintainedMonths int) {
	if unmaintainedMonths <= 0 {
		unmaintainedMonths = DefaultUnmaintainedMonths
	}
	if g.Kind != NoFix || len(fs) == 0 {
		return
	}
	type key struct{ component, version string }
	var order []key
	byItem := map[key][]NoFixFinding{}
	for _, f := range fs {
		k := key{f.Component, f.Version}
		if _, ok := byItem[k]; !ok {
			order = append(order, k)
		}
		byItem[k] = append(byItem[k], f)
	}
	sections := map[string]*NoFixSection{}
	adv := &NoFixAdvice{}
	type project struct{ dir, manager string }
	var projects []project
	projectPkgs := map[project][]string{}
	for _, k := range order {
		it, kind, bundled := adviseItem(byItem[k], now, unmaintainedMonths)
		s := sections[kind]
		if s == nil {
			s = &NoFixSection{Kind: kind, Title: noFixTitles[kind]}
			sections[kind] = s
		}
		s.Items = append(s.Items, it)
		s.Issues += len(it.Issues)
		if it.LastRelease != "" {
			s.UnmaintainedMonths = unmaintainedMonths
		}
		if !bundled {
			continue
		}
		f := byItem[k][0]
		if adv.Bundled == nil {
			adv.Bundled = &BundledIn{App: f.App, AppVersion: f.AppVersion, AppDir: f.AppDir}
			if f.AppLatest != "" && f.AppVersion != "" && newer(f.PurlType, f.AppLatest, f.AppVersion) {
				adv.Bundled.LatestVersion = f.AppLatest
			}
		}
		for _, x := range byItem[k] {
			if !inApp(x) {
				continue
			}
			dir, mgr := projectOf(x)
			if mgr == "" {
				continue
			}
			p := project{dir, mgr}
			if _, ok := projectPkgs[p]; !ok {
				projects = append(projects, p)
			}
			projectPkgs[p] = appendUnique(projectPkgs[p], whyName(x))
		}
	}
	for _, kind := range []string{NoFixRenamed, NoFixUnmaintained, NoFixYet} {
		s := sections[kind]
		if s == nil {
			continue
		}
		sort.SliceStable(s.Items, func(i, j int) bool {
			if len(s.Items[i].Issues) != len(s.Items[j].Issues) {
				return len(s.Items[i].Issues) > len(s.Items[j].Issues)
			}
			return s.Items[i].Component < s.Items[j].Component
		})
		if kind == NoFixUnmaintained {
			s.Title = unmaintainedTitle(s)
		}
		adv.Sections = append(adv.Sections, *s)
	}
	if b := adv.Bundled; b != nil {
		n := 0
		for _, s := range adv.Sections {
			for _, it := range s.Items {
				if it.Bundled {
					n++
				}
			}
		}
		for _, p := range projects {
			b.Commands = append(b.Commands, whyCommands(p.dir, p.manager, projectPkgs[p])...)
		}
		if len(b.Commands) > maxCommands {
			b.Commands = b.Commands[:maxCommands]
		}
		b.Text = bundledText(b, n)
	}
	g.NoFixAdvice = adv
	summary := noFixSummary(adv)
	if len(fs) == g.FindingCount {
		g.Action = summary
	} else {
		g.Action += " Application packages: " + summary
	}
}

// adviseItem classifies one package at one version from its findings.
func adviseItem(fs []NoFixFinding, now time.Time, unmaintainedMonths int) (NoFixItem, string, bool) {
	f := fs[0]
	it := NoFixItem{Component: f.Component, Version: f.Version}
	keys := map[string]bool{}
	bundled := false
	moveTo, fixedIn, allMove := "", "", true
	for _, x := range fs {
		if !keys[x.Key] {
			keys[x.Key] = true
			it.Issues = append(it.Issues, x.Key)
		}
		bundled = bundled || inApp(x)
		switch {
		case x.MoveTo == "":
			allMove = false
		case moveTo == "":
			moveTo, fixedIn = x.MoveTo, x.FixedIn
		case x.MoveTo != moveTo:
			allMove = false
		case newer(x.PurlType, x.FixedIn, fixedIn):
			fixedIn = x.FixedIn
		}
		if it.Workaround == "" && x.Workaround != "" {
			it.Workaround, it.WorkaroundSource = x.Workaround, x.Advisory
		}
	}
	sort.Strings(it.Issues)
	it.Bundled = bundled
	it.Deprecated = f.Deprecated
	kind := NoFixYet
	stale := f.LatestPublished != nil && f.LatestPublished.Before(now.AddDate(0, -unmaintainedMonths, 0))
	switch {
	case moveTo != "" && allMove:
		// Every issue of the package is fixed in the other one.
		kind, it.MoveTo, it.FixedVersion = NoFixRenamed, moveTo, fixedIn
		it.Text = fmt.Sprintf("Fixed in %s %s; %s gets no fix: move to %s.", moveTo, fixedIn, f.Component, moveTo)
	case f.Deprecated != "":
		kind = NoFixUnmaintained
		it.Text = "Deprecated by its maintainers (“" + oneLine(f.Deprecated, 300) + "”); a fix is unlikely."
	case stale:
		kind = NoFixUnmaintained
		it.LastRelease = f.LatestPublished.UTC().Format("2006-01-02")
		it.Text = fmt.Sprintf("No release since %s", f.LatestPublished.UTC().Format("January 2006"))
		if f.LatestStable != "" {
			it.Text += " (" + f.LatestStable + ")"
		}
		it.Text += "; a fix may not come."
	default:
		it.Text = "No fixed release yet."
		if f.LatestStable != "" && f.LatestStable == f.Version {
			it.Text = "No fixed release yet; " + f.Version + " is the newest release."
		}
	}
	if it.Workaround != "" {
		it.Text += " " + it.WorkaroundSource + " gives a workaround."
	}
	return it, kind, bundled
}

// unmaintainedTitle names the rule that put the packages in the section:
// the maintainers' deprecation, the risk policy's cutoff, or both.
func unmaintainedTitle(s *NoFixSection) string {
	deprecated := false
	for _, it := range s.Items {
		deprecated = deprecated || it.Deprecated != ""
	}
	stale := fmt.Sprintf("no release for %d months or more (your risk policy)", s.UnmaintainedMonths)
	switch {
	case s.UnmaintainedMonths == 0:
		return "Deprecated by the maintainers"
	case deprecated:
		return "Deprecated, or " + stale
	}
	return capitalise(stale)
}

// inApp reports whether a finding is in an application's dependency tree
// rather than a package the project lists itself.
func inApp(f NoFixFinding) bool {
	if f.App == "" || f.AppDir == "" || (f.Direct != nil && *f.Direct) {
		return false
	}
	dir := strings.TrimSuffix(f.AppDir, "/")
	return f.Location == dir || strings.HasPrefix(f.Location, dir+"/")
}

// projectOf returns the project directory a package was installed into or
// locked by, and the package manager that answers "why is it here?" for
// it, from where it was found. The manager is "" when none applies.
func projectOf(f NoFixFinding) (dir, manager string) {
	loc := f.Location
	if i := strings.Index(loc, "/node_modules/"); i >= 0 {
		dir = loc[:i]
		if strings.Contains(loc, "/node_modules/.pnpm/") {
			return dir, "pnpm"
		}
		return dir, "npm"
	}
	if i := strings.Index(loc, "/vendor/"); i >= 0 && f.PurlType == "composer" {
		return loc[:i], "composer"
	}
	switch path.Base(loc) {
	case "pnpm-lock.yaml":
		return path.Dir(loc), "pnpm"
	case "yarn.lock":
		return path.Dir(loc), "yarn"
	case "package-lock.json", "npm-shrinkwrap.json":
		return path.Dir(loc), "npm"
	case "composer.lock":
		return path.Dir(loc), "composer"
	case "go.mod", "go.sum":
		return path.Dir(loc), "go"
	case "Cargo.lock":
		return path.Dir(loc), "cargo"
	}
	return "", ""
}

// whyName is the name the package manager knows the package by.
func whyName(f NoFixFinding) string {
	if f.PurlType == "maven" {
		return strings.Replace(f.Component, "/", ":", 1)
	}
	return f.Component
}

// whyCommands are the commands that show which dependency pulls each
// package in. pnpm and npm take several packages at once; the others one.
func whyCommands(dir, manager string, pkgs []string) []string {
	cd := "cd " + shellQuote(dir) + " && "
	quoted := make([]string, len(pkgs))
	for i, p := range pkgs {
		quoted[i] = shellQuote(p)
	}
	switch manager {
	case "pnpm":
		return []string{cd + "pnpm why " + strings.Join(quoted, " ")}
	case "npm":
		return []string{cd + "npm ls " + strings.Join(quoted, " ")}
	}
	var out []string
	for _, p := range quoted {
		switch manager {
		case "yarn":
			out = append(out, cd+"yarn why "+p)
		case "composer":
			out = append(out, cd+"composer why "+p)
		case "go":
			out = append(out, cd+"go mod why -m "+p)
		case "cargo":
			out = append(out, cd+"cargo tree -i "+p)
		}
	}
	return out
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9@%+=:,./_-]+$`)

// shellQuote quotes s for a POSIX shell when it needs it: locations and
// names come from the reporting machine.
func shellQuote(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func bundledText(b *BundledIn, n int) string {
	app := b.App
	if b.AppVersion != "" {
		app += " " + b.AppVersion
	}
	subject, them, own := "These packages come", "them", "their"
	if n == 1 {
		subject, them, own = "This package comes", "it", "its"
	}
	where := ""
	if b.AppDir != "" {
		where = " (" + b.AppDir + ")"
	}
	t := fmt.Sprintf("%s with %s%s, as part of its dependencies: you can't upgrade %s on %s own; only a %s upgrade changes %s.",
		subject, app, where, them, own, b.App, them)
	if b.LatestVersion != "" {
		t += fmt.Sprintf(" Check whether %s %s ships newer versions of %s.", b.App, b.LatestVersion, them)
	}
	return t
}

// noFixSummary is the group's action in one paragraph, short enough for a
// list of fixes: what each kind holds, by package. The full lines are in
// the advice.
func noFixSummary(a *NoFixAdvice) string {
	var parts []string
	for i, s := range a.Sections {
		var names []string
		for j, it := range s.Items {
			if j == maxSummaryNames {
				names = append(names, fmt.Sprintf("%d more", len(s.Items)-j))
				break
			}
			n := it.Component
			if it.MoveTo != "" {
				n += " → " + it.MoveTo + " " + it.FixedVersion
			}
			names = append(names, n)
		}
		phrase := issuesPhrase(s.Issues)
		if i > 0 {
			phrase = strings.TrimSuffix(strings.TrimSuffix(phrase, " issues"), " issue") // "2 issues ..., 6 in ..."
		}
		switch s.Kind {
		case NoFixRenamed:
			phrase += " fixed under another name"
		case NoFixUnmaintained:
			phrase += " in unmaintained packages"
		default:
			phrase += " with no fix yet"
		}
		parts = append(parts, phrase+" ("+joinAnd(names)+")")
	}
	t := capitalise(joinAnd(parts)) + "."
	if b := a.Bundled; b != nil {
		app := b.App
		if b.AppVersion != "" {
			app += " " + b.AppVersion
		}
		t += fmt.Sprintf(" They come with %s: only a %s upgrade changes them.", app, b.App)
	}
	return t + " Meanwhile: mitigate them (with a note), accept the risk until a date, or ignore them with a reason."
}

// maxSummaryNames bounds the packages named per kind in the action.
const maxSummaryNames = 6

func issuesPhrase(n int) string {
	if n == 1 {
		return "1 issue"
	}
	return fmt.Sprintf("%s issues", thousands(n))
}

func joinAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// oneLine collapses whitespace and clips s to n bytes, at a rune boundary.
func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8Start(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// newer reports whether version a is newer than b in the purl type's
// ordering; versions it cannot compare are not newer.
func newer(purlType, a, b string) bool {
	if b == "" {
		return a != ""
	}
	c, err := version.For(version.ForPurlType(purlType))(a, b)
	return err == nil && c > 0
}
