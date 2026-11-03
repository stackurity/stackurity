package fixplan

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var nofixNow = time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)

func day(s string) *time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return &t
}

const ghostDir = "/var/www/ghost/versions/6.52.0"

// ghostFinding is a package inside a Ghost install, as the agent reports it
// (pnpm's store; direct is not known there).
func ghostFinding(id int64, key, name, ver string) NoFixFinding {
	return NoFixFinding{FindingID: id, Key: key, Component: name, PurlType: "npm", Version: ver,
		Location: ghostDir + "/node_modules/.pnpm/" + name + "@" + ver + "/node_modules/" + name,
		AppDir:   ghostDir, App: "ghost", AppVersion: "6.52.0"}
}

// ghostNoFix is the "Issues with no fix published yet" group of a Ghost
// 6.52.0 install (12 findings), with the release and advisory data the
// server stores for them.
func ghostNoFix() []NoFixFinding {
	babel := ghostFinding(1, "CVE-2023-45133", "babel-traverse", "6.26.0")
	babel.MoveTo, babel.FixedIn, babel.LatestStable, babel.LatestPublished = "@babel/traverse", "7.23.2", "6.26.0", day("2017-08-16")
	pick := ghostFinding(2, "CVE-2020-8203", "lodash.pick", "4.4.0")
	pick.MoveTo, pick.FixedIn, pick.LatestStable, pick.LatestPublished = "lodash", "4.17.19", "4.4.0", day("2016-08-13")
	request := ghostFinding(3, "CVE-2023-28155", "request", "2.88.2")
	request.Deprecated = "request has been deprecated, see https://github.com/request/request/issues/3142"
	request.LatestStable, request.LatestPublished = "2.88.2", day("2020-02-11")
	brute := ghostFinding(4, "GHSA-984p-xq9m-4rjw", "express-brute", "1.0.1")
	brute.LatestStable, brute.LatestPublished = "1.0.1", day("2016-08-04")
	minifier := ghostFinding(5, "CVE-2022-37620", "html-minifier", "4.0.0")
	minifier.LatestStable, minifier.LatestPublished = "4.0.0", day("2019-04-01")
	var out []NoFixFinding
	out = append(out, babel, pick, request, brute, minifier)
	id := int64(6)
	for _, key := range []string{"CVE-2026-19693", "CVE-2026-56876"} {
		z := ghostFinding(id, key, "extract-zip", "2.0.1")
		z.LatestStable, z.LatestPublished = "2.0.1", day("2020-06-01")
		// The same package in the bundled theme's lockfile.
		theme := z
		theme.FindingID, theme.Location, theme.Direct = id+1, ghostDir+"/content/themes/source/yarn.lock", new(bool)
		out = append(out, z, theme)
		id += 2
	}
	merge := ghostFinding(10, "CVE-2026-93753", "deepmerge", "4.3.1")
	merge.LatestStable, merge.LatestPublished = "4.3.1", day("2023-03-15")
	forge := ghostFinding(11, "CVE-2026-33894", "node-forge", "1.4.0")
	forge.LatestStable, forge.LatestPublished = "1.4.1", day("2026-10-20")
	forgeTheme := forge
	forgeTheme.FindingID, forgeTheme.Location = 12, ghostDir+"/content/themes/source/yarn.lock"
	return append(out, merge, forge, forgeTheme)
}

func noFixGroup(n int) *Group {
	return &Group{ID: "5:no_fix", Kind: NoFix, FindingCount: n, Title: "Issues with no fix published yet",
		Action: "Watch for fixes; consider mitigations or replacing the affected components."}
}

func section(t *testing.T, a *NoFixAdvice, kind string) NoFixSection {
	t.Helper()
	for _, s := range a.Sections {
		if s.Kind == kind {
			return s
		}
	}
	t.Fatalf("no %s section in %+v", kind, a.Sections)
	return NoFixSection{}
}

func item(t *testing.T, s NoFixSection, component string) NoFixItem {
	t.Helper()
	for _, it := range s.Items {
		if it.Component == component {
			return it
		}
	}
	t.Fatalf("%s is not in the %s section: %+v", component, s.Kind, s.Items)
	return NoFixItem{}
}

func TestNoFixGhostExample(t *testing.T) {
	fs := ghostNoFix()
	g := noFixGroup(len(fs))
	AdviseNoFix(g, fs, nofixNow, 0)
	a := g.NoFixAdvice
	if a == nil {
		t.Fatal("no advice")
	}
	var kinds []string
	for _, s := range a.Sections {
		kinds = append(kinds, s.Kind)
	}
	if strings.Join(kinds, ",") != "renamed,unmaintained,no_fix_yet" {
		t.Errorf("sections %v, want renamed, unmaintained, no_fix_yet in that order", kinds)
	}
	renamed := section(t, a, NoFixRenamed)
	if renamed.Title != "Fixed under another name" || renamed.Issues != 2 || len(renamed.Items) != 2 {
		t.Errorf("renamed section %+v", renamed)
	}
	if it := item(t, renamed, "babel-traverse"); it.Text != "Fixed in @babel/traverse 7.23.2; babel-traverse gets no fix: move to @babel/traverse." ||
		it.MoveTo != "@babel/traverse" || it.FixedVersion != "7.23.2" || !it.Bundled {
		t.Errorf("babel-traverse: %+v", it)
	}
	if it := item(t, renamed, "lodash.pick"); it.Text != "Fixed in lodash 4.17.19; lodash.pick gets no fix: move to lodash." {
		t.Errorf("lodash.pick: %q", it.Text)
	}
	un := section(t, a, NoFixUnmaintained)
	// extract-zip's two issues count once each, though each is in two places.
	if un.Issues != 6 || len(un.Items) != 5 {
		t.Errorf("unmaintained: %d issues in %d packages, want 6 in 5", un.Issues, len(un.Items))
	}
	if it := item(t, un, "request"); it.Text != `Deprecated by its maintainers (“request has been deprecated, see https://github.com/request/request/issues/3142”); a fix is unlikely.` ||
		it.Deprecated == "" {
		t.Errorf("request: %q", it.Text)
	}
	if it := item(t, un, "html-minifier"); it.Text != "No release since April 2019 (4.0.0); a fix may not come." || it.LastRelease != "2019-04-01" {
		t.Errorf("html-minifier: %+v", it)
	}
	if it := item(t, un, "extract-zip"); strings.Join(it.Issues, ",") != "CVE-2026-19693,CVE-2026-56876" {
		t.Errorf("extract-zip issues %v", it.Issues)
	}
	if un.Items[0].Component != "extract-zip" {
		t.Errorf("the package with the most issues comes first, got %s", un.Items[0].Component)
	}
	yet := section(t, a, NoFixYet)
	if it := item(t, yet, "node-forge"); it.Text != "No fixed release yet." || yet.Issues != 1 {
		t.Errorf("node-forge: %+v (section %d issues)", it, yet.Issues)
	}
	b := a.Bundled
	if b == nil || b.App != "ghost" || b.AppVersion != "6.52.0" || b.LatestVersion != "" {
		t.Fatalf("bundled: %+v", b)
	}
	if b.Text != "These packages come with ghost 6.52.0 (/var/www/ghost/versions/6.52.0), as part of its dependencies: "+
		"you can't upgrade them on their own; only a ghost upgrade changes them." {
		t.Errorf("bundled text %q", b.Text)
	}
	want := []string{
		"cd /var/www/ghost/versions/6.52.0 && pnpm why babel-traverse lodash.pick request express-brute html-minifier extract-zip deepmerge node-forge",
		"cd /var/www/ghost/versions/6.52.0/content/themes/source && yarn why extract-zip",
		"cd /var/www/ghost/versions/6.52.0/content/themes/source && yarn why node-forge",
	}
	if strings.Join(b.Commands, "\n") != strings.Join(want, "\n") {
		t.Errorf("commands:\n%s\nwant:\n%s", strings.Join(b.Commands, "\n"), strings.Join(want, "\n"))
	}
	if want := "2 issues fixed under another name (babel-traverse → @babel/traverse 7.23.2 and lodash.pick → lodash 4.17.19), " +
		"6 in unmaintained packages (extract-zip, deepmerge, express-brute, html-minifier and request) and 1 with no fix yet (node-forge). " +
		"They come with ghost 6.52.0: only a ghost upgrade changes them. " +
		"Meanwhile: mitigate them (with a note), accept the risk until a date, or ignore them with a reason."; g.Action != want {
		t.Errorf("action\n%s\nwant\n%s", g.Action, want)
	}
	if g.Title != "Issues with no fix published yet" {
		t.Errorf("the title stays: %q", g.Title)
	}
	// The API serves the advice with the group.
	j, _ := json.Marshal(g)
	if !strings.Contains(string(j), `"no_fix_advice":{"bundled":{"app":"ghost"`) {
		t.Errorf("json: %s", j)
	}
}

// A package renamed only for some of its issues is not "fixed under another
// name": moving would leave the others.
func TestNoFixRenamedNeedsEveryIssue(t *testing.T) {
	a := ghostFinding(1, "CVE-1", "babel-traverse", "6.26.0")
	a.MoveTo, a.FixedIn = "@babel/traverse", "7.23.2"
	b := ghostFinding(2, "CVE-2", "babel-traverse", "6.26.0")
	g := noFixGroup(2)
	AdviseNoFix(g, []NoFixFinding{a, b}, nofixNow, 0)
	if s := g.NoFixAdvice.Sections; len(s) != 1 || s[0].Kind != NoFixYet {
		t.Errorf("sections %+v", s)
	}
	// Both fixed there: the highest fixed version is named.
	b.MoveTo, b.FixedIn = "@babel/traverse", "7.24.0"
	g = noFixGroup(2)
	AdviseNoFix(g, []NoFixFinding{a, b}, nofixNow, 0)
	if it := g.NoFixAdvice.Sections[0].Items[0]; it.FixedVersion != "7.24.0" || len(it.Issues) != 2 {
		t.Errorf("item %+v", it)
	}
}

func TestNoFixDeprecatedAndStale(t *testing.T) {
	recent := day("2026-06-01")
	dep := NoFixFinding{FindingID: 1, Key: "CVE-1", Component: "left-pad", PurlType: "npm", Version: "1.0.0",
		Deprecated: "use String.prototype.padStart()", LatestPublished: recent}
	stale := NoFixFinding{FindingID: 2, Key: "CVE-2", Component: "old", PurlType: "npm", Version: "1.0.0",
		LatestStable: "1.2.0", LatestPublished: day("2024-10-01")}
	fresh := NoFixFinding{FindingID: 3, Key: "CVE-3", Component: "busy", PurlType: "npm", Version: "3.1.0",
		LatestStable: "3.1.0", LatestPublished: recent}
	unknown := NoFixFinding{FindingID: 4, Key: "CVE-4", Component: "unread", PurlType: "npm", Version: "1.0.0"}
	g := noFixGroup(4)
	AdviseNoFix(g, []NoFixFinding{dep, stale, fresh, unknown}, nofixNow, 0)
	un := section(t, g.NoFixAdvice, NoFixUnmaintained)
	if it := item(t, un, "left-pad"); !strings.Contains(it.Text, "“use String.prototype.padStart()”") {
		t.Errorf("deprecated: %q", it.Text)
	}
	if it := item(t, un, "old"); it.Text != "No release since October 2024 (1.2.0); a fix may not come." {
		t.Errorf("stale: %q", it.Text)
	}
	yet := section(t, g.NoFixAdvice, NoFixYet)
	if it := item(t, yet, "busy"); it.Text != "No fixed release yet; 3.1.0 is the newest release." {
		t.Errorf("fresh: %q", it.Text)
	}
	// No release data: nothing is claimed about maintenance.
	if it := item(t, yet, "unread"); it.Text != "No fixed release yet." {
		t.Errorf("unknown: %q", it.Text)
	}
	if g.NoFixAdvice.Bundled != nil {
		t.Errorf("no application: %+v", g.NoFixAdvice.Bundled)
	}
}

func TestNoFixWorkaroundQuoted(t *testing.T) {
	f := NoFixFinding{FindingID: 1, Key: "CVE-2026-33894", Component: "node-forge", PurlType: "npm", Version: "1.4.0",
		Workaround: "Do not verify signatures from untrusted sources.", Advisory: "GHSA-aaaa-bbbb-cccc"}
	g := noFixGroup(1)
	AdviseNoFix(g, []NoFixFinding{f}, nofixNow, 0)
	it := g.NoFixAdvice.Sections[0].Items[0]
	if it.Workaround != f.Workaround || it.WorkaroundSource != "GHSA-aaaa-bbbb-cccc" ||
		it.Text != "No fixed release yet. GHSA-aaaa-bbbb-cccc gives a workaround." {
		t.Errorf("item %+v", it)
	}
}

func TestNoFixBundled(t *testing.T) {
	yes, no := true, false
	in := ghostFinding(1, "CVE-1", "deepmerge", "4.3.1")
	in.AppLatest = "6.60.1"
	direct := in
	direct.FindingID, direct.Key, direct.Component, direct.Direct = 2, "CVE-2", "mine", &yes
	direct.Location = ghostDir + "/node_modules/mine"
	g := noFixGroup(2)
	AdviseNoFix(g, []NoFixFinding{in, direct}, nofixNow, 0)
	b := g.NoFixAdvice.Bundled
	if b == nil || b.LatestVersion != "6.60.1" ||
		b.Text != "This package comes with ghost 6.52.0 (/var/www/ghost/versions/6.52.0), as part of its dependencies: "+
			"you can't upgrade it on its own; only a ghost upgrade changes it. Check whether ghost 6.60.1 ships newer versions of it." {
		t.Fatalf("bundled %+v", b)
	}
	// A package the project lists itself is the person's to upgrade.
	yet := section(t, g.NoFixAdvice, NoFixYet)
	if item(t, yet, "mine").Bundled || !item(t, yet, "deepmerge").Bundled {
		t.Errorf("bundled flags: %+v", yet.Items)
	}
	if strings.Contains(strings.Join(b.Commands, " "), "mine") {
		t.Errorf("commands name only bundled packages: %v", b.Commands)
	}
	// Not newer: the latest release is not suggested.
	in.AppLatest = "6.52.0"
	g = noFixGroup(1)
	AdviseNoFix(g, []NoFixFinding{in}, nofixNow, 0)
	if g.NoFixAdvice.Bundled.LatestVersion != "" {
		t.Errorf("latest %q", g.NoFixAdvice.Bundled.LatestVersion)
	}
	// Outside the application's directory (a host's global packages): not bundled.
	host := NoFixFinding{FindingID: 3, Key: "CVE-3", Component: "x", PurlType: "npm", Version: "1.0.0",
		Location: "/usr/lib/node_modules/x", Direct: &no}
	g = noFixGroup(1)
	AdviseNoFix(g, []NoFixFinding{host}, nofixNow, 0)
	if g.NoFixAdvice.Bundled != nil {
		t.Errorf("host package bundled: %+v", g.NoFixAdvice.Bundled)
	}
}

func TestNoFixWhyCommands(t *testing.T) {
	cases := []struct {
		loc, typ, name, want string
	}{
		{"/srv/app/node_modules/x", "npm", "x", "cd /srv/app && npm ls x"},
		{"/srv/app/package-lock.json", "npm", "@scope/x", "cd /srv/app && npm ls @scope/x"},
		{"/srv/app/pnpm-lock.yaml", "npm", "x", "cd /srv/app && pnpm why x"},
		{"/srv/app/web/yarn.lock", "npm", "x", "cd /srv/app/web && yarn why x"},
		{"/srv/app/composer.lock", "composer", "monolog/monolog", "cd /srv/app && composer why monolog/monolog"},
		{"/srv/app/vendor/monolog/monolog", "composer", "monolog/monolog", "cd /srv/app && composer why monolog/monolog"},
		{"/srv/app/go.mod", "golang", "golang.org/x/net", "cd /srv/app && go mod why -m golang.org/x/net"},
		{"/srv/app/Cargo.lock", "cargo", "time", "cd /srv/app && cargo tree -i time"},
		// Paths from the reporting machine are quoted for the shell.
		{"/srv/my app/node_modules/x", "npm", "x", "cd '/srv/my app' && npm ls x"},
		{"/srv/a'b/yarn.lock", "npm", "x", `cd '/srv/a'\''b' && yarn why x`},
	}
	for _, c := range cases {
		f := NoFixFinding{FindingID: 1, Key: "CVE-1", Component: c.name, PurlType: c.typ, Version: "1.0.0", Location: c.loc,
			AppDir: c.loc[:strings.Index(c.loc[1:], "/")+1], App: "app"}
		if strings.HasPrefix(c.loc, "/srv/") {
			f.AppDir = "/srv"
		}
		g := noFixGroup(1)
		AdviseNoFix(g, []NoFixFinding{f}, nofixNow, 0)
		if b := g.NoFixAdvice.Bundled; b == nil || len(b.Commands) != 1 || b.Commands[0] != c.want {
			t.Errorf("%s: %+v, want %q", c.loc, b, c.want)
		}
	}
	// Python has no "why" command: the note stands without one.
	f := NoFixFinding{FindingID: 1, Key: "CVE-1", Component: "x", PurlType: "pypi", Version: "1.0", App: "app", AppDir: "/srv",
		Location: "/srv/venv/lib/python3.12/site-packages/x-1.0.dist-info"}
	g := noFixGroup(1)
	AdviseNoFix(g, []NoFixFinding{f}, nofixNow, 0)
	if b := g.NoFixAdvice.Bundled; b == nil || len(b.Commands) != 0 {
		t.Errorf("python: %+v", b)
	}
}

// Operating system findings in the same group keep the group's own action.
func TestNoFixMixedWithOSPackages(t *testing.T) {
	f := NoFixFinding{FindingID: 1, Key: "CVE-1", Component: "x", PurlType: "npm", Version: "1.0.0"}
	g := noFixGroup(3)
	AdviseNoFix(g, []NoFixFinding{f}, nofixNow, 0)
	if !strings.HasPrefix(g.Action, "Watch for fixes; consider mitigations or replacing the affected components. Application packages: 1 issue with no fix yet (x).") {
		t.Errorf("action %q", g.Action)
	}
	if NeedsNoFixAdvice(Row{Kind: "vulnerability", PurlType: "deb"}) || !NeedsNoFixAdvice(Row{Kind: "vulnerability", PurlType: "npm"}) {
		t.Error("NeedsNoFixAdvice: OS packages get none, application packages do")
	}
	// Other kinds of group are left alone.
	pg := &Group{Kind: PackageUpgrade, Action: "a", FindingCount: 1}
	AdviseNoFix(pg, []NoFixFinding{f}, nofixNow, 0)
	if pg.NoFixAdvice != nil || pg.Action != "a" {
		t.Errorf("package upgrade changed: %+v", pg)
	}
}

// The unmaintained cutoff is the risk policy's, and the section's heading
// says which rule put the packages there.
func TestNoFixUnmaintainedCutoff(t *testing.T) {
	kinds := func(months int) (map[string]string, *NoFixAdvice) {
		fs := ghostNoFix()
		g := noFixGroup(len(fs))
		AdviseNoFix(g, fs, nofixNow, months)
		out := map[string]string{}
		for _, s := range g.NoFixAdvice.Sections {
			for _, it := range s.Items {
				out[it.Component] = s.Kind
			}
		}
		return out, g.NoFixAdvice
	}
	def, a := kinds(0)
	if def["deepmerge"] != NoFixUnmaintained || def["extract-zip"] != NoFixUnmaintained {
		t.Errorf("24 months: %v", def)
	}
	un := section(t, a, NoFixUnmaintained)
	if un.Title != "Deprecated, or no release for 24 months or more (your risk policy)" || un.UnmaintainedMonths != 24 {
		t.Errorf("title %q, months %d", un.Title, un.UnmaintainedMonths)
	}
	// 48 months: deepmerge (last release March 2023) has a fix to wait for.
	k48, a48 := kinds(48)
	if k48["deepmerge"] != NoFixYet || k48["extract-zip"] != NoFixUnmaintained {
		t.Errorf("48 months: %v", k48)
	}
	if un := section(t, a48, NoFixUnmaintained); un.Title != "Deprecated, or no release for 48 months or more (your risk policy)" {
		t.Errorf("48 months title %q", un.Title)
	}
	// 120 months: express-brute (August 2016) is still past it; extract-zip is not.
	if k120, _ := kinds(120); k120["extract-zip"] != NoFixYet || k120["express-brute"] != NoFixUnmaintained || k120["request"] != NoFixUnmaintained {
		t.Errorf("120 months: %v", k120)
	}
	// Deprecated only: the heading names that rule, not the policy.
	dep := NoFixFinding{FindingID: 1, Key: "CVE-1", Component: "request", PurlType: "npm", Version: "2.88.2", Deprecated: "use fetch",
		LatestPublished: day("2026-01-01")}
	g0 := noFixGroup(1)
	AdviseNoFix(g0, []NoFixFinding{dep}, nofixNow, 0)
	if un := g0.NoFixAdvice.Sections[0]; un.Title != "Deprecated by the maintainers" || un.UnmaintainedMonths != 0 {
		t.Errorf("deprecated only: %q, %d", un.Title, un.UnmaintainedMonths)
	}
	// Inactive only.
	f := NoFixFinding{FindingID: 1, Key: "CVE-1", Component: "old", PurlType: "npm", Version: "1.0.0", LatestPublished: day("2025-01-01")}
	g := noFixGroup(1)
	AdviseNoFix(g, []NoFixFinding{f}, nofixNow, 6)
	if s := g.NoFixAdvice.Sections[0]; s.Title != "No release for 6 months or more (your risk policy)" {
		t.Errorf("stale only: %q", s.Title)
	}
}
