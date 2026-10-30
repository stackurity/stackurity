package fixplan

import (
	"strings"
	"testing"
)

func host(id int64, f Row) Row {
	f.AssetID, f.AssetName, f.AssetKind, f.OS, f.OSVersion, f.OSName = 1, "help-droplet", "host", "ubuntu", "20.04", "Ubuntu 20.04.6 LTS"
	f.FindingID = id
	if f.Kind == "" {
		f.Kind = "vulnerability"
	}
	if f.PurlType == "" {
		f.PurlType = "deb"
	}
	if f.Priority == "" {
		f.Priority = "P3"
	}
	return f
}

func TestHostGrouping(t *testing.T) {
	rows := []Row{
		host(1, Row{Key: "CVE-1", Component: "openssl", FixedVersion: "1.1.1f-1ubuntu2.23", Priority: "P2", Severity: "high"}),
		host(2, Row{Key: "CVE-2", Component: "openssl", FixedVersion: "1.1.1f-1ubuntu2.24", Severity: "medium"}),
		host(3, Row{Key: "CVE-3", Component: "curl", FixedVersion: "7.68.0-1ubuntu2.25", KnownExploited: true}),
		host(4, Row{Component: "linux-image-5.4.0-190-generic", FixedVersion: "5.4.0-192.212", KernelIdle: true, Priority: "P4", KnownExploited: true}),
		host(5, Row{Component: "php7.4", FixedVersion: "7.4.3-4ubuntu2.29+esm1", RequiresPro: true, Priority: "P2"}),
		host(6, Row{Component: "libxml2"}),
		host(7, Row{Kind: "end_of_life", IsOS: true, Component: "ubuntu", Version: "20.04", PurlType: "generic", Priority: "P2",
			EOLTitle: "Ubuntu 20.04 is end-of-life since 2025-05-31"}),
		host(8, Row{Kind: "end_of_life", Component: "nginx", Version: "1.18.0", PurlType: "generic", EOLTitle: "nginx 1.18 is end-of-life since 2021-04-20"}),
	}
	groups, assign := Build(rows, map[string]Advice{"ubuntu:20.04": {ProductLabel: "Ubuntu", EOLDate: "2025-05-31", Target: "24.04 LTS"}})
	by := map[string]*Group{}
	for _, g := range groups {
		by[g.Kind] = g
	}
	if g := by[SecurityUpdates]; g == nil || g.FindingCount != 3 || g.PackageCount != 2 || g.Action != "sudo apt update && sudo apt upgrade" || g.KnownExploited != 1 || g.TopPriority != "P2" {
		t.Errorf("security updates = %+v", g)
	}
	if g := by[SecurityUpdates]; g.UniqueIssues != 3 {
		t.Errorf("unique issues = %d", g.UniqueIssues)
	}
	if g := by[OldKernels]; g == nil || g.FindingCount != 1 || !strings.Contains(g.Action, "autoremove") {
		t.Errorf("old kernels = %+v", g)
	}
	rel := by[ReleaseUpgrade]
	// OS EOL + Pro-only php + no-fix libxml2 all resolve by upgrading the release.
	if rel == nil || rel.FindingCount != 3 || rel.Needs != "ubuntu-pro" || rel.ToVersion != "24.04 LTS" || !strings.Contains(rel.Action, "2025-05-31") ||
		rel.Title != "Upgrade Ubuntu 20.04 to a supported release" {
		t.Errorf("release upgrade = %+v", rel)
	}
	// Upgrading is the action; Ubuntu Pro is an optional paid channel.
	if want := "Ubuntu 20.04 is end of life (since 2025-05-31); upgrade to 24.04 LTS. Some of these issues are fixed in Ubuntu Pro " +
		"(paid subscription); without it, upgrade to a supported release."; rel.Action != want {
		t.Errorf("release upgrade action = %q", rel.Action)
	}
	AddEndedPackages(groups, map[int64][]EndedPackage{1: {{Component: "php7.4-common", Subject: "PHP 7.4"}, {Component: "nginx", Subject: "nginx 1.18"}}})
	if rel.PackageCount != 5 || !strings.HasSuffix(rel.Note, "which only the release's support kept patched: PHP 7.4, nginx 1.18.") {
		t.Errorf("release upgrade with ended packages = %+v", rel)
	}
	if g := by[EndOfLife]; g.PackageCount != 1 {
		t.Errorf("ended packages only go to the release upgrade: %+v", g)
	}
	if g := by[EndOfLife]; g == nil || g.Title != "Upgrade nginx 1.18 (end of life)" || !strings.Contains(g.Action, "since 2021-04-20") {
		t.Errorf("eol = %+v", g)
	}
	if len(assign) != len(rows) {
		t.Errorf("every finding must be assigned: %d of %d", len(assign), len(rows))
	}
	if groups[0].Kind == OldKernels {
		t.Error("idle kernels must not lead the plan")
	}
}

func TestSubscriptionChannels(t *testing.T) {
	sles := func(id int64, f Row) Row {
		f = host(id, f)
		f.OS, f.OSVersion, f.OSName, f.PurlType = "sles", "15.5", "SUSE Linux Enterprise Server 15 SP5", "rpm"
		return f
	}
	groups, _ := Build([]Row{
		sles(1, Row{Component: "curl", FixedVersion: "8.0.1-150400.5.50.1", RequiresPro: true, Subscription: "SUSE LTSS"}),
		sles(2, Row{Component: "openssl-3", FixedVersion: "3.0.8-150500.5.8.1"}),
	}, nil)
	by := map[string]*Group{}
	for _, g := range groups {
		by[g.Kind] = g
	}
	// The free path is the action; LTSS is mentioned as a paid option.
	if g := by[NoFix]; g == nil || g.Needs != "SUSE LTSS" || g.Title != "Issues with no free fix yet" || strings.Contains(g.Action, "Ubuntu") ||
		!strings.HasPrefix(g.Action, "Install updates when SUSE Linux Enterprise Server 15 SP5 publishes free fixes") ||
		!strings.Contains(g.Action, "Fixed in SUSE LTSS (paid subscription); without it,") || strings.Contains(g.Action, "Enable") {
		t.Errorf("LTSS-only group = %+v", g)
	}
	if g := by[SecurityUpdates]; g == nil || g.Action != "sudo zypper refresh && sudo zypper patch" {
		t.Errorf("SLES updates = %+v", g)
	}
	if u, _ := manager("amzn", "2"); u != "sudo yum update" {
		t.Errorf("Amazon Linux 2 has no dnf: %q", u)
	}
	if u, _ := manager("amzn", "2023"); u != "sudo dnf upgrade --refresh" {
		t.Errorf("Amazon Linux 2023 = %q", u)
	}
	if u, _ := manager("ol", "7.9"); u != "sudo yum update" {
		t.Errorf("Oracle Linux 7 has no dnf: %q", u)
	}
	if u, _ := manager("ol", "9.4"); u != "sudo dnf upgrade --refresh" {
		t.Errorf("Oracle Linux 9 = %q", u)
	}
}

func TestRepositoryGrouping(t *testing.T) {
	repo := func(id int64, comp, ver, fix string) Row {
		return Row{FindingID: id, Kind: "vulnerability", AssetID: 2, AssetName: "shop", AssetKind: "repository", ComponentID: 10,
			PurlType: "npm", Component: comp, Version: ver, FixedVersion: fix, Priority: "P2", Severity: "high"}
	}
	rows := []Row{repo(1, "lodash", "4.17.15", "4.17.19"), repo(2, "lodash", "4.17.15", "4.17.21"), repo(3, "lodash", "4.17.15", "")}
	groups, _ := Build(rows, nil)
	var up, none *Group
	for _, g := range groups {
		switch g.Kind {
		case PackageUpgrade:
			up = g
		case NoFix:
			none = g
		}
	}
	if up == nil || up.ToVersion != "4.17.21" || up.FindingCount != 2 || up.Title != "Upgrade lodash 4.17.15 → 4.17.21" || up.Effort != "low" {
		t.Errorf("package upgrade = %+v", up)
	}
	if none == nil || none.FindingCount != 1 {
		t.Errorf("no fix = %+v", none)
	}
	if up.TargetVersion != "4.17.21" {
		t.Errorf("target before a recommendation = %q", up.TargetVersion)
	}
	up.SetRecommendation("4.17.23", "patch", false, false, []string{"why"})
	if up.Recommended != "4.17.23" || up.ToVersion != "4.17.21" || up.TargetVersion != "4.17.23" ||
		up.Title != "Upgrade lodash 4.17.15 → 4.17.23" || !strings.Contains(up.Action, "to 4.17.23") || !strings.Contains(up.Action, "from 4.17.21") {
		t.Errorf("recommendation = %+v", up)
	}
	none.SetRecommendation("1.0", "patch", false, false, nil)
	if none.Recommended != "" {
		t.Error("a recommendation was set on a no-fix group")
	}
}

// The recommended version heads the group only inside the minimum fix's
// major line; a major upgrade or a withdrawn release keeps the minimum fix
// as the headline.
func TestRecommendationHeadline(t *testing.T) {
	build := func() *Group {
		groups, _ := Build([]Row{{FindingID: 1, Kind: "vulnerability", Key: "GHSA-1", AssetID: 2, AssetName: "shop", ComponentID: 10,
			PurlType: "npm", Component: "ip-address", Version: "10.1.0", FixedVersion: "10.7.4", Priority: "P2", Severity: "high"}}, nil)
		return groups[0]
	}
	cases := []struct {
		name, rec, ct    string
		major, yanked    bool
		title, target    string
		actionMentionsRe bool
	}{
		{"same line", "10.7.5", "minor", false, false, "Upgrade ip-address 10.1.0 → 10.7.5", "10.7.5", false},
		{"is the minimum", "10.7.4", "minor", false, false, "Upgrade ip-address 10.1.0 → 10.7.4", "10.7.4", false},
		{"major", "11.2.0", "major", true, false, "Upgrade ip-address 10.1.0 → 10.7.4", "10.7.4", true},
		{"other line, not flagged major", "11.2.0", "minor", false, false, "Upgrade ip-address 10.1.0 → 10.7.4", "10.7.4", true},
		{"withdrawn", "10.7.5", "minor", false, true, "Upgrade ip-address 10.1.0 → 10.7.4", "10.7.4", true},
	}
	// Below 1.0, only the same minor line leads.
	zero := func() *Group {
		groups, _ := Build([]Row{{FindingID: 1, Kind: "vulnerability", Key: "GHSA-2", AssetID: 2, AssetName: "shop", ComponentID: 11,
			PurlType: "npm", Component: "axios", Version: "0.21.1", FixedVersion: "0.30.2", Priority: "P2", Severity: "high"}}, nil)
		return groups[0]
	}
	z := zero()
	z.SetRecommendation("0.34.0", "minor", false, false, nil)
	if z.TargetVersion != "0.30.2" || z.Title != "Upgrade axios 0.21.1 → 0.30.2" {
		t.Errorf("0.x across minor lines: %q %q", z.Title, z.TargetVersion)
	}
	z = zero()
	z.SetRecommendation("0.30.5", "minor", false, false, nil)
	if z.TargetVersion != "0.30.5" {
		t.Errorf("0.x in the same minor line: %q", z.TargetVersion)
	}
	for _, c := range cases {
		g := build()
		g.SetRecommendation(c.rec, c.ct, c.major, c.yanked, nil)
		if g.Title != c.title || g.TargetVersion != c.target || g.ToVersion != "10.7.4" || g.Recommended != c.rec {
			t.Errorf("%s: title %q target %q to %q", c.name, g.Title, g.TargetVersion, g.ToVersion)
		}
		if got := strings.Contains(g.Action, "Recommended: "+c.rec); got != c.actionMentionsRe {
			t.Errorf("%s: action %q", c.name, g.Action)
		}
	}
}

func TestNoEOLHostKeepsNoFixSeparate(t *testing.T) {
	groups, _ := Build([]Row{host(1, Row{Component: "libxml2"})}, nil)
	if len(groups) != 1 || groups[0].Kind != NoFix {
		t.Errorf("groups = %+v", groups[0])
	}
	// On a supported release a Pro-only fix is not the action either.
	groups, _ = Build([]Row{host(1, Row{Component: "libnode72", RequiresPro: true, Subscription: "Ubuntu Pro"})}, nil)
	if g := groups[0]; g.Kind != NoFix || g.Needs != "ubuntu-pro" || g.Title != "Issues with no free fix yet" ||
		!strings.Contains(g.Action, "Fixed in Ubuntu Pro (paid subscription); without it, wait for the free fix or upgrade to a newer supported release.") ||
		strings.Contains(g.Action, "Enable") || strings.Contains(g.Action, "ESM") {
		t.Errorf("Pro-only group = %+v", g)
	}
}

func TestPlural(t *testing.T) {
	for n, want := range map[int]string{1: "1 finding", 999: "999 findings", 19558: "19,558 findings", 1234567: "1,234,567 findings"} {
		if got := plural(n, "finding"); got != want {
			t.Errorf("plural(%d) = %q, want %q", n, got, want)
		}
	}
}

// The same library at the same version in two apps (phpMyAdmin twice on one
// server) is one fix in two places; a different version is a different fix.
func TestSameFixInSeveralPlaces(t *testing.T) {
	app := func(id, asset int64, dir, ver, key, prio string) Row {
		return Row{FindingID: id, Kind: "vulnerability", Key: key, AssetID: asset, AssetName: "phpmyadmin on DBC", AssetKind: "application",
			AppDir: dir, ComponentID: 7, PurlType: "npm", Component: "jquery", Version: ver, FixedVersion: "3.5.0", Priority: prio, Severity: "medium"}
	}
	rows := []Row{
		app(1, 10, "/var/www/html/phpmyadmin", "3.3.1", "CVE-2019-11358", "P2"),
		app(2, 10, "/var/www/html/phpmyadmin", "3.3.1", "CVE-2020-11022", "P3"),
		app(3, 11, "/var/www/html/demo/phpmyadmin", "3.3.1", "CVE-2019-11358", "P1"),
		app(4, 11, "/var/www/html/demo/phpmyadmin", "3.3.1", "CVE-2020-11022", "P3"),
		app(5, 12, "/srv/old", "3.2.0", "CVE-2019-11358", "P2"),
	}
	groups, _ := Build(rows, nil)
	byKey := map[string][]Group{}
	for _, g := range groups {
		byKey[g.FixKey] = append(byKey[g.FixKey], *g)
	}
	same := byKey["package_upgrade:npm:jquery:3.3.1>3.5.0"]
	if len(byKey) != 2 || len(same) != 2 {
		t.Fatalf("fix keys = %v", byKey)
	}
	m := Merge(same)
	if m.FindingCount != 4 || m.UniqueIssues != 2 || m.TopPriority != "P1" || m.ByPriority["P3"] != 2 || len(m.Places) != 2 {
		t.Errorf("merged = %+v", m)
	}
	if m.Places[0].AppDir == m.Places[1].AppDir || m.Places[0].AppDir == "" {
		t.Errorf("places should name each app directory: %+v", m.Places)
	}
	for _, g := range groups {
		if g.Kind != PackageUpgrade && g.FixKey != g.ID {
			t.Errorf("%s groups stay per asset: %q", g.Kind, g.FixKey)
		}
	}
}

// A Windows host's findings with a free fix are one cumulative update: the
// newest among them. A fix only in paid Extended Security Updates goes to
// the release upgrade when the release has ended, else to "no free fix".
func TestWindowsUpdateGrouping(t *testing.T) {
	win := func(id, asset int64, f Row) Row {
		f.FindingID, f.AssetID, f.AssetName, f.AssetKind, f.OS, f.OSName = id, asset, "ws", "host", "windows", "Windows Server 2022 Datacenter"
		f.PurlType, f.Component, f.IsOS, f.Priority = "generic", "windows", true, "P3"
		if f.Kind == "" {
			f.Kind = "vulnerability"
		}
		if f.Version == "" {
			f.Version = "10.0.20348.4052"
		}
		return f
	}
	rows := []Row{
		win(1, 1, Row{Key: "CVE-1", FixedVersion: "10.0.20348.4171", KB: "KB5065432", KBReleased: "2025-09-09"}),
		// .887 < .4294 as numbers, although not as text.
		win(2, 1, Row{Key: "CVE-2", FixedVersion: "10.0.20348.4294", KB: "KB5066782", KBReleased: "2025-10-14", KnownExploited: true}),
		win(3, 1, Row{Key: "CVE-3", FixedVersion: "10.0.20348.887", KB: "KB5016627", KBReleased: "2022-08-09"}),
		// No KB known for the build: grouped by the build.
		win(4, 2, Row{Key: "CVE-1", FixedVersion: "10.0.20348.4171", Version: "10.0.20348.4000"}),
		// Ended release: the ESU-only fix goes to the release upgrade.
		win(5, 3, Row{Key: "CVE-4", FixedVersion: "10.0.19045.7807", KB: "KB5126657", RequiresPro: true, Subscription: "Windows Extended Security Updates"}),
		win(6, 3, Row{Kind: "end_of_life", Key: "windows:10-22h2", EOLTitle: "Windows 10 22H2 is end-of-life since 2025-10-14"}),
		// Not ended: the ESU-only fix has no free fix yet.
		win(7, 4, Row{Key: "CVE-4", FixedVersion: "10.0.19045.7807", RequiresPro: true, Subscription: "Windows Extended Security Updates"}),
	}
	groups, assign := Build(rows, nil)
	byID := map[string]*Group{}
	for _, g := range groups {
		byID[g.ID] = g
	}
	g := byID["1:windows_update:KB5066782"]
	if g == nil || g.FindingCount != 3 || g.ToVersion != "10.0.20348.4294" || g.KnownExploited != 1 || g.Title != "Install Windows update KB5066782" ||
		g.Action != "Install KB5066782 (build 10.0.20348.4294, the October 2025 update) through Windows Update, WSUS or the Microsoft Update Catalog, then restart. "+
			"It is cumulative, so it fixes these issues whichever update first fixed them; any later cumulative update does too." ||
		g.Note != "3 findings on Windows Server 2022 Datacenter are fixed by this update (first fixed in 3 updates: KB5016627, KB5065432, KB5066782)." {
		t.Errorf("host 1 = %+v", g)
	}
	if g := byID["2:windows_update:10.0.20348.4171"]; g == nil || g.Title != "Install the cumulative update for build 10.0.20348.4171" ||
		!strings.HasPrefix(g.Action, "Install the cumulative update for build 10.0.20348.4171 through") ||
		g.Note != "1 finding on Windows Server 2022 Datacenter is fixed by this update." {
		t.Errorf("host 2 = %+v", g)
	}
	if assign[5] != "3:release_upgrade" || assign[7] != "4:no_fix" {
		t.Errorf("ESU-only fixes assigned %q and %q", assign[5], assign[7])
	}
	if g := byID["3:release_upgrade"]; g == nil || g.Needs != "Windows Extended Security Updates" {
		t.Errorf("host 3 release upgrade = %+v", g)
	}
}

func TestProgramUpdateGrouping(t *testing.T) {
	row := func(id, asset int64, key, version, fixed string, kev bool) Row {
		return Row{FindingID: id, Kind: "vulnerability", Key: key, AssetID: asset, AssetName: "WIN", AssetKind: "host",
			OS: "windows", ComponentID: 10 + asset, PurlType: "generic", Component: "7-Zip 24.08 (x64)", Version: version, FixedVersion: fixed,
			Priority: "P2", Severity: "high", KnownExploited: kev, Program: "7-zip", ProgramLabel: "7-Zip"}
	}
	rows := []Row{
		row(1, 1, "CVE-2025-0411", "24.08", "24.09", true),
		row(2, 1, "CVE-2026-14266", "24.08", "26.02", false),
		row(3, 2, "CVE-2026-14266", "26.00", "26.02", false),
		// No fixed version: not an update to name.
		row(4, 2, "CVE-2026-0001", "26.00", "", false),
	}
	groups, assign := Build(rows, nil)
	byID := map[string]*Group{}
	for _, g := range groups {
		byID[g.ID] = g
	}
	g1, g2 := byID["1:program_update:7-zip"], byID["2:program_update:7-zip"]
	if g1 == nil || g2 == nil {
		t.Fatalf("groups %v", assign)
	}
	if g1.Title != "Update 7-Zip to 26.02" || g1.FindingCount != 2 || g1.KnownExploited != 1 || g1.FromVersion != "24.08" ||
		g1.FixKey != "program_update:7-zip>26.02" || g1.Effort != "low" || !strings.Contains(g1.Action, "7-zip.org") {
		t.Errorf("WIN-1 group %+v", g1)
	}
	if g2.FixKey != g1.FixKey || g2.FindingCount != 1 {
		t.Errorf("one fix across hosts: %+v", g2)
	}
	if assign[4] != "2:no_fix" {
		t.Errorf("a finding without a fix goes to no_fix, got %q", assign[4])
	}
}

// Two .NET lines installed side by side on one host are two updates: one
// "update to 9.0.21" would leave 8.0 vulnerable.
func TestProgramUpdateSideBySide(t *testing.T) {
	row := func(id int64, line, version, fixed string) Row {
		return Row{FindingID: id, Kind: "vulnerability", Key: "CVE-2026-105016", AssetID: 1, AssetName: "WIN", AssetKind: "host", OS: "windows",
			ComponentID: id, PurlType: "generic", Component: "Microsoft .NET Runtime - " + version + " (x64)", Version: "64.80.25123",
			FixedVersion: fixed, Priority: "P2", Severity: "high", Program: "dotnet-runtime", ProgramLabel: ".NET Runtime",
			ProgramLine: line, ProgramVersion: version}
	}
	groups, _ := Build([]Row{row(1, "8", "8.0.20", "8.0.32"), row(2, "9", "9.0.10", "9.0.21")}, nil)
	got := map[string]*Group{}
	for _, g := range groups {
		got[g.Component] = g
	}
	g8, g9 := got[".NET Runtime 8"], got[".NET Runtime 9"]
	if len(groups) != 2 || g8 == nil || g9 == nil {
		t.Fatalf("groups %d: %v", len(groups), got)
	}
	if g8.Title != "Update .NET Runtime 8 to 8.0.32" || g8.FromVersion != "8.0.20" || g8.FixKey != "program_update:dotnet-runtime@8>8.0.32" ||
		g9.Title != "Update .NET Runtime 9 to 9.0.21" || g9.FixKey != "program_update:dotnet-runtime@9>9.0.21" {
		t.Errorf("groups %+v %+v", g8, g9)
	}
}
