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
