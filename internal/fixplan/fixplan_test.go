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
}

func TestNoEOLHostKeepsNoFixSeparate(t *testing.T) {
	groups, _ := Build([]Row{host(1, Row{Component: "libxml2"})}, nil)
	if len(groups) != 1 || groups[0].Kind != NoFix {
		t.Errorf("groups = %+v", groups[0])
	}
}

func TestPlural(t *testing.T) {
	for n, want := range map[int]string{1: "1 finding", 999: "999 findings", 19558: "19,558 findings", 1234567: "1,234,567 findings"} {
		if got := plural(n, "finding"); got != want {
			t.Errorf("plural(%d) = %q, want %q", n, got, want)
		}
	}
}
