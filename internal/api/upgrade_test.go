package api_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/upgrade"
	"github.com/stackurity/stackurity/internal/why"
)

// upgradeFixture: one host with lodash 4.17.15 (two advisories, release data
// listing newer patches, one withdrawn) and an OS package.
func upgradeFixture(t *testing.T, e *env) (findingID, componentID int64) {
	t.Helper()
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	b := model.NewBatch(model.Collector{ID: "agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "web-1",
		Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "web-1"}}})
	b.Observations = []model.Observation{
		{Purl: "pkg:npm/lodash@4.17.15", Confidence: model.ConfidenceConfirmed},
		{Purl: "pkg:deb/debian/openssl@3.0.2-1?distro=debian-12", Confidence: model.ConfidenceConfirmed},
	}
	b.Complete = true
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	res, err := e.st.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.EnsureFeed(ctx, "osv:npm", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.UpsertAdvisories(ctx, "osv:npm", []*osv.Vulnerability{
		{ID: "GHSA-35jh-r3h4-6jhm", Aliases: []string{"CVE-2021-23337"}, Summary: "Command injection in lodash", Modified: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}
	rows, _, err := e.st.ListInventory(ctx, store.InventoryFilter{AssetID: res.AssetID})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	var in []store.FindingInput
	for _, r := range rows {
		ids = append(ids, r.ID)
		switch r.Name {
		case "lodash":
			componentID = r.ComponentID
			ev := map[string]any{"feed": "osv:npm"}
			in = append(in,
				store.FindingInput{Kind: "vulnerability", Key: "CVE-2021-23337", InventoryID: r.ID, AssetID: res.AssetID, ComponentID: r.ComponentID,
					Verification: "confirmed", Severity: "high", FixedVersion: "4.17.21", Sources: []string{"GHSA-35jh-r3h4-6jhm"}, Evidence: ev},
				store.FindingInput{Kind: "vulnerability", Key: "CVE-2020-8203", InventoryID: r.ID, AssetID: res.AssetID, ComponentID: r.ComponentID,
					Verification: "confirmed", Severity: "high", FixedVersion: "4.17.19", Sources: []string{"GHSA-p6mc-m468-83gw"}, Evidence: ev})
		case "openssl":
			in = append(in, store.FindingInput{Kind: "vulnerability", Key: "CVE-2023-0001", InventoryID: r.ID, AssetID: res.AssetID,
				ComponentID: r.ComponentID, Verification: "confirmed", Severity: "medium", FixedVersion: "3.0.2-1+deb12u1",
				Sources: []string{"DSA-1"}, Evidence: map[string]any{}})
		}
	}
	if _, _, err := e.st.SyncFindings(ctx, []string{"vulnerability"}, ids, in); err != nil {
		t.Fatal(err)
	}
	if err := e.st.UpsertRelease(ctx, store.Release{ComponentID: componentID, Latest: "4.17.23", LatestStable: "4.17.23",
		StableVersions: []string{"4.17.15", "4.17.19", "4.17.21", "4.17.23"}, Yanked: map[string]string{"4.17.24": "broken"},
		Source: "releases:npm", CheckedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	fs, _, err := e.st.ListFindings(ctx, store.FindingFilter{Key: "CVE-2021-23337"})
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings: %v %v", fs, err)
	}
	return fs[0].ID, componentID
}

func TestUpgradeAndOutcomeEndpoints(t *testing.T) {
	e := newEnv(t)
	e.user("view@x.io", auth.RoleViewer)
	view := e.login("view@x.io")
	fid, cid := upgradeFixture(t, e)
	path := "/api/v1/findings/" + itoa(fid)

	var detail struct {
		Upgrade *upgrade.Recommendation `json:"upgrade"`
	}
	if code := view.do("GET", path, nil, &detail); code != 200 || detail.Upgrade == nil {
		t.Fatalf("finding detail: %d %+v", code, detail)
	}
	u := detail.Upgrade
	if u.Recommended != "4.17.23" || u.MinimumFixed != "4.17.21" || u.Basis != upgrade.BasisLatestInLine || u.ChangeType != "patch" ||
		len(u.Fixes) != 2 || u.ReleaseData != upgrade.ReleaseAvailable || len(u.Rationale) == 0 {
		t.Errorf("upgrade = %+v", u)
	}
	var one struct {
		Upgrade upgrade.Recommendation `json:"upgrade"`
	}
	if code := view.do("GET", path+"/upgrade", nil, &one); code != 200 || one.Upgrade.Recommended != "4.17.23" {
		t.Errorf("finding upgrade: %d %+v", code, one)
	}
	var comp struct {
		Items []upgrade.VersionRecommendation `json:"items"`
		Total int64                           `json:"total"`
	}
	if code := view.do("GET", "/api/v1/components/"+itoa(cid)+"/upgrade", nil, &comp); code != 200 || comp.Total != 1 ||
		comp.Items[0].Version != "4.17.15" || comp.Items[0].Assets != 1 || comp.Items[0].Recommended != "4.17.23" {
		t.Errorf("component upgrade: %d %+v", code, comp)
	}

	var ex struct {
		Risk struct {
			PolicyVersion        string `json:"policy_version"`
			CurrentPolicyVersion string `json:"current_policy_version"`
			PolicyChanged        bool   `json:"policy_changed"`
			SLA                  struct {
				FixDays int `json:"fix_days"`
			} `json:"sla"`
			EPSS *why.EPSSDetail `json:"epss"`
		} `json:"risk"`
		Why struct {
			EPSS *why.EPSSDetail `json:"epss"`
		} `json:"why"`
		Advisories []struct {
			ID, Feed, URL string
		} `json:"advisories"`
		Feeds []struct {
			Name string `json:"name"`
		} `json:"feeds"`
		Collection map[string]*time.Time `json:"collection"`
	}
	// FIRST's EPSS for the CVE counts towards the priority and is explained.
	epssRows := []store.EPSSRow{{CVE: "CVE-2021-23337", Score: 0.42, Percentile: 0.97}}
	if _, err := e.st.ReplaceEPSS(tenant.System(context.Background()), "v2026.06.15", time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC),
		func() (*store.EPSSRow, error) {
			if len(epssRows) == 0 {
				return nil, nil
			}
			r := &epssRows[0]
			epssRows = epssRows[1:]
			return r, nil
		}); err != nil {
		t.Fatal(err)
	}
	// The version recorded is the one that prioritised the finding.
	if _, err := e.st.Prioritize(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), risk.DefaultPolicy(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if code := view.do("GET", path+"/explain", nil, &ex); code != 200 || ex.Risk.PolicyVersion != risk.DefaultPolicy().Version() ||
		ex.Risk.CurrentPolicyVersion != ex.Risk.PolicyVersion || ex.Risk.PolicyChanged ||
		ex.Risk.SLA.FixDays == 0 || len(ex.Advisories) != 1 || !strings.Contains(ex.Advisories[0].URL, "GHSA-35jh-r3h4-6jhm") ||
		len(ex.Feeds) != 1 || ex.Feeds[0].Name != "osv:npm" || ex.Collection["last_complete_collection_at"] == nil {
		t.Errorf("explain: %d %+v", code, ex)
	}
	if d := ex.Risk.EPSS; d == nil || !d.Counted || d.Score == nil || *d.Score != 0.42 || d.ModelVersion != "v2026.06.15" ||
		d.Date != "2026-10-28" || d.Threshold != 0.1 || !strings.Contains(d.Text, "42% chance") || ex.Why.EPSS == nil {
		t.Errorf("explain EPSS: %+v %+v", ex.Risk.EPSS, ex.Why.EPSS)
	}
	var list struct {
		Items []store.Finding `json:"items"`
		Total int64           `json:"total"`
	}
	if code := view.do("GET", "/api/v1/findings?epss_min=0.4", nil, &list); code != 200 || list.Total != 1 || list.Items[0].EPSS == nil ||
		*list.Items[0].EPSS != 0.42 || list.Items[0].EPSSPercentile == nil {
		t.Errorf("epss_min=0.4: %d %+v", code, list)
	}
	if code := view.do("GET", "/api/v1/findings?epss_min=0.5", nil, &list); code != 200 || list.Total != 0 {
		t.Errorf("epss_min=0.5: %d %d", code, list.Total)
	}
	for _, q := range []string{"10", "-0.1", "x"} {
		if code := view.do("GET", "/api/v1/findings?epss_min="+q, nil, nil); code != 400 {
			t.Errorf("epss_min=%s: %d", q, code)
		}
	}

	since := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	var ver store.VerifyReport
	if code := view.do("GET", "/api/v1/findings/verify?since="+since, nil, &ver); code != 200 || ver.StillOpen.Total != 0 || ver.NewSince != 3 {
		t.Errorf("verify: %d %+v", code, ver)
	}
	for _, q := range []string{"", "?since=yesterday", "?since=2999-01-01"} {
		if code := view.do("GET", "/api/v1/findings/verify"+q, nil, nil); code != 400 {
			t.Errorf("verify %q: %d", q, code)
		}
	}
	var out struct {
		Days   int                  `json:"days"`
		Report store.OutcomesReport `json:"report"`
	}
	if code := view.do("GET", "/api/v1/reports/outcomes?days=30", nil, &out); code != 200 || out.Days != 30 || len(out.Report.SLA) != 4 ||
		out.Report.Open.Active != 3 {
		t.Errorf("outcomes: %d %+v", code, out)
	}
	for _, q := range []string{"?days=0", "?days=400", "?days=x"} {
		if code := view.do("GET", "/api/v1/reports/outcomes"+q, nil, nil); code != 400 {
			t.Errorf("outcomes %q: %d", q, code)
		}
	}
	for _, p := range []string{path + "/upgrade", path + "/explain", "/api/v1/findings/verify?since=" + since, "/api/v1/reports/outcomes"} {
		if code := e.anon().do("GET", p, nil, nil); code != 401 {
			t.Errorf("anonymous %s: %d", p, code)
		}
	}

	// The action plan carries the recommendation for the package upgrade.
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if _, err := planner.Rebuild(ctx, e.st, time.Now()); err != nil {
		t.Fatal(err)
	}
	var groups struct {
		Items []map[string]any `json:"items"`
	}
	view.do("GET", "/api/v1/fix-groups?kind=package_upgrade", nil, &groups)
	if len(groups.Items) != 1 || groups.Items[0]["to_version"] != "4.17.21" || groups.Items[0]["recommended_version"] != "4.17.23" ||
		groups.Items[0]["change_type"] != "patch" || groups.Items[0]["target_version"] != "4.17.23" ||
		groups.Items[0]["title"] != "Upgrade lodash 4.17.15 → 4.17.23" || !strings.Contains(groups.Items[0]["action"].(string), "Any version from 4.17.21") {
		t.Errorf("fix groups = %+v", groups.Items)
	}

	// Another workspace can reach none of it.
	if _, _, err := e.st.CreateWorkspace(context.Background(), "Beta", "", "beta@x.io", "", pw); err != nil {
		t.Fatal(err)
	}
	beta := e.login("beta@x.io")
	for _, p := range []string{path, path + "/upgrade", path + "/explain", "/api/v1/components/" + itoa(cid) + "/upgrade"} {
		if code := beta.do("GET", p, nil, nil); code != 404 {
			t.Errorf("beta %s: %d", p, code)
		}
	}
	out.Report = store.OutcomesReport{}
	if code := beta.do("GET", "/api/v1/reports/outcomes", nil, &out); code != 200 || out.Report.Open.Active != 0 || out.Report.Resolved != 0 {
		t.Errorf("beta outcomes: %d %+v", code, out.Report)
	}
	ver = store.VerifyReport{}
	if code := beta.do("GET", "/api/v1/findings/verify?since="+since, nil, &ver); code != 200 || ver.NewSince != 0 || len(ver.Assets) != 0 {
		t.Errorf("beta verify: %d %+v", code, ver)
	}
}

// Grouped by fix, the same upgrade in several places is one item and counts
// once in the summary; filters apply first, so one asset is not merged.
func TestMergedFixGroups(t *testing.T) {
	e := newEnv(t)
	e.user("view@x.io", auth.RoleViewer)
	view := e.login("view@x.io")
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	host := func(name, version string) int64 {
		b := model.NewBatch(model.Collector{ID: "agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: name,
			Identifiers: []model.Identifier{{Scheme: "machine-id", Value: name}}})
		b.Observations = []model.Observation{{Purl: "pkg:npm/lodash@" + version, Confidence: model.ConfidenceConfirmed}}
		b.Complete = true
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		res, err := e.st.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		rows, _, err := e.st.ListInventory(ctx, store.InventoryFilter{AssetID: res.AssetID})
		if err != nil || len(rows) != 1 {
			t.Fatalf("inventory: %v %v", rows, err)
		}
		r := rows[0]
		in := []store.FindingInput{
			{Kind: "vulnerability", Key: "CVE-2021-23337", InventoryID: r.ID, AssetID: res.AssetID, ComponentID: r.ComponentID,
				Verification: "confirmed", Severity: "high", FixedVersion: "4.17.21", Sources: []string{"GHSA-1"}, Evidence: map[string]any{}},
			{Kind: "vulnerability", Key: "CVE-2020-8203", InventoryID: r.ID, AssetID: res.AssetID, ComponentID: r.ComponentID,
				Verification: "confirmed", Severity: "high", FixedVersion: "4.17.19", Sources: []string{"GHSA-2"}, Evidence: map[string]any{}}}
		if _, _, err := e.st.SyncFindings(ctx, []string{"vulnerability"}, []int64{r.ID}, in); err != nil {
			t.Fatal(err)
		}
		return res.AssetID
	}
	a := host("web-1", "4.17.15")
	host("web-2", "4.17.15")
	host("web-3", "4.17.10") // another installed version: its own fix
	if _, err := planner.Rebuild(ctx, e.st, time.Now()); err != nil {
		t.Fatal(err)
	}
	type item struct {
		ID           string `json:"id"`
		FindingCount int    `json:"finding_count"`
		Places       []struct {
			GroupID      string `json:"group_id"`
			FindingCount int    `json:"finding_count"`
		} `json:"places"`
	}
	var list struct {
		Items []item `json:"items"`
		Total int    `json:"total"`
	}
	if code := view.do("GET", "/api/v1/fix-groups?kind=package_upgrade&group_by=fix", nil, &list); code != 200 || list.Total != 2 || len(list.Items) != 2 {
		t.Fatalf("by fix: %d %+v", code, list)
	}
	var merged *item
	for i := range list.Items {
		if len(list.Items[i].Places) > 1 {
			merged = &list.Items[i]
		}
	}
	if merged == nil || len(merged.Places) != 2 || merged.FindingCount != 4 {
		t.Fatalf("merged item = %+v", merged)
	}
	// Each place's own group still opens.
	for _, x := range merged.Places {
		if code := view.do("GET", "/api/v1/fix-groups/"+url.PathEscape(x.GroupID), nil, nil); code != 200 || x.FindingCount != 2 {
			t.Errorf("group %s: %d", x.GroupID, code)
		}
	}
	list.Items = nil
	if view.do("GET", "/api/v1/fix-groups?kind=package_upgrade&group_by=asset", nil, &list); list.Total != 3 {
		t.Errorf("by asset: %d", list.Total)
	}
	// One asset in view is never merged.
	list.Items = nil
	if view.do("GET", "/api/v1/fix-groups?group_by=fix&asset_id="+itoa(a), nil, &list); list.Total != 1 || len(list.Items[0].Places) > 1 {
		t.Errorf("one asset: %+v", list)
	}
	// Counts follow the grouping: the same fix in two places counts once.
	var sum struct {
		Groups int `json:"groups"`
	}
	view.do("GET", "/api/v1/fix-groups/summary?group_by=fix", nil, &sum)
	byFix := sum.Groups
	view.do("GET", "/api/v1/fix-groups/summary?group_by=asset", nil, &sum)
	if byFix != sum.Groups-1 {
		t.Errorf("summary: by fix %d, by asset %d", byFix, sum.Groups)
	}
	if code := view.do("GET", "/api/v1/fix-groups/summary?group_by=nope", nil, nil); code != 400 {
		t.Errorf("bad group_by: %d", code)
	}
}
