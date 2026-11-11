package api_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/upgrade"
)

// telnet 0.17+2.5-3ubuntu4 is built from inetutils 2:2.5-3ubuntu4 and has a
// version of its own; Ubuntu fixed CVE-2026-24061 in inetutils
// 2:2.5-3ubuntu4.1. apt has no telnet 2:2.5-3ubuntu4.1, so neither the
// upgrade recommendation nor the explanation may offer it as telnet's
// version: they name telnet and the source build with the fix.
func TestUpgradeBinaryWithItsOwnVersion(t *testing.T) {
	e := newEnv(t)
	e.user("view@x.io", auth.RoleViewer)
	view := e.login("view@x.io")
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	b := model.NewBatch(model.Collector{ID: "agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "noble-1",
		Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "noble-1"}}})
	b.Observations = []model.Observation{{Purl: "pkg:deb/ubuntu/telnet@0.17%2B2.5-3ubuntu4?arch=amd64&distro=ubuntu-24.04&upstream=inetutils",
		Confidence: model.ConfidenceConfirmed, Evidence: map[string]string{"source_package": "inetutils", "source_version": "2:2.5-3ubuntu4"}}}
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
		t.Fatalf("inventory %v %v", rows, err)
	}
	r := rows[0]
	// The evidence the matcher stores for this package (internal/intel).
	ev := map[string]any{"osv_package": "inetutils", "target_ecosystem": "Ubuntu:24.04:LTS", "installed": "2:2.5-3ubuntu4", "comparator": "debian",
		"feed": "osv:Ubuntu", "matched_ranges": []any{"UBUNTU-CVE-2026-24061: < 2:2.5-3ubuntu4.1"},
		"match": map[string]any{"rule": "range", "record": "UBUNTU-CVE-2026-24061", "source_version": "2:2.5-3ubuntu4"}}
	if _, _, err := e.st.SyncFindings(ctx, []string{"vulnerability"}, []int64{r.ID}, []store.FindingInput{{Kind: "vulnerability",
		Key: "CVE-2026-24061", InventoryID: r.ID, AssetID: res.AssetID, ComponentID: r.ComponentID, Verification: "confirmed",
		Severity: "critical", FixedVersion: "2:2.5-3ubuntu4.1", Sources: []string{"UBUNTU-CVE-2026-24061"}, Evidence: ev}}); err != nil {
		t.Fatal(err)
	}
	fs, _, err := e.st.ListFindings(ctx, store.FindingFilter{Key: "CVE-2026-24061"})
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings: %v %v", fs, err)
	}
	path := "/api/v1/findings/" + itoa(fs[0].ID)

	var one struct {
		Upgrade upgrade.Recommendation `json:"upgrade"`
	}
	if code := view.do("GET", path+"/upgrade", nil, &one); code != 200 {
		t.Fatalf("finding upgrade: %d", code)
	}
	u := one.Upgrade
	if u.Recommended != "" || u.Basis != upgrade.BasisDistroSourceFixed || u.MinimumFixed != "2:2.5-3ubuntu4.1" || u.Source == nil ||
		u.Source.Binary != "telnet" || u.Source.Source != "inetutils" || u.Source.SourceVersion != "2:2.5-3ubuntu4" {
		t.Errorf("upgrade %+v source %+v", u, u.Source)
	}
	if !strings.Contains(strings.Join(u.Rationale, " "), "Upgrade telnet to a build from inetutils 2:2.5-3ubuntu4.1 or later") {
		t.Errorf("rationale %q", u.Rationale)
	}
	var comp struct {
		Items []upgrade.VersionRecommendation `json:"items"`
	}
	if code := view.do("GET", "/api/v1/components/"+itoa(r.ComponentID)+"/upgrade", nil, &comp); code != 200 || len(comp.Items) != 1 ||
		comp.Items[0].Recommended != "" || comp.Items[0].Source == nil || comp.Items[0].Source.Binary != "telnet" {
		t.Errorf("component upgrade: %d %+v", code, comp)
	}

	var ex struct {
		Why struct {
			Sentence string `json:"sentence"`
		} `json:"why"`
	}
	if code := view.do("GET", path+"/explain", nil, &ex); code != 200 ||
		!strings.Contains(ex.Why.Sentence, "fixed in inetutils 2:2.5-3ubuntu4.1 (upgrade telnet to a build from it or later)") {
		t.Errorf("explain: %d %q", code, ex.Why.Sentence)
	}
}
