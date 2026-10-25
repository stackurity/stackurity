//go:build ee

package api_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// In the licensed build the sweep also gets remediation objects: a policy,
// a plan and an action on the workspace's host.
func init() {
	eeFixtures = func(t *testing.T, e *env, f *tenantFx) {
		t.Helper()
		ctx := tenant.WithWorkspace(context.Background(), f.ws)
		var pol struct{ ID int64 }
		if code := f.sess["admin"].do("POST", "/api/v1/remediation/policies", map[string]any{"name": "policy-" + f.tag, "enabled": true,
			"target": "host_package", "ecosystems": []string{"deb"}, "change_types": []string{"distro", "patch"}, "approval": "required"}, &pol); code != 201 {
			t.Fatalf("%s policy: %d", f.tag, code)
		}
		f.ids["policy"] = fmt.Sprint(pol.ID)
		rows, _, err := e.st.ListInventory(ctx, store.InventoryFilter{AssetID: f.int("asset")})
		if err != nil {
			t.Fatal(err)
		}
		var invID, compID int64
		for _, r := range rows {
			if r.Name == "bash" {
				invID, compID = r.ID, r.ComponentID
			}
		}
		planID, _, err := e.st.UpsertPlan(ctx, store.PlanSpec{PolicyID: pol.ID, PolicyName: "policy-" + f.tag, Target: "host_package",
			ComponentID: compID, Package: "bash", TargetVersion: "5.3", ChangeType: "patch",
			Actions: []store.ActionSpec{{AssetID: f.int("asset"), InventoryID: invID, Kind: "package_upgrade", Package: "bash", Manager: "apt",
				FromVersion: "5.2", ToVersion: "5.3"}}})
		if err != nil {
			t.Fatal(err)
		}
		f.ids["plan"] = fmt.Sprint(planID)
		acts, err := e.st.ListActions(ctx, planID, 0)
		if err != nil || len(acts) != 1 {
			t.Fatalf("%s actions: %v %v", f.tag, acts, err)
		}
		f.ids["action"] = fmt.Sprint(acts[0].ID)
	}
}
