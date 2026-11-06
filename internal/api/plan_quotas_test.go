package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// TestPlanCheckCooldown: on a plan with a Check again cooldown, a second
// Check again on an asset (or one of its fixes) within it answers 429 with
// when it can run; a check still waiting answers as before, and "I
// applied this" is not held to it.
func TestPlanCheckCooldown(t *testing.T) {
	o := newOrg(t)
	setPlanLimits(t, o.e, store.PlanLimits{NextPlan: "Starter", CheckCooldownSeconds: 3600})
	path := "/api/v1/assets/" + o.s("beta-asset") + "/check"
	// The first (or the fixtures' check still waiting for its report).
	if code := o.admin.do("POST", path, nil, nil); code != 201 && code != 200 {
		t.Fatalf("first check: %d", code)
	}
	// Still waiting for its report: the same check again.
	if code := o.admin.do("POST", path, nil, nil); code != 200 {
		t.Errorf("check still waiting: %d", code)
	}
	o.ingest(t, "host-beta", "beta-m1", "prod-beta", "pkg:npm/beta-private-lib@1.0.0", "pkg:deb/debian/bash@5.2")
	resp := o.admin.req("POST", path, nil, map[string]string{"X-Stackurity-CSRF": "1"})
	defer resp.Body.Close()
	var body struct {
		Error struct {
			Code    string
			Message string
			Details []string
		}
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != 429 || body.Error.Code != "check_cooldown" || resp.Header.Get("Retry-After") == "" ||
		!strings.Contains(body.Error.Message, "once every 1h0m0s") || !strings.Contains(body.Error.Message, "Upgrade to Starter") ||
		len(body.Error.Details) == 0 || !strings.HasPrefix(body.Error.Details[0], "retry_at=") {
		t.Errorf("check within the cooldown: %d %s %+v", resp.StatusCode, resp.Header.Get("Retry-After"), body.Error)
	}
	if code := o.admin.do("POST", "/api/v1/fix-groups/"+o.fixGroup+"/check", nil, nil); code != 429 {
		t.Errorf("fix check within the cooldown: %d", code)
	}
	// Another asset has its own cooldown.
	if code := o.admin.do("POST", "/api/v1/assets/"+o.s("alpha-asset")+"/check", nil, nil); code != 201 && code != 200 {
		t.Errorf("another asset: %d", code)
	}
	// Without the limit: any time.
	setPlanLimits(t, o.e, store.PlanLimits{})
	if code := o.admin.do("POST", path, nil, nil); code != 201 {
		t.Errorf("without a cooldown: %d", code)
	}
}

// TestPlanSBOMImports: a plan's SBOM imports a month are taken one per
// import and refused with 402 plan_limit when used up; usage shows them.
func TestPlanSBOMImports(t *testing.T) {
	o := newOrg(t)
	setPlanLimits(t, o.e, store.PlanLimits{NextPlan: "Starter", SBOMImportsPerMonth: one(1)})
	if code, body := bearerBody(o.e, o.collector, "POST", "/api/v1/sbom/import?asset_name=shop", []byte(cdx)); code != 201 {
		t.Fatalf("first import: %d %s", code, body)
	}
	code, body := bearerBody(o.e, o.collector, "POST", "/api/v1/sbom/import?asset_name=shop", []byte(cdx))
	if code != 402 || !strings.Contains(body, "1 SBOM imports a month") || !strings.Contains(body, "Upgrade to Starter") {
		t.Errorf("second import: %d %s", code, body)
	}
	var usage store.AssetUsage
	if o.admin.do("GET", "/api/v1/usage", nil, &usage); usage.Plan == nil || usage.Plan.SBOMImports.Used != 1 ||
		usage.Plan.SBOMImports.Limit == nil || *usage.Plan.SBOMImports.Limit != 1 {
		t.Errorf("usage: %+v", usage.Plan)
	}
	// A failed import gives its place back.
	setPlanLimits(t, o.e, store.PlanLimits{SBOMImportsPerMonth: one(2)})
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if err := o.e.st.TakeSBOMImport(ctx); err != nil {
		t.Fatal(err)
	}
	if err := o.e.st.GiveBackSBOMImport(ctx); err != nil {
		t.Fatal(err)
	}
	if code, body := bearerBody(o.e, o.collector, "POST", "/api/v1/sbom/import?asset_name=shop", []byte(cdx)); code != 201 {
		t.Errorf("after a give-back: %d %s", code, body)
	}
}

// TestPlanAPIRequests: people's and API tokens' requests are capped an
// hour on a plan that sets it (429 with Retry-After); agents' uploads and
// collector tokens are not counted; without the limit nothing is counted.
func TestPlanAPIRequests(t *testing.T) {
	e := newEnv(t)
	if err := e.st.SetPlanLimits(context.Background(), tenant.DefaultWorkspace, store.PlanLimits{NextPlan: "Starter", APIRequestsPerHour: 4}); err != nil {
		t.Fatal(err)
	}
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	_, collector, err := e.st.CreateToken(ctx, "collector", auth.RoleCollector, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := []int{}
	for i := 0; i < 6; i++ {
		got = append(got, admin.do("GET", "/api/v1/assets", nil, nil))
	}
	if got[0] != 200 || got[5] != 429 {
		t.Fatalf("requests over the hour's cap: %v", got)
	}
	resp := admin.req("GET", "/api/v1/assets", nil, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Errorf("429 without Retry-After: %d", resp.StatusCode)
	}
	for i := 0; i < 6; i++ {
		raw := hostBatch(model.AssetHost, "web-1", "machine-id")
		if code, body := bearerBody(e, collector, "POST", "/api/v1/ingest", raw); code != 201 {
			t.Fatalf("agent upload %d over the cap: %d %s", i, code, body)
		}
	}
}
