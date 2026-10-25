package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

func TestSearchAPI(t *testing.T) {
	e := newEnv(t)
	e.user("view@x.io", auth.RoleViewer)
	view := e.login("view@x.io")
	if code := bearerIngest(e); code != 201 {
		t.Fatal(code)
	}
	var res store.SearchResults
	if code := view.do("GET", "/api/v1/search?q=bash", nil, &res); code != 200 || len(res.Components) != 1 || res.More == nil {
		t.Errorf("viewer search: %d %+v", code, res)
	}
	for _, q := range []string{"", "a", strings.Repeat("x", 201)} {
		if code := view.do("GET", "/api/v1/search?q="+url.QueryEscape(q), nil, nil); code != 400 {
			t.Errorf("q=%q: %d", q, code)
		}
	}
	if code := e.anon().do("GET", "/api/v1/search?q=web", nil, nil); code != 401 {
		t.Errorf("anonymous search: %d", code)
	}
	_, collector, err := e.st.CreateToken(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), "c", auth.RoleCollector, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if code := bearer(e, collector, "GET", "/api/v1/search?q=web", nil, nil); code != 403 {
		t.Errorf("collector search: %d", code)
	}
}

// TestSearchWorkspaceIsolation checks that workspace B cannot find workspace
// A's assets, identifiers, components, findings or teams through search, even
// when both share a machine id and a public package.
func TestSearchWorkspaceIsolation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.user("alpha-admin@x.io", auth.RoleAdmin)
	betaWS, betaAdmin, err := e.st.CreateWorkspace(ctx, "Beta Corp", "", "beta-admin@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	alphaSess, betaSess := e.login("alpha-admin@x.io"), e.login("beta-admin@x.io")
	var me struct{ User store.User }
	alphaSess.do("GET", "/api/v1/auth/me", nil, &me)
	a := e.populate(t, tenant.DefaultWorkspace, "alpha", alphaSess, me.User.ID)
	b := e.populate(t, betaWS.ID, "beta", betaSess, betaAdmin.ID)

	// Alpha has a finding on its private library and on the shared bash package.
	actx := tenant.WithWorkspace(ctx, tenant.DefaultWorkspace)
	rows, _, err := e.st.ListInventory(actx, store.InventoryFilter{AssetID: a.asset})
	if err != nil || len(rows) != 2 {
		t.Fatalf("alpha inventory: %v %+v", err, rows)
	}
	var want []store.FindingInput
	var ids []int64
	for _, r := range rows {
		ids = append(ids, r.ID)
		want = append(want, store.FindingInput{Kind: "vulnerability", Key: "CVE-2099-0001", InventoryID: r.ID, AssetID: a.asset,
			ComponentID: r.ComponentID, Verification: "confirmed", Severity: "critical", Title: "alpha-only issue",
			Sources: []string{"X"}, Evidence: map[string]any{}})
	}
	if _, _, err := e.st.SyncFindings(actx, []string{"vulnerability"}, ids, want); err != nil {
		t.Fatal(err)
	}

	search := func(s *session, q string) (store.SearchResults, string) {
		t.Helper()
		resp := s.req("GET", "/api/v1/search?q="+url.QueryEscape(q)+"&limit=50", nil, nil)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("search %q: %d %s", q, resp.StatusCode, body)
		}
		var res store.SearchResults
		if err := json.Unmarshal(body, &res); err != nil {
			t.Fatal(err)
		}
		// The query is echoed back; only the results matter.
		res.Query = ""
		found, _ := json.Marshal(res)
		return res, string(found)
	}

	// Positive control: alpha finds its own objects.
	for _, q := range []string{"alpha", "CVE-2099-0001", "team-alpha", "alpha-private-lib"} {
		if res, _ := search(alphaSess, q); len(res.Assets)+len(res.Components)+len(res.Teams)+len(res.Vulnerabilities) == 0 {
			t.Errorf("alpha cannot find %q", q)
		}
	}

	// Beta never sees anything of alpha's, by name, id, key or identifier.
	for _, q := range []string{"alpha", "host-alpha", "team-alpha", "alpha-private-lib", "pkg:npm/alpha-private-lib@1.0.0",
		"alpha-private-lib@1.0.0", "CVE-2099-0001", "cve-2099", "alpha-only", "hooks.example/alpha"} {
		res, body := search(betaSess, q)
		if strings.Contains(strings.ToLower(body), "alpha") || len(res.Vulnerabilities) != 0 {
			t.Errorf("beta search %q leaked: %s", q, body)
		}
	}

	// Shared values resolve to beta's own objects only, with beta's counts.
	res, body := search(betaSess, "shared-machine-id")
	if len(res.Assets) != 1 || res.Assets[0].ID != b.asset || strings.Contains(body, "alpha") {
		t.Errorf("shared machine id from beta: %s", body)
	}
	res, body = search(betaSess, "bash")
	if len(res.Components) != 1 || res.Components[0].AssetCount != 1 || res.Components[0].OpenFindings != 0 ||
		len(res.Components[0].Assets) != 1 || res.Components[0].Assets[0].ID != b.asset {
		t.Errorf("shared component from beta: %s", body)
	}
	res, body = search(betaSess, "team-")
	if len(res.Teams) != 1 || res.Teams[0].ID != b.team {
		t.Errorf("teams from beta: %s", body)
	}
	// And alpha sees its bash finding, which beta's counts above left out.
	if res, _ := search(alphaSess, "bash"); len(res.Components) != 1 || res.Components[0].OpenFindings != 1 {
		t.Errorf("alpha bash: %+v", res.Components)
	}
}
