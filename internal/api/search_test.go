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
	// Members are for engineers and above, like the user directory.
	e.user("eng@x.io", auth.RoleEngineer)
	if code := view.do("GET", "/api/v1/search?q=x.io", nil, &res); code != 200 || len(res.Members) != 0 {
		t.Errorf("viewer sees members: %d %+v", code, res.Members)
	}
	if code := e.login("eng@x.io").do("GET", "/api/v1/search?q=x.io", nil, &res); code != 200 || len(res.Members) != 2 {
		t.Errorf("engineer member search: %d %+v", code, res.Members)
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
// A's assets, identifiers, components, findings, finding titles, teams or
// members through search, even when both share a machine id, a public package
// and a member.
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

	// A member of both workspaces, with a different role in each, assigned
	// alpha's findings.
	e.user("both@x.io", auth.RoleEngineer)
	if _, err := e.st.AddMember(tenant.WithWorkspace(ctx, betaWS.ID), "both@x.io", "", auth.RoleViewer, ""); err != nil {
		t.Fatal(err)
	}
	var both int64
	if err := e.st.Pool.QueryRow(ctx, `SELECT id FROM users WHERE email = 'both@x.io'`).Scan(&both); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool.Exec(actx, `UPDATE findings SET assignee_user_id = $1`, both); err != nil {
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
	if res, body := search(alphaSess, "only issue"); len(res.Findings) != 1 || res.Findings[0].OpenFindings != 2 {
		t.Errorf("alpha cannot find its finding title: %s", body)
	}
	if res, body := search(alphaSess, "alpha-admin"); len(res.Members) != 1 || res.Members[0].Email != "alpha-admin@x.io" {
		t.Errorf("alpha cannot find its member: %s", body)
	}

	// Beta never sees anything of alpha's, by name, id, key or identifier.
	for _, q := range []string{"alpha", "host-alpha", "team-alpha", "alpha-private-lib", "pkg:npm/alpha-private-lib@1.0.0",
		"alpha-private-lib@1.0.0", "CVE-2099-0001", "cve-2099", "alpha-only", "hooks.example/alpha", "only issue", "issue",
		"alpha-admin", "alpha-admin@x.io", "admin@x.io"} {
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
	// Members: beta sees its own, and the shared member with beta's role and
	// no assignments; alpha sees alpha's role and alpha's assignments.
	res, body = search(betaSess, "x.io")
	if len(res.Members) != 2 || strings.Contains(body, "alpha") {
		t.Errorf("members from beta: %s", body)
	}
	res, body = search(betaSess, "both@x.io")
	if len(res.Members) != 1 || res.Members[0].Role != "viewer" || res.Members[0].OpenAssigned != 0 {
		t.Errorf("shared member from beta: %s", body)
	}
	res, body = search(alphaSess, "both@x.io")
	if len(res.Members) != 1 || res.Members[0].Role != "engineer" || res.Members[0].OpenAssigned != 2 {
		t.Errorf("shared member from alpha: %s", body)
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
