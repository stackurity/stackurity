package api_test

import (
	"context"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// glProjectsOf lists the active Stackurity projects of the asset an
// integration scanned.
func glProjectsOf(t *testing.T, f *glFx, integration int64) []int64 {
	t.Helper()
	in := glIntegration(t, f.e, tenant.DefaultWorkspace, integration)
	if in.AssetID == nil {
		t.Fatalf("integration %d has no asset", integration)
	}
	rows, err := f.e.st.Pool.Query(tenant.System(context.Background()), `SELECT pa.project_id FROM project_assets pa
		JOIN projects p ON p.id = pa.project_id AND p.archived_at IS NULL WHERE pa.asset_id = $1 ORDER BY 1`, *in.AssetID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

func glConnectWith(t *testing.T, f *glFx, s *session, group int64, body map[string]any) (int, glOAuthAnswer) {
	t.Helper()
	code, out := f.oauth(s, f.authorize(t, s, glAlice))
	if code != 200 || out.Pick == "" {
		t.Fatalf("oauth: %d %+v", code, out)
	}
	body["pick"] = out.Pick
	body["group_id"] = group
	var res glOAuthAnswer
	st := s.do("POST", "/api/v1/integrations/gitlab/connections", body, &res)
	return st, res
}

// Two GitLab groups connected one after the other each file their assets
// in the Stackurity project chosen for them: not in none, not all in one.
// A group connected with no project (as every group was before the
// choice existed) is filed later by choosing its project.
func TestGitLabGroupsFileAssetsInTheirProjects(t *testing.T) {
	f := gitlabSetup(t)
	e := f.e
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f.gl.mu.Lock()
	f.gl.groups[30] = &glGroup{id: 30, path: "gamma", name: "Gamma", premium: true, members: map[int64]int{glAlice: 50}}
	f.gl.mu.Unlock()
	f.gl.addProject(301, "gamma/app", map[string]string{"package-lock.json": glShopLock})

	pAcme, err := e.st.CreateProject(ctx, "Acme team", "")
	if err != nil {
		t.Fatal(err)
	}
	pGamma, err := e.st.CreateProject(ctx, "Gamma team", "")
	if err != nil {
		t.Fatal(err)
	}
	admin := e.login("admin@x.io")

	// acme with no project: its assets are in none, as the report said.
	code, out := glConnectWith(t, f, admin, 10, map[string]any{"project_id": 0})
	if code != 201 || out.Connection.ProjectID != nil {
		t.Fatalf("connect acme: %d %+v", code, out)
	}
	acme := out.Connection
	f.drain(t)
	ints := glIntegrations(t, e, tenant.DefaultWorkspace)
	for _, name := range []string{"acme/shop", "acme/blog", "acme/backend/api"} {
		if got := glProjectsOf(t, f, ints[name].ID); len(got) != 0 {
			t.Fatalf("%s before a project was chosen: %v", name, got)
		}
	}

	// gamma, connected next with the switcher on Gamma team and no
	// project_id: its asset goes there, and acme's are untouched.
	gammaSession := &session{e: admin.e, http: admin.http, hdr: map[string]string{"X-Stackurity-Project": itoa(pGamma.ID)}}
	code, out = glConnectWith(t, f, gammaSession, 30, map[string]any{})
	if code != 201 || out.Connection.ProjectID == nil || *out.Connection.ProjectID != pGamma.ID {
		t.Fatalf("connect gamma: %d %+v", code, out)
	}
	f.drain(t)
	ints = glIntegrations(t, e, tenant.DefaultWorkspace)
	if got := glProjectsOf(t, f, ints["gamma/app"].ID); len(got) != 1 || got[0] != pGamma.ID {
		t.Fatalf("gamma/app: %v", got)
	}
	if got := glProjectsOf(t, f, ints["acme/shop"].ID); len(got) != 0 {
		t.Fatalf("acme/shop after gamma: %v", got)
	}

	// Choosing acme's project files its unfiled assets; gamma's stay.
	eng := e.login("eng@x.io")
	if code := eng.do("PATCH", "/api/v1/integrations/gitlab/connections/"+itoa(acme.ID), map[string]any{"project_id": pAcme.ID}, nil); code != 403 {
		t.Fatalf("engineer: %d", code)
	}
	if code := admin.do("PATCH", "/api/v1/integrations/gitlab/connections/"+itoa(acme.ID), map[string]any{"project_id": 999999}, nil); code != 404 {
		t.Fatalf("unknown project: %d", code)
	}
	if code := admin.do("PATCH", "/api/v1/integrations/gitlab/connections/"+itoa(acme.ID), map[string]any{}, nil); code != 400 {
		t.Fatalf("no project_id: %d", code)
	}
	var upd struct {
		Connection  store.GitLabConnection `json:"connection"`
		AssetsAdded int64                  `json:"assets_added"`
	}
	if code := admin.do("PATCH", "/api/v1/integrations/gitlab/connections/"+itoa(acme.ID), map[string]any{"project_id": pAcme.ID}, &upd); code != 200 ||
		upd.AssetsAdded != 3 || upd.Connection.ProjectID == nil || *upd.Connection.ProjectID != pAcme.ID {
		t.Fatalf("choose acme's project: %d %+v", code, upd)
	}
	for _, name := range []string{"acme/shop", "acme/blog", "acme/backend/api"} {
		if got := glProjectsOf(t, f, ints[name].ID); len(got) != 1 || got[0] != pAcme.ID {
			t.Fatalf("%s: %v", name, got)
		}
	}
	if got := glProjectsOf(t, f, ints["gamma/app"].ID); len(got) != 1 || got[0] != pGamma.ID {
		t.Fatalf("gamma/app after acme's project: %v", got)
	}

	// A new project in acme goes into acme's project on its first scan.
	f.gl.addProject(104, "acme/docs", map[string]string{"package-lock.json": glBlogLock})
	if code := admin.do("POST", "/api/v1/integrations/gitlab/connections/"+itoa(acme.ID)+"/sync", nil, nil); code != 202 {
		t.Fatalf("sync: %d", code)
	}
	f.drain(t)
	ints = glIntegrations(t, e, tenant.DefaultWorkspace)
	if got := glProjectsOf(t, f, ints["acme/docs"].ID); len(got) != 1 || got[0] != pAcme.ID {
		t.Fatalf("acme/docs: %v", got)
	}

	// An asset someone takes out of the project is not put back by the
	// next scan.
	shop := glIntegration(t, e, tenant.DefaultWorkspace, ints["acme/shop"].ID)
	if _, err := e.st.RemoveProjectAssets(ctx, pAcme.ID, []int64{*shop.AssetID}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.QueueIntegrationRun(ctx, shop.ID, 0); err != nil {
		t.Fatal(err)
	}
	f.drain(t)
	if got := glProjectsOf(t, f, shop.ID); len(got) != 0 {
		t.Fatalf("acme/shop put back: %v", got)
	}

	// Connecting acme again without a project_id keeps its project.
	code, out = glConnectWith(t, f, admin, 10, map[string]any{})
	if code != 201 || out.Connection.ProjectID == nil || *out.Connection.ProjectID != pAcme.ID {
		t.Fatalf("connect acme again: %d %+v", code, out)
	}
}
