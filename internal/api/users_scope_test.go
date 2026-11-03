package api_test

import (
	"context"
	"sort"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// TestAddUserNeedsScope: POST /users says what the person can see, or is
// refused. There is no default: a request without a role or grants is 400
// and creates no account. Grants are written with the user in one
// transaction (a bad one leaves nothing), may not name another
// organisation's project or asset, and the new member sees exactly what
// they were given.
func TestAddUserNeedsScope(t *testing.T) {
	e := newEnv(t)
	bg := context.Background()
	a := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	admin := e.login("admin@x.io")
	wsB, _, err := e.st.CreateWorkspace(bg, "Beta", "", "beta@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	asset := func(ctx context.Context, id string) int64 {
		bt := model.NewBatch(model.Collector{ID: "t", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: id,
			Identifiers: []model.Identifier{{Scheme: "machine-id", Value: id}}})
		r, err := e.st.Ingest(ctx, bt, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}
	a1, a2, a3, b1 := asset(a, "a1"), asset(a, "a2"), asset(a, "a3"), asset(tenant.WithWorkspace(bg, wsB.ID), "b1")
	proj, err := e.st.CreateProject(a, "site", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.AddProjectAssets(a, proj.ID, []int64{a1}); err != nil {
		t.Fatal(err)
	}
	exists := func(email string) bool {
		ok, err := e.st.UserExists(a, email)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	for name, body := range map[string]map[string]any{
		"no role and no grants": {"email": "new@x.io", "name": "New", "password": pw},
		"role none, no grants":  {"email": "new@x.io", "password": pw, "role": "none"},
		"empty grants":          {"email": "new@x.io", "password": pw, "grants": []any{}},
		"role and grants":       {"email": "new@x.io", "password": pw, "role": "viewer", "grants": []any{map[string]any{"project_id": proj.ID, "role": "viewer"}}},
		"another organisation's asset": {"email": "new@x.io", "password": pw, "grants": []any{
			map[string]any{"project_id": proj.ID, "role": "viewer"}, map[string]any{"asset_id": b1, "role": "engineer"}}},
		"bad phone": {"email": "new@x.io", "password": pw, "role": "viewer", "phone": "not a phone"},
	} {
		if code := admin.do("POST", "/api/v1/users", body, nil); code != 400 {
			t.Errorf("%s: %d, want 400", name, code)
		}
		if exists("new@x.io") {
			t.Fatalf("%s: the account was created", name)
		}
	}
	if gs, _ := e.st.ListGrants(a, store.GrantFilter{}); len(gs) != 0 {
		t.Fatalf("grants left behind: %+v", gs)
	}

	// Only admins add people.
	if code := e.login("eng@x.io").do("POST", "/api/v1/users", map[string]any{"email": "new@x.io", "password": pw, "role": "viewer"}, nil); code != 403 {
		t.Errorf("engineer added a user: %d", code)
	}

	// Specific: the project (with the assets added to it later) and a2.
	var u store.User
	if code := admin.do("POST", "/api/v1/users", map[string]any{"email": "spec@x.io", "name": "Spec", "phone": "+44 20 7946 0000", "password": pw,
		"role": "none", "grants": []any{map[string]any{"project_id": proj.ID, "role": "viewer"}, map[string]any{"asset_id": a2, "role": "engineer"}}}, &u); code != 201 {
		t.Fatalf("specific: %d", code)
	}
	if u.Access != "projects" || u.Role != "" || u.Phone != "+44 20 7946 0000" || u.ProjectGrants != 1 || u.AssetGrants != 1 {
		t.Fatalf("specific user: %+v", u)
	}
	spec := e.login("spec@x.io")
	var list struct{ Items []struct{ ID int64 } }
	if code := spec.do("GET", "/api/v1/assets", nil, &list); code != 200 {
		t.Fatalf("assets: %d", code)
	}
	var seen []int64
	for _, x := range list.Items {
		seen = append(seen, x.ID)
	}
	sort.Slice(seen, func(i, j int) bool { return seen[i] < seen[j] })
	if len(seen) != 2 || seen[0] != a1 || seen[1] != a2 {
		t.Fatalf("specific user sees %v, want [%d %d], not %d or %d", seen, a1, a2, a3, b1)
	}
	if code := spec.do("GET", "/api/v1/assets/"+itoa(a3), nil, nil); code != 404 {
		t.Errorf("asset outside their grants: %d", code)
	}
	if code := spec.do("GET", "/api/v1/users", nil, nil); code != 403 {
		t.Errorf("organisation page for a specific member: %d", code)
	}
	// Engineer on a2 only: may edit a2, not a1 (viewer through the project).
	if code := spec.do("PATCH", "/api/v1/assets/"+itoa(a2), map[string]any{"criticality": "high"}, nil); code != 200 {
		t.Errorf("edit a2 as engineer: %d", code)
	}
	if code := spec.do("PATCH", "/api/v1/assets/"+itoa(a1), map[string]any{"criticality": "high"}, nil); code != 403 {
		t.Errorf("edit a1 as viewer: %d", code)
	}

	// All: an organisation-wide role.
	if code := admin.do("POST", "/api/v1/users", map[string]any{"email": "all@x.io", "password": pw, "role": "engineer"}, &u); code != 201 ||
		u.Access != "organisation" || u.Role != auth.RoleEngineer || u.ProjectGrants+u.AssetGrants != 0 {
		t.Fatalf("all: %d %+v", code, u)
	}
	// Already a member.
	if code := admin.do("POST", "/api/v1/users", map[string]any{"email": "all@x.io", "role": "viewer"}, nil); code != 409 {
		t.Errorf("again: %d", code)
	}

	// The phone can be changed and cleared; nonsense is refused.
	if code := admin.do("PATCH", "/api/v1/users/"+itoa(u.ID), map[string]any{"phone": " 98450 12345 "}, &u); code != 200 || u.Phone != "98450 12345" {
		t.Errorf("set phone: %d %q", code, u.Phone)
	}
	if code := admin.do("PATCH", "/api/v1/users/"+itoa(u.ID), map[string]any{"phone": "x"}, nil); code != 400 {
		t.Errorf("bad phone: %d", code)
	}
	if code := admin.do("PATCH", "/api/v1/users/"+itoa(u.ID), map[string]any{"phone": ""}, &u); code != 200 || u.Phone != "" {
		t.Errorf("clear phone: %d %q", code, u.Phone)
	}

	// The list shows the scope at a glance.
	var users struct{ Items []store.User }
	admin.do("GET", "/api/v1/users", nil, &users)
	found := false
	for _, x := range users.Items {
		if x.Email == "spec@x.io" {
			found = x.ProjectGrants == 1 && x.AssetGrants == 1 && x.Phone == "+44 20 7946 0000"
		}
	}
	if !found {
		t.Errorf("users list: %+v", users.Items)
	}
	// One access.grant per grant, and user.create with the count.
	evs, _, err := e.st.ListAudit(a, "access_grant", "", store.Page{Limit: 50})
	if err != nil || len(evs) != 2 {
		t.Errorf("access.grant events: %d %v", len(evs), err)
	}
}
