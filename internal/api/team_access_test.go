package api_test

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// TestTeamAccess: membership of a team gives the team's access (its
// grants), from the next request and only while they are in it. The team
// an asset belongs to (owner team) routes alerts and gives nothing.
// Add user and invitations can add people to teams in the same
// transaction, and with no other access the teams must be able to see
// something. Community has one team, enforced by the server.
func TestTeamAccess(t *testing.T) {
	e := newEnvWith(t, func(s *api.Server) { s.TrustProxy = true })
	visitors := 0
	anon := func() *session {
		visitors++
		s := e.anon()
		s.hdr = map[string]string{"CF-Connecting-IP": fmt.Sprintf("203.0.113.%d", visitors)}
		return s
	}
	bg := context.Background()
	a := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	asset := func(id string) int64 {
		bt := model.NewBatch(model.Collector{ID: "t", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: id,
			Identifiers: []model.Identifier{{Scheme: "machine-id", Value: id}}})
		r, err := e.st.Ingest(a, bt, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}
	a1, a2, a3 := asset("a1"), asset("a2"), asset("a3")
	shop, err := e.st.CreateProject(a, "Shop", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.AddProjectAssets(a, shop.ID, []int64{a1}); err != nil {
		t.Fatal(err)
	}
	var web, ops store.Team
	admin.do("POST", "/api/v1/teams", map[string]any{"name": "Web"}, &web)
	admin.do("POST", "/api/v1/teams", map[string]any{"name": "Ops"}, &ops)
	sees := func(s *session) []int64 {
		t.Helper()
		var list struct{ Items []struct{ ID int64 } }
		if code := s.do("GET", "/api/v1/assets", nil, &list); code != 200 {
			t.Fatalf("assets: %d", code)
		}
		var out []int64
		for _, x := range list.Items {
			out = append(out, x.ID)
		}
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out
	}

	// Can see and Owns, set together. Web sees Shop and a3; Ops owns a2
	// and sees nothing.
	if code := admin.do("PATCH", fmt.Sprintf("/api/v1/teams/%d", web.ID), map[string]any{
		"access": []any{map[string]any{"project_id": shop.ID, "role": "engineer"}, map[string]any{"asset_id": a3, "role": "viewer"}}}, nil); code != 204 {
		t.Fatalf("web access: %d", code)
	}
	if code := admin.do("PATCH", fmt.Sprintf("/api/v1/teams/%d", ops.ID), map[string]any{"owns": []int64{a2}}, nil); code != 204 {
		t.Fatalf("ops owns: %d", code)
	}
	if gs, _ := e.st.ListGrants(a, store.GrantFilter{TeamID: web.ID}); len(gs) != 2 {
		t.Fatalf("web grants: %+v", gs)
	}
	if as, _ := e.st.GetAsset(a, a2); as.OwnerTeamID == nil || *as.OwnerTeamID != ops.ID {
		t.Fatalf("a2 owner: %+v", as.OwnerTeamID)
	}
	// Changing access replaces it: a3's grant goes, Shop's role changes.
	if code := admin.do("PATCH", fmt.Sprintf("/api/v1/teams/%d", web.ID), map[string]any{
		"access": []any{map[string]any{"project_id": shop.ID, "role": "viewer"}}}, nil); code != 204 {
		t.Fatal(code)
	}
	if gs, _ := e.st.ListGrants(a, store.GrantFilter{TeamID: web.ID}); len(gs) != 1 || gs[0].Role != auth.RoleViewer {
		t.Fatalf("web grants after the change: %+v", gs)
	}
	// Refused, and nothing changes: another team's member list stays, a
	// bad grant rolls back the whole update.
	if code := admin.do("PATCH", fmt.Sprintf("/api/v1/teams/%d", web.ID), map[string]any{"name": "Renamed",
		"access": []any{map[string]any{"asset_id": 999999, "role": "viewer"}}}, nil); code != 400 {
		t.Errorf("bad grant: %d", code)
	}
	if tm, _ := e.st.GetTeam(a, web.ID); tm.Name != "Web" {
		t.Errorf("a refused update renamed the team: %q", tm.Name)
	}
	if code := admin.do("PATCH", fmt.Sprintf("/api/v1/teams/%d", ops.ID), map[string]any{"owns": []int64{a2, 999999}}, nil); code != 400 {
		t.Errorf("bad owned asset: %d", code)
	}

	// Add user with a team and no other access: the team's access.
	var u store.User
	if code := admin.do("POST", "/api/v1/users", map[string]any{"email": "m1@x.io", "password": pw, "role": "none", "teams": []int64{web.ID}}, &u); code != 201 {
		t.Fatalf("add with a team: %d", code)
	}
	m1 := e.login("m1@x.io")
	if got := sees(m1); len(got) != 1 || got[0] != a1 {
		t.Fatalf("team member sees %v, want [%d]", got, a1)
	}
	var users struct{ Items []store.User }
	admin.do("GET", "/api/v1/users", nil, &users)
	for _, x := range users.Items {
		if x.Email == "m1@x.io" && (len(x.AccessTeams) != 1 || x.AccessTeams[0] != "Web") {
			t.Errorf("access_teams: %+v", x.AccessTeams)
		}
	}
	// The owner team alone gives nothing: Ops owns a2 but has no grant.
	for name, body := range map[string]map[string]any{
		"owner team only":    {"email": "m2@x.io", "password": pw, "teams": []int64{ops.ID}},
		"no such team":       {"email": "m2@x.io", "password": pw, "teams": []int64{999999}},
		"team named twice":   {"email": "m2@x.io", "password": pw, "teams": []int64{web.ID, web.ID}},
		"role none, nothing": {"email": "m2@x.io", "password": pw, "role": "none", "teams": []int64{}},
	} {
		if code := admin.do("POST", "/api/v1/users", body, nil); code != 400 {
			t.Errorf("%s: %d, want 400", name, code)
		}
		if ok, _ := e.st.UserExists(a, "m2@x.io"); ok {
			t.Fatalf("%s: the account was created", name)
		}
	}
	// A member of Ops (owner of a2) with Shop access does not see a2.
	if code := admin.do("POST", "/api/v1/users", map[string]any{"email": "m3@x.io", "password": pw,
		"grants": []any{map[string]any{"project_id": shop.ID, "role": "viewer"}}, "teams": []int64{ops.ID}}, nil); code != 201 {
		t.Fatal(code)
	}
	if got := sees(e.login("m3@x.io")); len(got) != 1 || got[0] != a1 {
		t.Errorf("owner team member sees %v, want only [%d] (not a2)", got, a1)
	}

	// Removed from the team: nothing, on their next request.
	if code := admin.do("PATCH", fmt.Sprintf("/api/v1/teams/%d", web.ID), map[string]any{"members": []int64{}}, nil); code != 204 {
		t.Fatal(code)
	}
	// With no access left, the assets list is refused (403) rather than
	// empty, as for any member with nothing.
	if code := m1.do("GET", "/api/v1/assets", nil, nil); code != 403 {
		t.Errorf("assets after leaving the team: %d", code)
	}
	if code := m1.do("GET", fmt.Sprintf("/api/v1/assets/%d", a1), nil, nil); code != 403 && code != 404 {
		t.Errorf("a1 after leaving the team: %d", code)
	}

	// Invitations: the teams join with the person.
	var inv scopedInvite
	if code := admin.do("POST", "/api/v1/invitations", map[string]any{"email": "inv@x.io", "teams": []int64{web.ID}}, &inv); code != 201 ||
		len(inv.Invitation.Teams) != 1 || inv.Invitation.Teams[0].Name != "Web" || len(inv.Invitation.Teams[0].Access) != 1 {
		t.Fatalf("invite with a team: %d %+v", code, inv)
	}
	if code := admin.do("POST", "/api/v1/invitations", map[string]any{"email": "x@x.io", "teams": []int64{ops.ID}}, nil); code != 400 {
		t.Errorf("invite with the owner team only: %d", code)
	}
	var pv struct{ Invitation store.InvitationPreview }
	anon().do("POST", "/api/v1/invitations/preview", map[string]string{"token": tokenOf(t, inv.Link)}, &pv)
	if !pv.Invitation.Usable || len(pv.Invitation.Teams) != 1 || pv.Invitation.Teams[0].Access[0].Name != "Shop" {
		t.Errorf("preview: %+v", pv.Invitation)
	}
	s := anon()
	var acc struct{ Teams int }
	if code := s.do("POST", "/api/v1/invitations/accept", map[string]any{"token": tokenOf(t, inv.Link), "password": pw}, &acc); code != 200 || acc.Teams != 1 {
		t.Fatalf("accept: %d %+v", code, acc)
	}
	if got := sees(s); len(got) != 1 || got[0] != a1 {
		t.Errorf("invited team member sees %v", got)
	}
	// A team deleted before the link is used: nothing left, refused.
	var gone scopedInvite
	admin.do("POST", "/api/v1/invitations", map[string]any{"email": "gone@x.io", "teams": []int64{web.ID}}, &gone)
	if code := admin.do("DELETE", fmt.Sprintf("/api/v1/teams/%d", web.ID), nil, nil); code != 204 {
		t.Fatal(code)
	}
	if code := anon().do("POST", "/api/v1/invitations/accept", map[string]any{"token": tokenOf(t, gone.Link), "password": pw}, nil); code != 410 {
		t.Errorf("accept with the team deleted: %d", code)
	}
	if ok, _ := e.st.UserExists(a, "gone@x.io"); ok {
		t.Error("an account was made for an invitation that gives nothing")
	}
	// A member gets the team at once.
	var given scopedInvite
	if code := admin.do("POST", "/api/v1/invitations", map[string]any{"email": "m3@x.io", "teams": []int64{ops.ID},
		"grants": []any{map[string]any{"asset_id": a3, "role": "viewer"}}}, &given); code != 201 || !given.Granted {
		t.Errorf("member: %d %+v", code, given)
	}
}

// TestTeamAccessCommunity: Community includes one team; adding people to
// it and giving it access works, a second team is refused by the server.
func TestTeamAccessCommunity(t *testing.T) {
	e := newEnv(t)
	e.api.Licence.Set(nil)
	a := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	p, err := e.st.CreateProject(a, "Shop", "")
	if err != nil {
		t.Fatal(err)
	}
	var one store.Team
	if code := admin.do("POST", "/api/v1/teams", map[string]any{"name": "One"}, &one); code != 201 {
		t.Fatalf("first team: %d", code)
	}
	if code := admin.do("POST", "/api/v1/teams", map[string]any{"name": "Two"}, nil); code != 402 {
		t.Errorf("second team on Community: %d", code)
	}
	if code := admin.do("PATCH", fmt.Sprintf("/api/v1/teams/%d", one.ID), map[string]any{
		"access": []any{map[string]any{"project_id": p.ID, "role": "viewer"}}}, nil); code != 204 {
		t.Errorf("access for the one team: %d", code)
	}
	if code := admin.do("POST", "/api/v1/users", map[string]any{"email": "m@x.io", "password": pw, "teams": []int64{one.ID}}, nil); code != 201 {
		t.Errorf("add to the one team: %d", code)
	}
}
