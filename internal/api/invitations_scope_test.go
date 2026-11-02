package api_test

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

type scopedInvite struct {
	Invitation store.Invitation
	Link       string
	Granted    bool
	Grants     []store.Grant
	Replaced   []int64
}

type acceptedView struct {
	ProjectID int64  `json:"project_id"`
	Scope     string `json:"scope"`
	Grants    int    `json:"grants"`
	Dropped   []store.InvitationGrant
	Joined    bool
}

// TestInvitationScope: an invitation says what the person will see, like
// Add user: an organisation-wide role, or grants on chosen projects and
// assets with a role each. There is no default; another organisation's
// project or asset is refused; accepting gives everything in one
// transaction, after checking again that each project is still active and
// each asset unmerged: stale ones are dropped and reported, and when
// nothing is left accepting is refused and nothing is written. Invitations
// made before grants existed (one project, one role) still work.
func TestInvitationScope(t *testing.T) {
	e := newEnvWith(t, func(s *api.Server) { s.TrustProxy = true })
	visitors := 0
	anon := func() *session {
		visitors++
		s := e.anon()
		s.hdr = map[string]string{"CF-Connecting-IP": fmt.Sprintf("198.51.100.%d", visitors)}
		return s
	}
	bg := context.Background()
	a := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	wsB, _, err := e.st.CreateWorkspace(bg, "Beta", "", "beta@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	b := tenant.WithWorkspace(bg, wsB.ID)
	asset := func(ctx context.Context, id string) int64 {
		bt := model.NewBatch(model.Collector{ID: "t", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: id,
			Identifiers: []model.Identifier{{Scheme: "machine-id", Value: id}}})
		r, err := e.st.Ingest(ctx, bt, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}
	a1, a2, a3, a4, b1 := asset(a, "a1"), asset(a, "a2"), asset(a, "a3"), asset(a, "a4"), asset(b, "b1")
	project := func(ctx context.Context, name string, assets ...int64) int64 {
		p, err := e.st.CreateProject(ctx, name, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(assets) > 0 {
			if _, err := e.st.AddProjectAssets(ctx, p.ID, assets); err != nil {
				t.Fatal(err)
			}
		}
		return p.ID
	}
	shop, blog, docs, projB := project(a, "Shop", a1), project(a, "Blog"), project(a, "Docs"), project(b, "Other")
	archive := func(id int64) {
		yes := true
		if err := e.st.UpdateProject(a, id, store.ProjectUpdate{Archived: &yes}); err != nil {
			t.Fatal(err)
		}
	}
	pg := func(id int64, role string) map[string]any { return map[string]any{"project_id": id, "role": role} }
	ag := func(id int64, role string) map[string]any { return map[string]any{"asset_id": id, "role": role} }
	inviteScoped := func(body map[string]any) (int, scopedInvite) {
		t.Helper()
		var out scopedInvite
		code := admin.do("POST", "/api/v1/invitations", body, &out)
		return code, out
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := e.st.Pool.QueryRow(tenant.System(bg), sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
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
	accept := func(link, password string) (int, acceptedView, *session) {
		t.Helper()
		s := anon()
		var out acceptedView
		code := s.do("POST", "/api/v1/invitations/accept", map[string]any{"token": tokenOf(t, link), "name": "N", "password": password}, &out)
		return code, out, s
	}

	// No scope, an ambiguous one, or another organisation's project or
	// asset: 400, and no invitation is made.
	for name, body := range map[string]map[string]any{
		"nothing":                        {"email": "n@x.io"},
		"role none":                      {"email": "n@x.io", "role": "none"},
		"empty grants":                   {"email": "n@x.io", "grants": []any{}},
		"role and grants":                {"email": "n@x.io", "role": "viewer", "grants": []any{pg(shop, "viewer")}},
		"project_id and grants":          {"email": "n@x.io", "project_id": shop, "role": "viewer", "grants": []any{pg(blog, "viewer")}},
		"grant without a role":           {"email": "n@x.io", "grants": []any{map[string]any{"project_id": shop}}},
		"grant naming both":              {"email": "n@x.io", "grants": []any{map[string]any{"project_id": shop, "asset_id": a2, "role": "viewer"}}},
		"another organisation's asset":   {"email": "n@x.io", "grants": []any{pg(shop, "viewer"), ag(b1, "engineer")}},
		"another organisation's project": {"email": "n@x.io", "grants": []any{ag(a2, "viewer"), pg(projB, "viewer")}},
		"no such project":                {"email": "n@x.io", "grants": []any{pg(999999, "viewer")}},
	} {
		if code, _ := inviteScoped(body); code != 400 {
			t.Errorf("%s: %d, want 400", name, code)
		}
	}
	if n := count(`SELECT count(*) FROM invitations`); n != 0 {
		t.Fatalf("%d invitations made by refused requests", n)
	}

	// Specific: a whole project, an asset and another project, each with
	// its own role.
	code, spec := inviteScoped(map[string]any{"email": "spec@x.io", "name": "Spec",
		"grants": []any{pg(shop, "viewer"), ag(a2, "engineer"), pg(blog, "security")}})
	if code != 201 || spec.Invitation.Scope != "specific" || spec.Invitation.Role != "" || spec.Invitation.ProjectID != nil ||
		len(spec.Invitation.Grants) != 3 || len(spec.Replaced) != 0 {
		t.Fatalf("specific invitation: %d %+v", code, spec)
	}
	// It is listed under each project it names (a project's Invite page).
	for _, p := range []int64{shop, blog} {
		var list struct{ Items []store.Invitation }
		admin.do("GET", fmt.Sprintf("/api/v1/invitations?project_id=%d", p), nil, &list)
		if len(list.Items) != 1 || list.Items[0].ID != spec.Invitation.ID || len(list.Items[0].Grants) != 3 {
			t.Errorf("invitations of project %d: %+v", p, list.Items)
		}
	}
	var pv struct{ Invitation store.InvitationPreview }
	if code := anon().do("POST", "/api/v1/invitations/preview", map[string]string{"token": tokenOf(t, spec.Link)}, &pv); code != 200 ||
		pv.Invitation.Scope != "specific" || !pv.Invitation.Usable || len(pv.Invitation.Grants) != 3 {
		t.Fatalf("preview: %d %+v", code, pv)
	}
	// Atomic: a refused accept (password too short) writes nothing.
	if code, _, _ := accept(spec.Link, "short"); code != 400 {
		t.Fatalf("short password: %d", code)
	}
	if ok, _ := e.st.UserExists(a, "spec@x.io"); ok {
		t.Fatal("an account was made by a refused accept")
	}
	if n := count(`SELECT count(*) FROM access_grants`); n != 0 {
		t.Fatalf("%d grants after a refused accept", n)
	}
	code, acc, specS := accept(spec.Link, pw)
	if code != 200 || acc.Scope != "specific" || acc.Grants != 3 || len(acc.Dropped) != 0 || !acc.Joined || acc.ProjectID != 0 {
		t.Fatalf("accept: %d %+v", code, acc)
	}
	var me meView
	specS.do("GET", "/api/v1/auth/me", nil, &me)
	if me.Access != "projects" || me.Role != "" || me.ProjectRole != "security" {
		t.Errorf("me after accepting: %+v", me)
	}
	if got := sees(specS); len(got) != 2 || got[0] != a1 || got[1] != a2 {
		t.Errorf("sees %v, want [%d %d]", got, a1, a2)
	}
	if code := specS.do("PATCH", fmt.Sprintf("/api/v1/assets/%d", a2), map[string]any{"criticality": "high"}, nil); code != 200 {
		t.Errorf("engineer on a2: %d", code)
	}
	if code := specS.do("PATCH", fmt.Sprintf("/api/v1/assets/%d", a1), map[string]any{"criticality": "high"}, nil); code != 403 {
		t.Errorf("viewer on a1 (through Shop): %d", code)
	}
	if n := count(`SELECT count(*) FROM audit_events WHERE action = 'access.grant'`); n != 3 {
		t.Errorf("%d access.grant events, want 3", n)
	}
	// The link works once.
	if code, _, _ := accept(spec.Link, pw); code != 410 {
		t.Errorf("second accept: %d", code)
	}

	// Already a member: the grants are given at once, together.
	var given scopedInvite
	if code := admin.do("POST", "/api/v1/invitations", map[string]any{"email": "spec@x.io", "grants": []any{ag(a4, "security"), pg(docs, "viewer")}}, &given); code != 201 ||
		!given.Granted || len(given.Grants) != 2 {
		t.Fatalf("member: %d %+v", code, given)
	}
	if code, _ := inviteScoped(map[string]any{"email": "spec@x.io", "role": "viewer"}); code != 409 {
		t.Errorf("organisation-wide for a member: %d", code)
	}
	if code, _ := inviteScoped(map[string]any{"email": "spec@x.io", "grants": []any{ag(a3, "viewer"), ag(b1, "viewer")}}); code != 400 {
		t.Errorf("member, another organisation's asset: %d", code)
	}
	if got := sees(specS); len(got) != 3 {
		t.Errorf("after the member grants: %v (a3 must not have been given)", got)
	}

	// Stale grants are dropped, with what and why.
	code, stale := inviteScoped(map[string]any{"email": "stale@x.io", "grants": []any{pg(shop, "viewer"), pg(blog, "viewer"), ag(a3, "engineer")}})
	if code != 201 {
		t.Fatalf("stale invitation: %d", code)
	}
	archive(blog)
	if err := e.st.DeleteAsset(a, a3); err != nil {
		t.Fatal(err)
	}
	anon().do("POST", "/api/v1/invitations/preview", map[string]string{"token": tokenOf(t, stale.Link)}, &pv)
	if !pv.Invitation.Usable || len(pv.Invitation.Grants) != 3 {
		t.Fatalf("stale preview: %+v", pv.Invitation)
	}
	why := map[string]string{}
	for _, g := range pv.Invitation.Grants {
		why[g.Name] = g.Unavailable
	}
	if why["Shop"] != "" || why["Blog"] != "archived" || why["a3"] != "deleted" {
		t.Errorf("preview availability: %v", why)
	}
	code, acc, staleS := accept(stale.Link, pw)
	if code != 200 || acc.Grants != 1 || len(acc.Dropped) != 2 || acc.ProjectID != shop {
		t.Fatalf("accept with stale grants: %d %+v", code, acc)
	}
	if got := sees(staleS); len(got) != 1 || got[0] != a1 {
		t.Errorf("sees %v, want only a1", got)
	}

	// A merged asset is dropped too.
	code, merged := inviteScoped(map[string]any{"email": "merged@x.io", "grants": []any{ag(a1, "viewer"), ag(a2, "viewer")}})
	if code != 201 {
		t.Fatal(code)
	}
	if _, err := e.st.Pool.Exec(tenant.System(bg), `UPDATE assets SET merged_into = $1 WHERE id = $2`, a1, a2); err != nil {
		t.Fatal(err)
	}
	if code, acc, _ := accept(merged.Link, pw); code != 200 || acc.Grants != 1 || len(acc.Dropped) != 1 || acc.Dropped[0].Unavailable != "merged" {
		t.Errorf("merged asset: %d %+v", code, acc)
	}

	// Nothing left: refused (fail closed), and nothing is written.
	code, gone := inviteScoped(map[string]any{"email": "gone@x.io", "grants": []any{pg(docs, "viewer")}})
	if code != 201 {
		t.Fatal(code)
	}
	archive(docs)
	anon().do("POST", "/api/v1/invitations/preview", map[string]string{"token": tokenOf(t, gone.Link)}, &pv)
	if pv.Invitation.Usable {
		t.Errorf("preview of an invitation with nothing left: %+v", pv.Invitation)
	}
	var problem struct{ Error struct{ Code string } }
	if code := anon().do("POST", "/api/v1/invitations/accept", map[string]any{"token": tokenOf(t, gone.Link), "password": pw}, &problem); code != 410 ||
		problem.Error.Code != "invitation_stale" {
		t.Errorf("accept with nothing left: %d %+v", code, problem)
	}
	if ok, _ := e.st.UserExists(a, "gone@x.io"); ok {
		t.Error("an account was made for an invitation that gives nothing")
	}
	if inv, err := e.st.GetInvitation(a, gone.Invitation.ID); err != nil || inv.Status != "pending" {
		t.Errorf("the invitation after a refused accept: %+v %v", inv, err)
	}

	// All projects and assets.
	code, org := inviteScoped(map[string]any{"email": "org@x.io", "role": "security"})
	if code != 201 || org.Invitation.Scope != "organisation" || org.Invitation.Role != auth.RoleSecurity || len(org.Invitation.Grants) != 0 {
		t.Fatalf("organisation-wide: %d %+v", code, org)
	}
	// Inviting again replaces the open invitation.
	code, again := inviteScoped(map[string]any{"email": "org@x.io", "grants": []any{pg(shop, "engineer")}})
	if code != 201 || len(again.Replaced) != 1 || again.Replaced[0] != org.Invitation.ID {
		t.Fatalf("replace: %d %+v", code, again)
	}
	if code, _, _ := accept(org.Link, pw); code != 410 {
		t.Errorf("the replaced link: %d", code)
	}
	code, org = inviteScoped(map[string]any{"email": "org@x.io", "role": "security"})
	if code != 201 || len(org.Replaced) != 1 {
		t.Fatal(code, org)
	}
	code, _, orgS := accept(org.Link, pw)
	orgS.do("GET", "/api/v1/auth/me", nil, &me)
	if code != 200 || me.Role != "security" || me.Access != "organisation" {
		t.Errorf("organisation-wide accept: %d %+v", code, me)
	}

	// An invitation made before grants existed: one project, one role.
	secret, prefix, err := auth.NewToken("inv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool.Exec(a, `INSERT INTO invitations (email, project_id, role, prefix, token_hash, expires_at)
		VALUES ('old@x.io', $1, 'engineer', $2, $3, $4)`, shop, prefix, auth.HashToken(secret), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	link := "https://x/invite#" + secret
	anon().do("POST", "/api/v1/invitations/preview", map[string]string{"token": secret}, &pv)
	if pv.Invitation.Scope != "project" || pv.Invitation.Project != "Shop" || pv.Invitation.Role != auth.RoleEngineer || len(pv.Invitation.Grants) != 1 {
		t.Errorf("old-format preview: %+v", pv.Invitation)
	}
	code, acc, oldS := accept(link, pw)
	if code != 200 || acc.Scope != "project" || acc.ProjectID != shop || acc.Grants != 1 {
		t.Fatalf("old-format accept: %d %+v", code, acc)
	}
	oldS.do("GET", "/api/v1/auth/me", nil, &me)
	if me.Access != "projects" || me.ProjectRole != "engineer" {
		t.Errorf("old-format member: %+v", me)
	}

	// The single-project form of the request still works.
	if code, inv := inviteScoped(map[string]any{"email": "one@x.io", "project_id": shop, "role": "viewer"}); code != 201 ||
		inv.Invitation.Scope != "specific" || len(inv.Invitation.Grants) != 1 || *inv.Invitation.Grants[0].ProjectID != shop {
		t.Errorf("project_id form: %d %+v", code, inv)
	}
	// Workspace B sees none of A's invitations or their grants.
	if n := count(`SELECT count(*) FROM invitation_grants WHERE workspace_id = $1`, wsB.ID); n != 0 {
		t.Errorf("%d grants in B", n)
	}
	if rows, err := e.st.ListInvitations(b, 0); err != nil || len(rows) != 0 {
		t.Errorf("B's list: %+v %v", rows, err)
	}
}

// TestInviteOnlyFlag: /auth/me says when people join by invitation only, so
// the dashboard offers Invite instead of Add user.
func TestInviteOnlyFlag(t *testing.T) {
	for _, only := range []bool{false, true} {
		e := newEnvWith(t, func(s *api.Server) { s.InviteOnly = only })
		e.user("admin@x.io", auth.RoleAdmin)
		admin := e.login("admin@x.io")
		var me struct {
			InviteOnly bool `json:"invite_only"`
		}
		admin.do("GET", "/api/v1/auth/me", nil, &me)
		if me.InviteOnly != only {
			t.Errorf("invite_only %v: me says %v", only, me.InviteOnly)
		}
		want := 201
		if only {
			want = 403
		}
		if code := admin.do("POST", "/api/v1/users", map[string]any{"email": "u@x.io", "role": "viewer", "password": pw}, nil); code != want {
			t.Errorf("invite_only %v: POST /users %d, want %d", only, code, want)
		}
		if code, _ := invite(t, admin, map[string]any{"email": "i@x.io", "role": "viewer"}); code != 201 {
			t.Errorf("invite_only %v: invitation %d", only, code)
		}
	}
}

// TestAccessGrantInviteOnly: on an invite-only server (Stackurity Cloud),
// giving access by email to someone who is not a member is refused, as
// POST /users is: it would add them, and make an account with a password
// the admin chose, without the invitation that proves they own the
// address. Members can still be given access that way.
func TestAccessGrantInviteOnly(t *testing.T) {
	e := newEnvWith(t, func(s *api.Server) { s.InviteOnly = true })
	a := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("member@x.io", store.RoleNone)
	admin := e.login("admin@x.io")
	p, err := e.st.CreateProject(a, "Shop", "")
	if err != nil {
		t.Fatal(err)
	}
	var problem struct{ Error struct{ Code string } }
	if code := admin.do("POST", "/api/v1/access-grants", map[string]any{"email": "new@x.io", "password": pw, "project_id": p.ID, "role": "viewer"}, &problem); code != 403 ||
		problem.Error.Code != "invite_only" {
		t.Errorf("new person: %d %+v", code, problem)
	}
	if ok, _ := e.st.UserExists(a, "new@x.io"); ok {
		t.Error("an account was made on an invite-only server")
	}
	var out struct{ Grant store.Grant }
	if code := admin.do("POST", "/api/v1/access-grants", map[string]any{"email": "Member@X.io", "project_id": p.ID, "role": "viewer"}, &out); code != 201 ||
		out.Grant.UserEmail != "member@x.io" {
		t.Errorf("member: %d %+v", code, out)
	}
}
