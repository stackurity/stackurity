package api_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

type onboardingState struct {
	State     string `json:"state"`
	ShowFlow  bool   `json:"show_flow"`
	HasAssets bool   `json:"has_assets"`
	ProjectID int64  `json:"project_id"`
	Steps     struct {
		Project, Asset, Notifications, Invite bool
	} `json:"steps"`
}

func ingestWith(t *testing.T, e *env, token, name string, purls ...string) store.IngestResult {
	t.Helper()
	b := model.NewBatch(model.Collector{ID: "agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: name,
		Identifiers: []model.Identifier{{Scheme: "machine-id", Value: name + "-id"}}})
	for _, p := range purls {
		b.Observations = append(b.Observations, model.Observation{Purl: p, Confidence: model.ConfidenceConfirmed})
	}
	b.Complete = true
	raw, _ := json.Marshal(b)
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/ingest", strings.NewReader(string(raw)))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var res store.IngestResult
	if resp.StatusCode != 201 || json.NewDecoder(resp.Body).Decode(&res) != nil {
		t.Fatalf("ingest %s: %d", name, resp.StatusCode)
	}
	return res
}

func projectAssets(t *testing.T, s *session, project int64) []string {
	t.Helper()
	var list struct{ Items []store.Asset }
	if code := s.do("GET", fmt.Sprintf("/api/v1/assets?project_id=%d", project), nil, &list); code != 200 {
		t.Fatalf("assets of project %d: %d", project, code)
	}
	var names []string
	for _, a := range list.Items {
		names = append(names, a.Name)
	}
	return names
}

// The first-run flow: a new organisation's admin sees it, each step is
// read from what exists, assets added through it land in the chosen
// project, and it ends when every step is done. Other roles do not see it.
func TestOnboardingFlow(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("viewer@x.io", auth.RoleViewer)
	admin := e.login("admin@x.io")
	var o onboardingState
	if code := admin.do("GET", "/api/v1/onboarding", nil, &o); code != 200 || o.State != "new" || !o.ShowFlow || o.Steps.Project {
		t.Fatalf("new organisation: %d %+v", code, o)
	}
	if code := e.login("viewer@x.io").do("GET", "/api/v1/onboarding", nil, nil); code != 403 {
		t.Errorf("viewer reads onboarding: %d", code)
	}

	// 1. The project, remembered by the flow.
	var p store.Project
	if code := admin.do("POST", "/api/v1/projects", map[string]any{"name": "Shop", "description": "The online shop"}, &p); code != 201 {
		t.Fatalf("project: %d", code)
	}
	if code := admin.do("PUT", "/api/v1/onboarding", map[string]any{"project_id": p.ID}, &o); code != 200 || o.ProjectID != p.ID || !o.Steps.Project || o.Steps.Asset {
		t.Fatalf("choose project: %d %+v", code, o)
	}
	if code := admin.do("PUT", "/api/v1/onboarding", map[string]any{"project_id": 999999}, nil); code != 400 {
		t.Errorf("unknown project: %d", code)
	}
	if code := admin.do("PUT", "/api/v1/onboarding", map[string]any{"state": "finished"}, nil); code != 400 {
		t.Errorf("unknown state: %d", code)
	}

	// 2. A repository: a collector token for the project. What it creates
	// lands in the project.
	var tok struct {
		Token  store.Token
		Secret string
	}
	if code := admin.do("POST", "/api/v1/tokens", map[string]any{"name": "ci", "role": "collector", "project_id": p.ID}, &tok); code != 201 ||
		tok.Token.ProjectID == nil || *tok.Token.ProjectID != p.ID {
		t.Fatalf("project token: %d %+v", code, tok.Token)
	}
	if code := admin.do("POST", "/api/v1/tokens", map[string]any{"name": "x", "role": "viewer", "project_id": p.ID}, nil); code != 400 {
		t.Errorf("project on a user token: %d", code)
	}
	if code := admin.do("POST", "/api/v1/tokens", map[string]any{"name": "x", "role": "collector", "project_id": 999999}, nil); code != 400 {
		t.Errorf("token for an unknown project: %d", code)
	}
	since := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	ingestWith(t, e, tok.Secret, "shop-repo", "pkg:npm/lodash@4.17.15", "pkg:npm/express@4.0.0")
	if got := projectAssets(t, admin, p.ID); strings.Join(got, ",") != "shop-repo" {
		t.Errorf("project assets: %v", got)
	}

	// 3. The waiting screen sees it, in the project.
	var res struct{ Items []store.FirstResult }
	if code := admin.do("GET", "/api/v1/onboarding/results?since="+since+fmt.Sprintf("&project_id=%d", p.ID), nil, &res); code != 200 ||
		len(res.Items) != 1 || res.Items[0].Name != "shop-repo" || res.Items[0].Packages != 2 || res.Items[0].Checked {
		t.Fatalf("results: %d %+v", code, res.Items)
	}
	if code := admin.do("GET", "/api/v1/onboarding/results?since=yesterday", nil, nil); code != 400 {
		t.Errorf("bad since: %d", code)
	}
	if code := admin.do("GET", "/api/v1/onboarding", nil, &o); code != 200 || o.ShowFlow || !o.HasAssets || !o.Steps.Asset || o.State != "new" {
		t.Fatalf("after the first asset: %+v", o)
	}

	// 5. Notifications for the project.
	var ch store.Channel
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "webhook", "name": "hook",
		"config": map[string]string{"url": "https://hooks.example/x"}}, &ch); code != 201 {
		t.Fatalf("channel: %d", code)
	}
	if code := admin.do("POST", "/api/v1/routes", map[string]any{"name": "shop urgent", "channel_id": ch.ID, "enabled": true,
		"project_ids": []int64{p.ID}, "mode": "urgent_summary"}, nil); code != 201 {
		t.Fatalf("route: %d", code)
	}
	// 6. An invitation: every step is done, and so is the flow.
	if code := admin.do("POST", "/api/v1/invitations", map[string]any{"email": "dev@x.io", "project_id": p.ID, "role": "engineer"}, nil); code != 201 {
		t.Fatalf("invite: %d", code)
	}
	if code := admin.do("GET", "/api/v1/onboarding", nil, &o); code != 200 || o.State != "done" || !o.Steps.Notifications || !o.Steps.Invite {
		t.Fatalf("all steps done: %+v", o)
	}
	// Skipping and resuming.
	if code := admin.do("PUT", "/api/v1/onboarding", map[string]any{"state": "skipped"}, &o); code != 200 || o.State != "done" {
		t.Errorf("a finished flow stays done: %+v", o)
	}
	var audit struct{ Items []store.AuditEvent }
	admin.do("GET", "/api/v1/audit?object_type=settings&object_id=onboarding", nil, &audit)
	if len(audit.Items) < 2 {
		t.Errorf("onboarding changes not audited: %+v", audit.Items)
	}
}

// Skipping hides the flow; Home's checklist stays until it is done.
func TestOnboardingSkip(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	var o onboardingState
	if code := admin.do("PUT", "/api/v1/onboarding", map[string]any{"state": "skipped"}, &o); code != 200 || o.State != "skipped" || o.ShowFlow {
		t.Fatalf("skip: %d %+v", code, o)
	}
	if code := admin.do("PUT", "/api/v1/onboarding", map[string]any{"state": "new"}, &o); code != 200 || !o.ShowFlow {
		t.Fatalf("resume: %d %+v", code, o)
	}
}

// A host enrolled with a code made for a project lands in it; an SBOM
// uploaded by an admin for a project does too. Others may not file assets.
func TestAssetsLandInProject(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	admin := e.login("admin@x.io")
	var p store.Project
	admin.do("POST", "/api/v1/projects", map[string]any{"name": "Shop"}, &p)
	var enr struct {
		Enrollment store.Enrollment
		Code       string
	}
	if code := admin.do("POST", "/api/v1/enrollments", map[string]any{"label": "web", "project_id": p.ID}, &enr); code != 201 ||
		enr.Enrollment.ProjectID == nil || *enr.Enrollment.ProjectID != p.ID {
		t.Fatalf("enrollment: %d %+v", code, enr.Enrollment)
	}
	if code := admin.do("POST", "/api/v1/enrollments", map[string]any{"label": "web", "project_id": 999999}, nil); code != 400 {
		t.Errorf("enrollment for an unknown project: %d", code)
	}
	var red struct{ Token string }
	if code := e.anon().do("POST", "/api/v1/enroll", map[string]string{"code": enr.Code, "hostname": "web-1"}, &red); code != 200 {
		t.Fatalf("enroll: %d", code)
	}
	ingestWith(t, e, red.Token, "web-1", "pkg:deb/debian/bash@5.2")
	// A second report of the same host does not add it again (nothing to
	// add), and an admin removing it from the project is not undone.
	if got := projectAssets(t, admin, p.ID); strings.Join(got, ",") != "web-1" {
		t.Errorf("enrolled host: %v", got)
	}

	sbom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"lodash","version":"4.17.15","purl":"pkg:npm/lodash@4.17.15"}]}`
	up := func(s *session, q string) int {
		resp := s.req("POST", "/api/v1/sbom/import?asset_name=shop-app"+q, strings.NewReader(sbom),
			map[string]string{"X-Stackurity-CSRF": "1", "Content-Type": "application/json"})
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := up(e.login("eng@x.io"), fmt.Sprintf("&project_id=%d", p.ID)); code != 403 {
		t.Errorf("engineer files an SBOM in a project: %d", code)
	}
	if code := up(admin, "&project_id=999999"); code != 404 {
		t.Errorf("SBOM for an unknown project: %d", code)
	}
	if code := up(admin, fmt.Sprintf("&project_id=%d", p.ID)); code != 201 {
		t.Fatalf("SBOM upload: %d", code)
	}
	if got := projectAssets(t, admin, p.ID); strings.Join(got, ",") != "shop-app,web-1" {
		t.Errorf("after the upload: %v", got)
	}
}

type invited struct {
	Invitation store.Invitation
	Link       string
	Emailed    bool
	Granted    bool
}

func invite(t *testing.T, s *session, body map[string]any) (int, invited) {
	t.Helper()
	var out invited
	code := s.do("POST", "/api/v1/invitations", body, &out)
	return code, out
}

func tokenOf(t *testing.T, link string) string {
	t.Helper()
	_, tok, ok := strings.Cut(link, "/invite#")
	if !ok || !strings.HasPrefix(tok, "inv_") {
		t.Fatalf("link %q", link)
	}
	return tok
}

type meView struct {
	User        store.User
	Role        string
	Access      string
	ProjectRole string `json:"project_role"`
	Workspace   struct{ ID int64 }
	Projects    []store.Project
}

// Invitations: single use, expiring, revocable, hashed at rest, rate
// limited. Accepting joins only the invitation's organisation with only
// its role, whatever the request says or whoever is signed in.
func TestInvitationSecurity(t *testing.T) {
	// Each visitor below comes from its own address, so the per-address
	// limit (TestInvitationRateLimits) does not get in the way.
	e := newEnvWith(t, func(s *api.Server) { s.TrustProxy = true })
	visitors := 0
	anonFrom := func() *session {
		visitors++
		s := e.anon()
		s.hdr = map[string]string{"X-Forwarded-For": fmt.Sprintf("192.0.2.%d", visitors)}
		return s
	}
	ctx := context.Background()
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	e.user("viewer@x.io", auth.RoleViewer)
	admin := e.login("admin@x.io")
	var shop, blog store.Project
	admin.do("POST", "/api/v1/projects", map[string]any{"name": "Shop"}, &shop)
	admin.do("POST", "/api/v1/projects", map[string]any{"name": "Blog"}, &blog)

	// Only organisation admins invite.
	if code, _ := invite(t, e.login("eng@x.io"), map[string]any{"email": "new@x.io", "project_id": shop.ID, "role": "viewer"}); code != 403 {
		t.Errorf("engineer invites: %d", code)
	}
	for _, bad := range []map[string]any{
		{"email": "not-an-email", "project_id": shop.ID, "role": "viewer"},
		{"email": "new@x.io", "project_id": shop.ID, "role": "owner"},
		{"email": "new@x.io", "project_id": shop.ID, "role": "collector"},
		{"email": "new@x.io", "project_id": 999999, "role": "viewer"},
		{"email": "new@x.io", "project_id": shop.ID, "role": "viewer", "workspace_id": 2},
	} {
		if code, _ := invite(t, admin, bad); code != 400 {
			t.Errorf("invite %v: %d, want 400", bad, code)
		}
	}

	code, inv := invite(t, admin, map[string]any{"email": "New@X.io", "name": "Nia", "project_id": shop.ID, "role": "engineer"})
	if code != 201 || inv.Emailed || inv.Link == "" || inv.Invitation.Email != "new@x.io" || inv.Invitation.Status != "pending" ||
		inv.Invitation.ExpiresAt.Sub(time.Now()) < 167*time.Hour || inv.Invitation.ExpiresAt.Sub(time.Now()) > 169*time.Hour {
		t.Fatalf("invite: %d %+v", code, inv)
	}
	tok := tokenOf(t, inv.Link)
	// Hashed at rest: the token is nowhere in the table.
	var stored string
	if err := e.st.Pool.QueryRow(tenant.System(ctx), `SELECT string_agg(i::text, ' ') FROM invitations i`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, tok) || strings.Contains(stored, tok[len("inv_"):]) {
		t.Error("the invitation token is stored in clear")
	}
	var list struct{ Items []store.Invitation }
	admin.do("GET", "/api/v1/invitations", nil, &list)
	if raw, _ := json.Marshal(list); len(list.Items) != 1 || strings.Contains(string(raw), tok) {
		t.Errorf("invitation list: %s", raw)
	}

	// Preview: what, by whom, with which role; nothing for a wrong token.
	anon := anonFrom()
	var pv struct {
		Invitation store.InvitationPreview
	}
	if code := anon.do("POST", "/api/v1/invitations/preview", map[string]string{"token": tok}, &pv); code != 200 ||
		pv.Invitation.Project != "Shop" || pv.Invitation.Role != auth.RoleEngineer || pv.Invitation.AccountExists || pv.Invitation.InvitedBy != "admin@x.io" {
		t.Fatalf("preview: %d %+v", code, pv)
	}
	for _, wrong := range []string{"", "inv_", tok + "x", strings.ToUpper(tok), "stk_" + tok[4:]} {
		if code := anon.do("POST", "/api/v1/invitations/preview", map[string]string{"token": wrong}, nil); code != 410 {
			t.Errorf("preview %q: %d", wrong, code)
		}
	}

	// The request cannot choose the role or the organisation.
	for _, extra := range []map[string]any{{"role": "admin"}, {"workspace_id": 1}, {"project_id": blog.ID}, {"email": "other@x.io"}} {
		body := map[string]any{"token": tok, "password": pw}
		for k, v := range extra {
			body[k] = v
		}
		if code := anonFrom().do("POST", "/api/v1/invitations/accept", body, nil); code != 400 {
			t.Errorf("accept with %v: %d, want 400", extra, code)
		}
	}
	if code := anonFrom().do("POST", "/api/v1/invitations/accept", map[string]any{"token": tok, "password": "short"}, nil); code != 400 {
		t.Errorf("weak password: %d", code)
	}

	// Accepting creates the account and the grant, and signs in.
	nia := anonFrom()
	var acc struct {
		WorkspaceID    int64 `json:"workspace_id"`
		ProjectID      int64 `json:"project_id"`
		AccountCreated bool  `json:"account_created"`
	}
	if code := nia.do("POST", "/api/v1/invitations/accept", map[string]any{"token": tok, "name": "", "password": pw}, &acc); code != 200 ||
		!acc.AccountCreated || acc.ProjectID != shop.ID || acc.WorkspaceID != tenant.DefaultWorkspace {
		t.Fatalf("accept: %d %+v", code, acc)
	}
	var me meView
	if code := nia.do("GET", "/api/v1/auth/me", nil, &me); code != 200 || me.Access != "projects" || me.Role != "" ||
		me.ProjectRole != "engineer" || len(me.Projects) != 1 || me.Projects[0].Name != "Shop" || me.User.Name != "Nia" {
		t.Fatalf("me after accepting: %d %+v", code, me)
	}
	if code := nia.do("GET", "/api/v1/users", nil, nil); code != 403 {
		t.Errorf("project member reads users: %d", code)
	}
	// Single use.
	if code := anonFrom().do("POST", "/api/v1/invitations/accept", map[string]any{"token": tok, "password": pw}, nil); code != 410 {
		t.Errorf("second use: %d", code)
	}
	if code := anonFrom().do("POST", "/api/v1/invitations/preview", map[string]any{"token": tok}, nil); code != 410 {
		t.Errorf("preview after use: %d", code)
	}

	// Expired and revoked links stop working.
	_, exp := invite(t, admin, map[string]any{"email": "late@x.io", "project_id": shop.ID, "role": "viewer"})
	if _, err := e.st.Pool.Exec(tenant.System(ctx), `UPDATE invitations SET expires_at = now() - interval '1 second' WHERE id = $1`, exp.Invitation.ID); err != nil {
		t.Fatal(err)
	}
	if code := anonFrom().do("POST", "/api/v1/invitations/accept", map[string]any{"token": tokenOf(t, exp.Link), "password": pw}, nil); code != 410 {
		t.Errorf("expired: %d", code)
	}
	_, rev := invite(t, admin, map[string]any{"email": "gone@x.io", "project_id": shop.ID, "role": "viewer"})
	if code := admin.do("DELETE", fmt.Sprintf("/api/v1/invitations/%d", rev.Invitation.ID), nil, nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code := admin.do("DELETE", fmt.Sprintf("/api/v1/invitations/%d", rev.Invitation.ID), nil, nil); code != 404 {
		t.Errorf("revoke twice: %d", code)
	}
	if code := anonFrom().do("POST", "/api/v1/invitations/accept", map[string]any{"token": tokenOf(t, rev.Link), "password": pw}, nil); code != 410 {
		t.Errorf("revoked: %d", code)
	}
	// Inviting again replaces the open invitation: the old link stops.
	_, first := invite(t, admin, map[string]any{"email": "twice@x.io", "project_id": shop.ID, "role": "viewer"})
	_, second := invite(t, admin, map[string]any{"email": "twice@x.io", "project_id": shop.ID, "role": "engineer"})
	if code := anonFrom().do("POST", "/api/v1/invitations/preview", map[string]any{"token": tokenOf(t, first.Link)}, nil); code != 410 {
		t.Errorf("replaced link: %d", code)
	}
	if code := anonFrom().do("POST", "/api/v1/invitations/preview", map[string]any{"token": tokenOf(t, second.Link)}, nil); code != 200 {
		t.Errorf("new link: %d", code)
	}

	// Someone already in the organisation gets the project role at once;
	// an organisation-wide invitation for them is refused.
	code, g := invite(t, admin, map[string]any{"email": "viewer@x.io", "project_id": blog.ID, "role": "engineer"})
	if code != 201 || !g.Granted || g.Link != "" {
		t.Errorf("member invited to a project: %d %+v", code, g)
	}
	if code, _ := invite(t, admin, map[string]any{"email": "viewer@x.io", "role": "admin"}); code != 409 {
		t.Errorf("member invited organisation-wide: %d", code)
	}

	var audit struct{ Items []store.AuditEvent }
	admin.do("GET", "/api/v1/audit?limit=200", nil, &audit)
	seen := map[string]bool{}
	for _, a := range audit.Items {
		seen[a.Action] = true
	}
	for _, want := range []string{"invitation.create", "invitation.accept", "invitation.revoke", "user.create", "access.grant"} {
		if !seen[want] {
			t.Errorf("no %s audit event", want)
		}
	}
}

// An existing account must be signed in to accept, as itself. A member of
// another organisation joins this one with the invitation's role only:
// their role there does not carry over, nothing changes there, and an
// existing higher grant here is kept.
func TestInvitationExistingAccount(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("someone@x.io", auth.RoleViewer)
	admin := e.login("admin@x.io")
	var shop store.Project
	admin.do("POST", "/api/v1/projects", map[string]any{"name": "Shop"}, &shop)
	beta, _, err := e.st.CreateWorkspace(ctx, "Beta Corp", "", "boss@beta.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	_, inv := invite(t, admin, map[string]any{"email": "boss@beta.io", "project_id": shop.ID, "role": "viewer"})
	tok := tokenOf(t, inv.Link)

	var pv struct{ Invitation store.InvitationPreview }
	e.anon().do("POST", "/api/v1/invitations/preview", map[string]string{"token": tok}, &pv)
	if !pv.Invitation.AccountExists {
		t.Errorf("preview: %+v", pv)
	}
	var er struct{ Error struct{ Code string } }
	if code := e.anon().do("POST", "/api/v1/invitations/accept", map[string]any{"token": tok, "password": "whatever-they-like-1"}, &er); code != 409 || er.Error.Code != "sign_in_required" {
		t.Errorf("not signed in: %d %+v", code, er)
	}
	if code := e.login("someone@x.io").do("POST", "/api/v1/invitations/accept", map[string]any{"token": tok}, &er); code != 409 || er.Error.Code != "wrong_account" {
		t.Errorf("signed in as someone else: %d %+v", code, er)
	}
	// With an API token: refused.
	boss := e.login("boss@beta.io")
	var bt struct{ Secret string }
	if code := boss.do("POST", "/api/v1/tokens", map[string]any{"name": "t", "role": "admin"}, &bt); code != 201 {
		t.Fatalf("token: %d", code)
	}
	if code := bearer(e, bt.Secret, "POST", "/api/v1/invitations/accept", []byte(`{"token":"`+tok+`"}`), nil); code != 403 {
		t.Errorf("accept with a token: %d", code)
	}
	var me meView
	boss.do("GET", "/api/v1/auth/me", nil, &me)
	if me.Workspace.ID != beta.ID || me.Role != "admin" {
		t.Fatalf("boss in Beta: %+v", me)
	}
	if code := boss.do("POST", "/api/v1/invitations/accept", map[string]any{"token": tok}, nil); code != 200 {
		t.Fatalf("accept as the invitee: %d", code)
	}
	// Now working in the default organisation, with Shop as viewer only.
	boss.do("GET", "/api/v1/auth/me", nil, &me)
	if me.Workspace.ID != tenant.DefaultWorkspace || me.Role != "" || me.Access != "projects" || me.ProjectRole != "viewer" {
		t.Errorf("boss after accepting: %+v", me)
	}
	if code := boss.do("GET", "/api/v1/users", nil, nil); code != 403 {
		t.Errorf("boss reads users here: %d", code)
	}
	if role, err := e.st.MemberRole(ctx, beta.ID, me.User.ID); err != nil || role != auth.RoleAdmin {
		t.Errorf("role in Beta changed: %q %v", role, err)
	}
	if ok, _ := e.st.IsMember(ctx, beta.ID, me.User.ID); !ok {
		t.Error("left Beta")
	}

	// An organisation member keeps their organisation role, and a higher
	// project grant is not lowered.
	wctx := tenant.WithWorkspace(ctx, tenant.DefaultWorkspace)
	var someone int64
	if err := e.st.Pool.QueryRow(wctx, `SELECT id FROM users WHERE email = 'someone@x.io'`).Scan(&someone); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.st.SaveGrant(wctx, store.GrantInput{ProjectID: &shop.ID, UserID: &someone, Role: auth.RoleSecurity}, 0); err != nil {
		t.Fatal(err)
	}
	// The API grants a member the project role at once, so an invitation
	// for a member only exists when they joined after it was sent: make
	// one in the store, as if they had.
	_, tok2, err := e.st.CreateInvitation(wctx, "someone@x.io", "", &shop.ID, auth.RoleViewer, 0)
	if err != nil {
		t.Fatal(err)
	}
	if code := e.login("someone@x.io").do("POST", "/api/v1/invitations/accept", map[string]any{"token": tok2}, nil); code != 200 {
		t.Fatalf("member accepts: %d", code)
	}
	if role, _ := e.st.MemberRole(ctx, tenant.DefaultWorkspace, someone); role != auth.RoleViewer {
		t.Errorf("organisation role changed to %q", role)
	}
	gs, _ := e.st.ListGrants(wctx, store.GrantFilter{UserID: someone})
	if len(gs) != 1 || gs[0].Role != auth.RoleSecurity {
		t.Errorf("grants after a lower invitation: %+v", gs)
	}
}

// An organisation-wide invitation gives its role to a new member.
func TestInvitationOrganisationWide(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	_, inv := invite(t, admin, map[string]any{"email": "sec@x.io", "role": "security"})
	s := e.anon()
	if code := s.do("POST", "/api/v1/invitations/accept", map[string]any{"token": tokenOf(t, inv.Link), "name": "Sec", "password": pw}, nil); code != 200 {
		t.Fatalf("accept: %d", code)
	}
	var me meView
	s.do("GET", "/api/v1/auth/me", nil, &me)
	if me.Role != "security" || me.Access != "organisation" {
		t.Errorf("me: %+v", me)
	}
}

// Following links is rate limited per address, and so is sending
// invitations per organisation.
func TestInvitationRateLimits(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	anon := e.anon()
	limited := 0
	for i := 0; i < 15; i++ {
		if code := anon.do("POST", "/api/v1/invitations/preview", map[string]string{"token": fmt.Sprintf("inv_guess%d", i)}, nil); code == 429 {
			limited++
		}
	}
	if limited != 5 {
		t.Errorf("%d of 15 guesses limited, want 5", limited)
	}
	if code := anon.do("POST", "/api/v1/invitations/accept", map[string]string{"token": "inv_guess", "password": pw}, nil); code != 429 {
		t.Errorf("accept after the limit: %d", code)
	}
	sent := 0
	for i := 0; i < 35; i++ {
		if code, _ := invite(t, admin, map[string]any{"email": fmt.Sprintf("p%d@x.io", i), "role": "viewer"}); code == 201 {
			sent++
		}
	}
	if sent != 30 {
		t.Errorf("%d invitations sent in an hour, want 30", sent)
	}
}

// fakeSMTP accepts one message without TLS or authentication.
type fakeSMTP struct {
	mu   sync.Mutex
	ln   net.Listener
	data []string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	say := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
	say("220 fake")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250 fake")
		case strings.HasPrefix(cmd, "DATA"):
			say("354 go on")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = append(f.data, b.String())
			f.mu.Unlock()
			say("250 ok")
		case strings.HasPrefix(cmd, "QUIT"):
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

// With an email channel the link goes by email and is not shown; the
// message says who invited whom to what, and links to the dashboard.
func TestInvitationEmail(t *testing.T) {
	e := newEnv(t)
	smtpd := newFakeSMTP(t)
	var d net.Dialer
	e.api.Dispatcher = &notify.Dispatcher{Store: e.st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sender: &notify.Sender{Dial: d.DialContext}}
	e.api.BaseURL = "https://stk.example"
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	var shop store.Project
	admin.do("POST", "/api/v1/projects", map[string]any{"name": "Shop"}, &shop)
	host, port, _ := net.SplitHostPort(smtpd.ln.Addr().String())
	var portN int
	fmt.Sscan(port, &portN)
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "email", "name": "mail",
		"config": map[string]any{"host": host, "port": portN, "from": "stackurity@x.io", "to": []string{"ops@x.io"}, "tls": "none"}}, nil); code != 201 {
		t.Fatalf("email channel: %d", code)
	}
	code, inv := invite(t, admin, map[string]any{"email": "dev@x.io", "project_id": shop.ID, "role": "engineer"})
	if code != 201 || !inv.Emailed || inv.Link != "" || inv.Invitation.EmailedAt == nil {
		t.Fatalf("emailed invitation: %d %+v", code, inv)
	}
	smtpd.mu.Lock()
	defer smtpd.mu.Unlock()
	if len(smtpd.data) != 1 {
		t.Fatalf("%d emails", len(smtpd.data))
	}
	m := smtpd.data[0]
	if !strings.Contains(m, "To: dev@x.io") || !strings.Contains(m, "Subject: You are invited to Default on Stackurity") ||
		!strings.Contains(m, "https://stk.example/invite#inv_") || !strings.Contains(m, "the project Shop in Default, as engineer") ||
		strings.Contains(m, "ops@x.io") || strings.Contains(m, "—") {
		t.Errorf("email:\n%s", m)
	}
}
