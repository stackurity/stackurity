package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// estate is what one workspace owns in the isolation tests. Every name
// contains the workspace's tag, so a leak shows up as the tag in a response.
type estate struct {
	ws                             int64
	admin                          *session
	adminID, collectorTokenID      int64
	collector                      string
	asset, component               int64
	team, channel, route           int64
	integration, enrollment, jobID int64
}

func (e *env) populate(t *testing.T, ws int64, tag string, admin *session, adminID int64) *estate {
	t.Helper()
	ctx := tenant.WithWorkspace(context.Background(), ws)
	es := &estate{ws: ws, admin: admin, adminID: adminID}
	tok, secret, err := e.st.CreateToken(ctx, "collector-"+tag, auth.RoleCollector, nil, adminID, 0)
	if err != nil {
		t.Fatal(err)
	}
	es.collector, es.collectorTokenID = secret, tok.ID

	b := model.NewBatch(model.Collector{ID: "agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "host-" + tag,
		Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "shared-machine-id"}}})
	b.Observations = []model.Observation{
		{Purl: "pkg:npm/" + tag + "-private-lib@1.0.0", Confidence: model.ConfidenceConfirmed},
		{Purl: "pkg:deb/debian/bash@5.2", Confidence: model.ConfidenceConfirmed},
	}
	raw, _ := json.Marshal(b)
	if code := bearer(e, secret, "POST", "/api/v1/ingest", raw, nil); code != 201 {
		t.Fatalf("%s ingest: %d", tag, code)
	}
	var assets struct{ Items []store.Asset }
	admin.do("GET", "/api/v1/assets", nil, &assets)
	if len(assets.Items) != 1 {
		t.Fatalf("%s assets: %+v", tag, assets.Items)
	}
	es.asset = assets.Items[0].ID
	var comps struct{ Items []map[string]any }
	admin.do("GET", "/api/v1/components?q="+tag, nil, &comps)
	if len(comps.Items) != 1 {
		t.Fatalf("%s components: %+v", tag, comps.Items)
	}
	es.component = int64(comps.Items[0]["id"].(float64))

	var team store.Team
	if code := admin.do("POST", "/api/v1/teams", map[string]any{"name": "team-" + tag}, &team); code != 201 {
		t.Fatalf("%s team: %d", tag, code)
	}
	es.team = team.ID
	var ch store.Channel
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "webhook", "name": "chan-" + tag,
		"config": map[string]string{"url": "https://hooks.example/" + tag}}, &ch); code != 201 {
		t.Fatalf("%s channel: %d", tag, code)
	}
	es.channel = ch.ID
	var rt struct{ ID int64 }
	if code := admin.do("POST", "/api/v1/routes", map[string]any{"name": "route-" + tag, "channel_id": ch.ID, "enabled": true,
		"min_priority": "P2"}, &rt); code != 201 {
		t.Fatalf("%s route: %d", tag, code)
	}
	es.route = rt.ID
	var in store.Integration
	if code := admin.do("POST", "/api/v1/integrations", map[string]any{"kind": "git_repository",
		"config": map[string]string{"url": "https://github.com/" + tag + "/repo"}}, &in); code != 201 {
		t.Fatalf("%s integration: %d", tag, code)
	}
	es.integration = in.ID
	var run struct {
		JobID int64 `json:"job_id"`
	}
	if code := admin.do("POST", fmt.Sprintf("/api/v1/integrations/%d/run", in.ID), nil, &run); code != 202 {
		t.Fatalf("%s run: %d", tag, code)
	}
	es.jobID = run.JobID
	var enr struct{ Enrollment store.Enrollment }
	if code := admin.do("POST", "/api/v1/enrollments", map[string]any{"label": "enr-" + tag}, &enr); code != 201 {
		t.Fatalf("%s enrollment: %d", tag, code)
	}
	es.enrollment = enr.Enrollment.ID
	return es
}

// TestWorkspaceIsolation signs in to workspace B and tries to read, change
// and delete everything workspace A owns, by listing, by guessing ids and
// through shared identifiers.
func TestWorkspaceIsolation(t *testing.T) {
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
	// A is at its monitored-asset limit and refused a host named for it.
	if err := e.st.SetAssetLimit(ctx, tenant.DefaultWorkspace, new(int64(1))); err != nil {
		t.Fatal(err)
	}
	if code, _ := bearerBody(e, a.collector, "POST", "/api/v1/ingest", hostBatch(model.AssetHost, "refused-alpha", "machine-id")); code != 402 {
		t.Fatalf("alpha refused host: %d", code)
	}
	// A is also read-only, in trial mode and at a project limit, with a
	// reason naming it: B sees none of that, and B still collects and
	// reports in full (checked below, then A is writable again).
	alphaSince := time.Now()
	if err := e.st.SetReadOnly(ctx, tenant.DefaultWorkspace, &alphaSince, "alpha's trial ended"); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetReportMode(ctx, tenant.DefaultWorkspace, store.ReportTrial); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetProjectLimit(ctx, tenant.DefaultWorkspace, new(int64(0))); err != nil {
		t.Fatal(err)
	}
	if code, body := bearerBody(e, a.collector, "POST", "/api/v1/ingest", hostBatch(model.AssetHost, "alpha-ro", "machine-id")); code != 402 ||
		!strings.Contains(body, "read_only") {
		t.Fatalf("alpha read-only ingest: %d %s", code, body)
	}
	if code, body := bearerBody(e, b.collector, "POST", "/api/v1/ingest", hostBatch(model.AssetHost, "beta-new", "machine-id")); code != 201 {
		t.Errorf("beta ingest while alpha is read-only: %d %s", code, body)
	}
	if code := betaSess.do("POST", "/api/v1/projects", map[string]any{"name": "beta-new"}, nil); code != 201 {
		t.Errorf("beta project while alpha is at its project limit: %d", code)
	}
	var betaUsage store.AssetUsage
	if betaSess.do("GET", "/api/v1/usage", nil, &betaUsage); betaUsage.ReadOnly != nil || betaUsage.ReportMode != "full" || betaUsage.ProjectLimit != nil {
		t.Errorf("beta usage while alpha is read-only: %+v", betaUsage)
	}
	var betaOutcomes map[string]any
	if betaSess.do("GET", "/api/v1/reports/outcomes", nil, &betaOutcomes); betaOutcomes["trial"] != nil {
		t.Errorf("beta's outcomes report is in trial mode: %v", betaOutcomes["trial"])
	}
	for _, get := range []string{"/api/v1/auth/me", "/api/v1/usage", "/api/v1/workspaces"} {
		resp := betaSess.req("GET", get, nil, nil)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(strings.ToLower(string(body)), "alpha") || strings.Contains(string(body), `"trial"`) {
			t.Errorf("GET %s from beta shows alpha's state: %s", get, body)
		}
	}
	if err := e.st.SetReadOnly(ctx, tenant.DefaultWorkspace, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetReportMode(ctx, tenant.DefaultWorkspace, store.ReportFull); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetProjectLimit(ctx, tenant.DefaultWorkspace, nil); err != nil {
		t.Fatal(err)
	}
	if a.asset == b.asset || a.component == b.component {
		t.Fatalf("the shared machine id merged the workspaces' hosts or private components: %+v %+v", a, b)
	}

	get := func(s *session, path string) (int, string) {
		resp := s.req("GET", path, nil, nil)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	// Lists seen from B never mention A.
	for _, path := range append([]string{
		"/api/v1/overview", "/api/v1/facets", "/api/v1/assets", "/api/v1/components", "/api/v1/components?q=alpha",
		"/api/v1/inventory", "/api/v1/findings", "/api/v1/findings/summary", "/api/v1/fix-groups", "/api/v1/evaluation-gaps",
		"/api/v1/incidents", "/api/v1/coverage", "/api/v1/teams", "/api/v1/users", "/api/v1/users/directory", "/api/v1/tokens",
		"/api/v1/audit", "/api/v1/channels", "/api/v1/routes", "/api/v1/deliveries", "/api/v1/integrations", "/api/v1/jobs",
		"/api/v1/enrollments", "/api/v1/conflicts", "/api/v1/remediation/policies", "/api/v1/remediation/plans",
		"/api/v1/reports/evidence", "/api/v1/reports/outcomes", "/api/v1/workspaces", "/api/v1/auth/me", "/api/v1/usage",
	}, editionIsolationLists...) {
		code, body := get(betaSess, path)
		if code >= 500 {
			t.Errorf("GET %s: %d %s", path, code, body)
		}
		if strings.Contains(strings.ToLower(body), "alpha") {
			t.Errorf("GET %s from beta mentions alpha: %s", path, body)
		}
	}

	// Lists under A's asset are empty from B.
	for _, path := range []string{fmt.Sprintf("/api/v1/assets/%d/inventory", a.asset), fmt.Sprintf("/api/v1/assets/%d/coverage", a.asset),
		fmt.Sprintf("/api/v1/assets/%d/collections", a.asset), fmt.Sprintf("/api/v1/assets/%d/relations", a.asset),
		fmt.Sprintf("/api/v1/assets/%d/remediation", a.asset)} {
		code, body := get(betaSess, path)
		if (code != 404 && code != 200) || strings.Contains(body, `"id"`) || strings.Contains(strings.ToLower(body), "alpha") {
			t.Errorf("GET %s from beta: %d %s", path, code, body)
		}
	}

	// A's objects by id are not found from B.
	for _, path := range []string{
		fmt.Sprintf("/api/v1/assets/%d", a.asset), fmt.Sprintf("/api/v1/assets/%d/stack", a.asset),
		fmt.Sprintf("/api/v1/assets/%d/sbom", a.asset), fmt.Sprintf("/api/v1/assets/%d/drift", a.asset),
		fmt.Sprintf("/api/v1/components/%d", a.component), fmt.Sprintf("/api/v1/components/%d/intel", a.component),
		fmt.Sprintf("/api/v1/jobs/%d", a.jobID),
	} {
		code, body := get(betaSess, path)
		if code != 404 || strings.Contains(strings.ToLower(body), "alpha") {
			t.Errorf("GET %s from beta: %d %s", path, code, body)
		}
	}

	// Changes and deletions aimed at A's ids from B do nothing.
	for _, m := range []struct {
		method, path string
		body         any
	}{
		{"PATCH", fmt.Sprintf("/api/v1/assets/%d", a.asset), map[string]any{"environment": "hacked"}},
		{"DELETE", fmt.Sprintf("/api/v1/assets/%d", a.asset), nil},
		{"PATCH", fmt.Sprintf("/api/v1/teams/%d", a.team), map[string]any{"name": "hacked"}},
		{"DELETE", fmt.Sprintf("/api/v1/teams/%d", a.team), nil},
		{"PATCH", fmt.Sprintf("/api/v1/channels/%d", a.channel), map[string]any{"enabled": false}},
		{"DELETE", fmt.Sprintf("/api/v1/channels/%d", a.channel), nil},
		{"DELETE", fmt.Sprintf("/api/v1/routes/%d", a.route), nil},
		{"PATCH", fmt.Sprintf("/api/v1/integrations/%d", a.integration), map[string]any{"enabled": false}},
		{"POST", fmt.Sprintf("/api/v1/integrations/%d/run", a.integration), nil},
		{"DELETE", fmt.Sprintf("/api/v1/integrations/%d", a.integration), nil},
		{"DELETE", fmt.Sprintf("/api/v1/enrollments/%d", a.enrollment), nil},
		{"DELETE", fmt.Sprintf("/api/v1/tokens/%d", a.collectorTokenID), nil},
		{"PATCH", fmt.Sprintf("/api/v1/users/%d", a.adminID), map[string]any{"role": "viewer"}},
		{"DELETE", fmt.Sprintf("/api/v1/users/%d", a.adminID), nil},
		{"POST", fmt.Sprintf("/api/v1/assets/%d/remediation-token", a.asset), nil},
		{"POST", "/api/v1/workspaces/1/activate", nil},
	} {
		if code := betaSess.do(m.method, m.path, m.body, nil); code < 400 || code >= 500 {
			t.Errorf("%s %s from beta: %d", m.method, m.path, code)
		}
	}

	// A still has everything, unchanged.
	var asset store.Asset
	if code := alphaSess.do("GET", fmt.Sprintf("/api/v1/assets/%d", a.asset), nil, &asset); code != 200 || asset.Environment == "hacked" {
		t.Errorf("alpha asset after beta's attempts: %d %+v", code, asset)
	}
	for path, want := range map[string]string{"/api/v1/teams": "team-alpha", "/api/v1/channels": "chan-alpha",
		"/api/v1/routes": "route-alpha", "/api/v1/integrations": "github.com/alpha", "/api/v1/enrollments": "enr-alpha",
		"/api/v1/users": "alpha-admin"} {
		if _, body := get(alphaSess, path); !strings.Contains(body, want) {
			t.Errorf("alpha lost %s: %s", want, body)
		}
	}
	if code := bearer(e, a.collector, "GET", "/api/v1/auth/me", nil, nil); code != 200 {
		t.Errorf("alpha collector token stopped working: %d", code)
	}
	var meAlpha struct{ Role auth.Role }
	alphaSess.do("GET", "/api/v1/auth/me", nil, &meAlpha)
	if meAlpha.Role != auth.RoleAdmin {
		t.Errorf("alpha admin role changed: %s", meAlpha.Role)
	}

	// B's collector token cannot reach A even when it names A's asset.
	if code := bearer(e, b.collector, "GET", fmt.Sprintf("/api/v1/assets/%d", a.asset), nil, nil); code != 403 && code != 404 {
		t.Errorf("beta collector read alpha asset: %d", code)
	}
}

// TestWorkspaceMembership covers switching, roles per workspace, removal and
// disabled workspaces.
func TestWorkspaceMembership(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.user("owner@x.io", auth.RoleAdmin)
	if _, err := e.st.UpdateUserInstanceAdmin(ctx, "owner@x.io", true); err != nil {
		t.Fatal(err)
	}
	owner := e.login("owner@x.io")

	// Instance admin creates a workspace for someone new and adds an existing user.
	var created struct {
		Workspace store.Workspace
	}
	if code := owner.do("POST", "/api/v1/admin/workspaces", map[string]any{"name": "Gamma Ltd", "admin_email": "gamma@x.io",
		"admin_password": pw}, &created); code != 201 || created.Workspace.Slug != "gamma-ltd" {
		t.Fatalf("create workspace: %d %+v", code, created)
	}
	gamma := e.login("gamma@x.io")
	if code := gamma.do("POST", "/api/v1/users", map[string]any{"email": "owner@x.io", "role": "viewer"}, nil); code != 201 {
		t.Fatalf("add existing user: %d", code)
	}
	if code := gamma.do("GET", "/api/v1/admin/workspaces", nil, nil); code != 403 {
		t.Errorf("workspace admin listed all workspaces: %d", code)
	}

	// The owner is admin in the default workspace and viewer in Gamma.
	var me struct {
		Role       auth.Role
		Workspaces []store.Membership
	}
	owner.do("GET", "/api/v1/auth/me", nil, &me)
	if me.Role != auth.RoleAdmin || len(me.Workspaces) != 2 {
		t.Fatalf("me before switching: %+v", me)
	}
	if code := owner.do("POST", fmt.Sprintf("/api/v1/workspaces/%d/activate", created.Workspace.ID), nil, nil); code != 200 {
		t.Fatalf("activate: %d", code)
	}
	owner.do("GET", "/api/v1/auth/me", nil, &me)
	if me.Role != auth.RoleViewer {
		t.Errorf("role in gamma: %s", me.Role)
	}
	if code := owner.do("POST", "/api/v1/teams", map[string]any{"name": "x"}, nil); code != 403 {
		t.Errorf("viewer created a team in gamma: %d", code)
	}

	// Gamma's admin cannot change the shared account, only its role there.
	var ownerID int64
	var users struct{ Items []store.User }
	gamma.do("GET", "/api/v1/users", nil, &users)
	for _, u := range users.Items {
		if u.Email == "owner@x.io" {
			ownerID = u.ID
		}
	}
	if code := gamma.do("PATCH", fmt.Sprintf("/api/v1/users/%d", ownerID), map[string]any{"password": "a new long password"}, nil); code != 409 {
		t.Errorf("gamma admin reset a shared account's password: %d", code)
	}
	if code := gamma.do("PATCH", fmt.Sprintf("/api/v1/users/%d", ownerID), map[string]any{"disabled": true}, nil); code != 409 {
		t.Errorf("gamma admin disabled a shared account: %d", code)
	}
	if code := gamma.do("PATCH", fmt.Sprintf("/api/v1/users/%d", ownerID), map[string]any{"role": "engineer"}, nil); code != 200 {
		t.Errorf("gamma admin changed the role: %d", code)
	}

	// The last admin cannot be removed; a member can.
	var gammaUsers struct{ Items []store.User }
	gamma.do("GET", "/api/v1/users", nil, &gammaUsers)
	for _, u := range gammaUsers.Items {
		if u.Email == "gamma@x.io" {
			if code := gamma.do("DELETE", fmt.Sprintf("/api/v1/users/%d", u.ID), nil, nil); code != 409 {
				t.Errorf("removed the last admin: %d", code)
			}
		}
	}
	if code := gamma.do("DELETE", fmt.Sprintf("/api/v1/users/%d", ownerID), nil, nil); code != 204 {
		t.Fatalf("remove member: %d", code)
	}
	owner.do("GET", "/api/v1/auth/me", nil, &me)
	if me.Role != auth.RoleAdmin || len(me.Workspaces) != 1 {
		t.Errorf("after removal the session should fall back to the default workspace: %+v", me)
	}

	// A disabled workspace locks its members out; the default one cannot be disabled.
	if code := owner.do("PATCH", fmt.Sprintf("/api/v1/admin/workspaces/%d", created.Workspace.ID), map[string]any{"disabled": true}, nil); code != 200 {
		t.Fatalf("disable: %d", code)
	}
	if code := gamma.do("GET", "/api/v1/assets", nil, nil); code != 403 {
		t.Errorf("member of a disabled workspace listed assets: %d", code)
	}
	if code := owner.do("PATCH", "/api/v1/admin/workspaces/1", map[string]any{"disabled": true}, nil); code != 409 {
		t.Errorf("disabled the default workspace: %d", code)
	}
}

// TestNoScopeSeesNothing checks the database default: code that forgets to
// set a workspace reads no tenant rows and cannot write any.
func TestNoScopeSeesNothing(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	tok, _, err := e.st.CreateToken(tenant.WithWorkspace(context.Background(), 1), "c", auth.RoleCollector, nil, 0, 0)
	if err != nil || tok.WorkspaceID != 1 {
		t.Fatal(err)
	}
	bare := context.Background()
	if ts, err := e.st.ListTokens(bare, 0); err != nil || len(ts) != 0 {
		t.Errorf("unscoped read returned %d tokens (err %v)", len(ts), err)
	}
	if _, err := e.st.CreateTeam(bare, "t", ""); err == nil {
		t.Error("unscoped write succeeded")
	}
}

// TestWorkspaceSecrets checks that workspace admins use stored secrets and
// cannot reference the server's own.
func TestWorkspaceSecrets(t *testing.T) {
	e := newEnv(t)
	box, err := secrets.NewBox([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	e.api.SecretBox = box
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")

	repo := 0
	gitWith := func(ref string) map[string]any {
		repo++
		return map[string]any{"kind": "git_repository", "config": map[string]string{"url": fmt.Sprintf("https://github.com/a/r%d", repo)}, "secret_ref": ref}
	}
	if code := admin.do("POST", "/api/v1/integrations", gitWith("env:STACKURITY_SECRET_GH"), nil); code != 403 {
		t.Errorf("workspace admin referenced a server secret: %d", code)
	}
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "slack", "name": "s", "secret_ref": "env:STACKURITY_SECRET_SLACK"}, nil); code != 403 {
		t.Errorf("workspace admin gave a channel a server secret: %d", code)
	}
	if code := admin.do("PUT", "/api/v1/secrets/GH_TOKEN", map[string]string{"value": "ghp_secret"}, nil); code != 204 {
		t.Fatalf("store secret: %d", code)
	}
	if code := admin.do("POST", "/api/v1/integrations", gitWith("secret:GH_TOKEN"), nil); code != 201 {
		t.Errorf("stored secret reference: %d", code)
	}
	resp := admin.req("GET", "/api/v1/secrets", nil, nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "GH_TOKEN") || strings.Contains(string(body), "ghp_secret") {
		t.Errorf("secret listing: %s", body)
	}
	v, err := e.st.SecretValue(tenant.WithWorkspace(context.Background(), 1), box, "GH_TOKEN")
	if err != nil || v != "ghp_secret" {
		t.Errorf("decrypt: %q %v", v, err)
	}

	// Another workspace can neither read it nor open its ciphertext.
	other, _, err := e.st.CreateWorkspace(context.Background(), "Other", "", "o@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.SecretValue(tenant.WithWorkspace(context.Background(), other.ID), box, "GH_TOKEN"); err == nil {
		t.Error("another workspace read the secret")
	}
	if _, err := box.Open(other.ID, "GH_TOKEN", mustSeal(t, box, 1, "GH_TOKEN", "x")); err == nil {
		t.Error("a ciphertext opened under another workspace")
	}

	// An instance admin may use server secrets, and only they may then change that integration.
	e.instanceAdmin("admin@x.io")
	var in store.Integration
	if code := admin.do("POST", "/api/v1/integrations", gitWith("env:STACKURITY_SECRET_GH"), &in); code != 201 {
		t.Fatalf("instance admin with env secret: %d", code)
	}
	e.user("admin2@x.io", auth.RoleAdmin)
	if code := e.login("admin2@x.io").do("PATCH", fmt.Sprintf("/api/v1/integrations/%d", in.ID),
		map[string]any{"config": map[string]string{"url": "https://evil.example/a/b"}}, nil); code != 403 {
		t.Errorf("workspace admin redirected an integration that reads a server secret: %d", code)
	}
}

func mustSeal(t *testing.T, b *secrets.Box, ws int64, name, v string) []byte {
	out, err := b.Seal(ws, name, v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
