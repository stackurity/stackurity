package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

func one(n int64) *int64 { return &n }

// raw sends a JSON body like do and returns the status and body.
func (s *session) raw(method, path string, body []byte) (int, string) {
	resp := s.req(method, path, bytes.NewReader(body), map[string]string{"X-Stackurity-CSRF": "1", "Content-Type": "application/json"})
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// setPlanLimits sets the default workspace's plan limits as a hosted
// edition's billing would.
func setPlanLimits(t *testing.T, e *env, l store.PlanLimits) {
	t.Helper()
	if err := e.st.SetPlanLimits(context.Background(), tenant.DefaultWorkspace, l); err != nil {
		t.Fatal(err)
	}
}

// planRefused checks a 402 plan_limit naming the plan to upgrade to.
func planRefused(t *testing.T, what string, code int, body string, want string) {
	t.Helper()
	if code != 402 || !strings.Contains(body, `"plan_limit"`) || !strings.Contains(body, want) || !strings.Contains(body, "Upgrade to Starter") {
		t.Errorf("%s over the plan: %d %s", what, code, body)
	}
}

// TestPlanRuleLimits: with plan limits set, every place a rule of a
// limited kind is added refuses the one over the limit with 402
// plan_limit, naming the plan to upgrade to; the ones there keep working
// and can be changed and deleted; turning an inherited rule off for a
// project does not count; without limits (self-hosted) nothing changes.
func TestPlanRuleLimits(t *testing.T) {
	o := newOrg(t)
	e := o.e
	alpha := o.s("alpha-project")
	post := func(path string, body any) (int, string) {
		raw, _ := json.Marshal(body)
		return o.admin.raw("POST", path, raw)
	}

	// Self-hosted: no limits, several of everything.
	var ch store.Channel
	if code := o.admin.do("POST", "/api/v1/channels", map[string]any{"kind": "webhook", "name": "hook-1",
		"config": map[string]string{"url": "https://hooks.example/1"}}, &ch); code != 201 {
		t.Fatalf("channel: %d", code)
	}
	var orgRule store.Route
	if code := o.admin.do("POST", "/api/v1/routes", map[string]any{"name": "r1", "channel_id": ch.ID, "enabled": true}, &orgRule); code != 201 {
		t.Fatalf("rule: %d", code)
	}
	if code, body := post("/api/v1/routes", map[string]any{"name": "r2", "channel_id": ch.ID, "enabled": true}); code != 201 {
		t.Fatalf("second rule without limits: %d %s", code, body)
	}
	var usage store.AssetUsage
	if o.admin.do("GET", "/api/v1/usage", nil, &usage); usage.Plan != nil {
		t.Fatalf("usage shows a plan without limits: %+v", usage.Plan)
	}

	// The fixtures' own rules count too: each limit leaves room for one
	// more (channels none).
	setPlanLimits(t, e, store.PlanLimits{NextPlan: "Starter", RuleLimits: map[string]int64{store.LimitTeams: 100}})
	o.admin.do("GET", "/api/v1/usage", nil, &usage)
	room := func(k string) int64 { return usage.Plan.Rules[k].Used + 1 }
	limits := map[string]int64{store.LimitAlertRules: room(store.LimitAlertRules), store.LimitChannels: room(store.LimitChannels) - 1,
		store.LimitTeams: room(store.LimitTeams), store.LimitAPITokens: room(store.LimitAPITokens),
		store.LimitVEXSources: room(store.LimitVEXSources), store.LimitOwnerRules: room(store.LimitOwnerRules)}
	rules := limits[store.LimitAlertRules]
	word := func(k, name string) string { return fmt.Sprintf("%d %s", limits[k], name) }
	setPlanLimits(t, e, store.PlanLimits{Plan: "Free", NextPlan: "Starter", RuleLimits: limits})

	// A project's own rule takes the last place.
	if code, body := post("/api/v1/projects/"+alpha+"/notifications/routes", map[string]any{"name": "alpha", "channel_id": ch.ID}); code != 201 {
		t.Fatalf("last rule (a project's): %d %s", code, body)
	}
	ruleWord := fmt.Sprintf("%d alert rules", rules)
	code, body := post("/api/v1/routes", map[string]any{"name": "r4", "channel_id": ch.ID, "enabled": true})
	planRefused(t, "organisation rule", code, body, ruleWord)
	code, body = post("/api/v1/projects/"+alpha+"/notifications/routes", map[string]any{"name": "alpha-2", "channel_id": ch.ID})
	planRefused(t, "project rule", code, body, ruleWord)
	// Editing an inherited rule for a project makes a copy: refused too.
	raw, _ := json.Marshal(map[string]string{"state": "edit"})
	code, body = o.admin.raw("PUT", fmt.Sprintf("/api/v1/projects/%s/notifications/inherited/%d", alpha, orgRule.ID), raw)
	planRefused(t, "edited inherited rule", code, body, ruleWord)
	// Turning it off is not a rule: allowed at the limit.
	if code := o.admin.do("PUT", fmt.Sprintf("/api/v1/projects/%s/notifications/inherited/%d", alpha, orgRule.ID), map[string]string{"state": "off"}, nil); code != 200 {
		t.Errorf("turn off at the limit: %d", code)
	}
	// Existing rules are changed and deleted as before.
	if code := o.admin.do("PUT", fmt.Sprintf("/api/v1/routes/%d", orgRule.ID), map[string]any{"name": "renamed", "channel_id": ch.ID, "enabled": true}, nil); code != 200 {
		t.Errorf("edit at the limit: %d", code)
	}
	if code := o.admin.do("DELETE", fmt.Sprintf("/api/v1/routes/%d", orgRule.ID), nil, nil); code != 204 {
		t.Errorf("delete at the limit: %d", code)
	}
	if code, body := post("/api/v1/routes", map[string]any{"name": "r4", "channel_id": ch.ID, "enabled": true}); code != 201 {
		t.Errorf("after a delete: %d %s", code, body)
	}

	// Channels: none left, on the organisation's and a project's.
	code, body = post("/api/v1/channels", map[string]any{"kind": "webhook", "name": "hook-2", "config": map[string]string{"url": "https://hooks.example/2"}})
	planRefused(t, "organisation channel", code, body, word(store.LimitChannels, "notification channels"))
	code, body = post("/api/v1/projects/"+alpha+"/notifications/channels", map[string]any{"kind": "stackurity_email", "name": "alpha mail",
		"config": map[string]any{"to": []string{"a@x.io"}}})
	if code != 402 && code != 400 {
		t.Errorf("project channel over the plan: %d %s", code, body)
	}

	// Teams, API tokens, VEX sources, owner rules: one more each.
	var team store.Team
	if code := o.admin.do("POST", "/api/v1/teams", map[string]any{"name": "ops"}, &team); code != 201 {
		t.Fatalf("first team: %d", code)
	}
	code, body = post("/api/v1/teams", map[string]any{"name": "dev"})
	planRefused(t, "team", code, body, word(store.LimitTeams, "teams"))
	if code, body := post("/api/v1/tokens", map[string]any{"name": "ci", "role": "viewer"}); code != 201 {
		t.Fatalf("first token: %d %s", code, body)
	}
	code, body = post("/api/v1/tokens", map[string]any{"name": "ci-2", "role": "viewer"})
	planRefused(t, "API token", code, body, word(store.LimitAPITokens, "API tokens"))
	if code, body := post("/api/v1/vex/sources", map[string]any{"name": "vendor"}); code != 201 {
		t.Fatalf("first VEX source: %d %s", code, body)
	}
	code, body = post("/api/v1/vex/sources", map[string]any{"name": "vendor-2"})
	planRefused(t, "VEX source", code, body, word(store.LimitVEXSources, "VEX sources"))
	if code, body := post("/api/v1/owner-rules", map[string]any{"asset_id": o.id("alpha-asset"), "layer": "os", "team_id": team.ID}); code != 201 {
		t.Fatalf("first owner rule: %d %s", code, body)
	}
	code, body = post("/api/v1/owner-rules", map[string]any{"asset_id": o.id("beta-asset"), "layer": "os", "team_id": team.ID})
	planRefused(t, "owner rule", code, body, word(store.LimitOwnerRules, "owner rules"))

	// Agents' tokens are not API tokens people make: never limited.
	if _, _, err := e.st.CreateAssetToken(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), o.id("alpha-asset"), "agent-2", o.adminID); err != nil {
		t.Errorf("agent token at the API-token limit: %v", err)
	}

	// Usage shows each limit and how much of it is used.
	if code := o.admin.do("GET", "/api/v1/usage", nil, &usage); code != 200 || usage.Plan == nil {
		t.Fatalf("usage: %d %+v", code, usage.Plan)
	}
	if r := usage.Plan.Rules[store.LimitAlertRules]; r.Used != rules || r.Limit == nil || *r.Limit != rules || usage.Plan.NextPlan != "Starter" {
		t.Errorf("usage of alert rules: %+v", usage.Plan)
	}
	if r := usage.Plan.Rules[store.LimitCITrusts]; r.Limit != nil {
		t.Errorf("an unlimited kind has a limit: %+v", r)
	}

	// Removing the limits lifts them.
	setPlanLimits(t, e, store.PlanLimits{})
	if code, body := post("/api/v1/teams", map[string]any{"name": "dev"}); code != 201 {
		t.Errorf("team without limits: %d %s", code, body)
	}
}

// TestPlanChannelKinds: a plan that includes only some kinds of channel
// refuses the others, also on a project; the included ones are made.
func TestPlanChannelKinds(t *testing.T) {
	o := newOrg(t)
	setPlanLimits(t, o.e, store.PlanLimits{NextPlan: "Starter", AllowedChannelKinds: []string{"stackurity_email", "slack_app"}})
	raw, _ := json.Marshal(map[string]any{"kind": "webhook", "name": "hook", "config": map[string]string{"url": "https://hooks.example/1"}})
	code, body := o.admin.raw("POST", "/api/v1/channels", raw)
	if code != 402 || !strings.Contains(body, "does not include Webhook") && !strings.Contains(body, "does not include webhook") || !strings.Contains(body, "Upgrade to Starter") {
		t.Errorf("webhook on a plan without it: %d %s", code, body)
	}
	code, body = o.admin.raw("POST", "/api/v1/projects/"+o.s("alpha-project")+"/notifications/channels", raw)
	if code != 402 && code != 403 {
		t.Errorf("project webhook on a plan without it: %d %s", code, body)
	}
	// Add to Slack and Add to Teams check before sending anyone to Slack
	// or Teams.
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if err := o.e.st.PlanRoom(ctx, store.LimitChannels, "slack_app"); err != nil {
		t.Errorf("Slack app on a plan with it: %v", err)
	}
	if pl, ok := store.AsPlanLimit(o.e.st.PlanRoom(ctx, store.LimitChannels, "teams_app")); !ok || pl.Kind != store.LimitChannelKind {
		t.Errorf("Teams app on a plan without it: %+v", pl)
	}
	setPlanLimits(t, o.e, store.PlanLimits{NextPlan: "Starter", RuleLimits: map[string]int64{store.LimitChannels: 0}})
	if !errors.Is(o.e.st.PlanRoom(ctx, store.LimitChannels, "slack_app"), store.ErrPlanLimit) {
		t.Errorf("Slack app with no channels left")
	}
}

// TestPlanMemberLimit: members and pending invitations count together;
// at the limit a new invitation, and a new account through access, are
// refused; accepting an invitation already sent is not.
func TestPlanMemberLimit(t *testing.T) {
	o := newOrg(t)
	var me struct{ Members []any }
	_ = me
	var usage store.AssetUsage
	setPlanLimits(t, o.e, store.PlanLimits{NextPlan: "Starter", MaxMembers: one(1)})
	o.admin.do("GET", "/api/v1/usage", nil, &usage)
	if usage.Plan == nil || usage.Plan.Members.Used < 1 {
		t.Fatalf("members usage: %+v", usage.Plan)
	}
	used := usage.Plan.Members.Used
	setPlanLimits(t, o.e, store.PlanLimits{NextPlan: "Starter", MaxMembers: one(used + 1)})
	raw, _ := json.Marshal(map[string]any{"email": "first@x.io", "role": "viewer"})
	if code, body := o.admin.raw("POST", "/api/v1/invitations", raw); code != 201 {
		t.Fatalf("invitation with room: %d %s", code, body)
	}
	raw, _ = json.Marshal(map[string]any{"email": "second@x.io", "role": "viewer"})
	code, body := o.admin.raw("POST", "/api/v1/invitations", raw)
	planRefused(t, "second invitation", code, body, "members")
	raw, _ = json.Marshal(map[string]any{"email": "third@x.io", "password": pw, "project_id": o.id("alpha-project"), "role": "viewer"})
	code, body = o.admin.raw("POST", "/api/v1/access-grants", raw)
	planRefused(t, "new account through access", code, body, "members")
	// Inviting the same person again does not take another place.
	if code := o.admin.do("POST", "/api/v1/invitations", map[string]any{"email": "first@x.io", "role": "viewer"}, nil); code == 402 {
		t.Errorf("inviting the invited again: %d", code)
	}
}

// TestPlanProjectsOverLimitReadOnly: with over_limit_read_only, the
// projects beyond the project limit (the newest) are read-only: an asset
// only in them collects nothing new; an asset also in an active project,
// and an unfiled asset, collect as before; projects say so.
func TestPlanProjectsOverLimitReadOnly(t *testing.T) {
	o := newOrg(t)
	ctx := context.Background()
	if err := o.e.st.SetProjectLimit(ctx, tenant.DefaultWorkspace, one(1)); err != nil {
		t.Fatal(err)
	}
	ingest := func(name, machine string) (int, string) {
		b := model.NewBatch(model.Collector{ID: "agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: name,
			Identifiers: []model.Identifier{{Scheme: "machine-id", Value: machine}}})
		b.Observations = []model.Observation{{Purl: "pkg:deb/debian/bash@5.3", Confidence: model.ConfidenceConfirmed}}
		b.Complete = true
		raw, _ := json.Marshal(b)
		return bearerBody(o.e, o.collector, "POST", "/api/v1/ingest", raw)
	}
	// A lower limit alone (as today) keeps every project collecting.
	if code, body := ingest("host-beta", "beta-m1"); code != 201 {
		t.Fatalf("beta without over_limit_read_only: %d %s", code, body)
	}
	setPlanLimits(t, o.e, store.PlanLimits{NextPlan: "Starter", OverLimitReadOnly: true})
	// Alpha is the older project: it stays active; Beta is read-only.
	var projects struct{ Items []store.Project }
	if code := o.admin.do("GET", "/api/v1/projects", nil, &projects); code != 200 {
		t.Fatalf("projects: %d", code)
	}
	ro := map[string]bool{}
	for _, p := range projects.Items {
		ro[p.Name] = p.ReadOnly
	}
	if ro["Project Alpha"] || !ro["Project Beta"] {
		t.Fatalf("read-only projects: %v", ro)
	}
	code, body := ingest("host-beta", "beta-m1")
	if code != 402 || !strings.Contains(body, `"read_only"`) || !strings.Contains(body, "Project Beta") || !strings.Contains(body, "upgrade to Starter") {
		t.Errorf("asset only in a read-only project: %d %s", code, body)
	}
	for _, a := range [][2]string{{"host-alpha", "alpha-m1"}, {"shared-db", "shared-m1"}, {"unfiled-beta", "loose-m1"}} {
		if code, body := ingest(a[0], a[1]); code != 201 {
			t.Errorf("%s (active project, or unfiled): %d %s", a[0], code, body)
		}
	}
	// Viewing the read-only project's asset still works.
	if code := o.admin.do("GET", "/api/v1/assets/"+o.s("beta-asset"), nil, nil); code != 200 {
		t.Errorf("viewing a read-only project's asset: %d", code)
	}
	// Archiving Alpha makes Beta the active one.
	yes := true
	if err := o.e.st.UpdateProject(tenant.WithWorkspace(ctx, tenant.DefaultWorkspace), o.id("alpha-project"), store.ProjectUpdate{Archived: &yes}); err != nil {
		t.Fatal(err)
	}
	if code, body := ingest("host-beta", "beta-m1"); code != 201 {
		t.Errorf("beta once alpha is archived: %d %s", code, body)
	}
}

// TestPlanLimitsAdmin: only an instance administrator sets plan limits,
// they are validated, and {} removes them.
func TestPlanLimitsAdmin(t *testing.T) {
	e := newEnv(t)
	e.user("owner@x.io", auth.RoleAdmin)
	e.instanceAdmin("owner@x.io")
	e.user("admin@x.io", auth.RoleAdmin)
	owner, admin := e.login("owner@x.io"), e.login("admin@x.io")
	body := map[string]any{"plan_limits": map[string]any{"plan": "Free", "next_plan": "Starter", "rule_limits": map[string]int{"alert_rules": 3}, "max_members": 2}}
	if code := admin.do("PATCH", "/api/v1/admin/workspaces/1", body, nil); code != 403 {
		t.Errorf("workspace admin sets plan limits: %d", code)
	}
	var ws store.Workspace
	if code := owner.do("PATCH", "/api/v1/admin/workspaces/1", body, &ws); code != 200 || ws.PlanLimits.RuleLimits["alert_rules"] != 3 ||
		ws.PlanLimits.MaxMembers == nil || *ws.PlanLimits.MaxMembers != 2 {
		t.Fatalf("set: %d %+v", code, ws.PlanLimits)
	}
	for _, bad := range []map[string]any{
		{"rule_limits": map[string]int{"routes": 3}},
		{"rule_limits": map[string]int{"teams": -1}},
		{"max_members": 0},
		{"allowed_channel_kinds": []string{"carrier-pigeon"}},
	} {
		if code := owner.do("PATCH", "/api/v1/admin/workspaces/1", map[string]any{"plan_limits": bad}, nil); code != 400 {
			t.Errorf("%v: %d", bad, code)
		}
	}
	var cleared store.Workspace
	if code := owner.do("PATCH", "/api/v1/admin/workspaces/1", map[string]any{"plan_limits": map[string]any{}}, &cleared); code != 200 || !cleared.PlanLimits.Empty() {
		t.Errorf("remove: %d %+v", code, cleared.PlanLimits)
	}
}

var _ = http.MethodGet
