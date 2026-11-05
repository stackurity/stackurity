package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Notifications of projects and assets (notify_scopes.go): what a project
// inherits from the organisation, turning a rule off or editing it there,
// the project's own rules and channels, and who may do which.

type scopeView struct {
	CanManage bool `json:"can_manage"`
	Inherited []struct {
		ID     int64  `json:"id"`
		From   string `json:"from"`
		State  string `json:"state"`
		CopyID *int64 `json:"copy_id"`
	} `json:"inherited"`
	Routes          []store.Route   `json:"routes"`
	Channels        []store.Channel `json:"channels"`
	UsableChannels  []struct{ ID int64 }
	ProjectChatApps bool     `json:"project_chat_apps"`
	OrgAdmins       []string `json:"org_admins"`
}

func (v scopeView) state(route int64) string {
	for _, r := range v.Inherited {
		if r.ID == route {
			return r.State
		}
	}
	return "absent"
}

func TestScopedNotifications(t *testing.T) {
	o := newOrg(t)
	e := o.e
	alpha, beta := o.s("alpha-project"), o.s("beta-project")
	base := "/api/v1/projects/" + alpha + "/notifications"

	// The organisation's channel and rule.
	var orgCh store.Channel
	if code := o.admin.do("POST", "/api/v1/channels", map[string]any{"kind": "webhook", "name": "org-hook",
		"config": map[string]string{"url": "https://hooks.example/org"}}, &orgCh); code != 201 {
		t.Fatalf("org channel: %d", code)
	}
	var orgRule store.Route
	if code := o.admin.do("POST", "/api/v1/routes", map[string]any{"name": "everything", "channel_id": orgCh.ID, "enabled": true}, &orgRule); code != 201 {
		t.Fatalf("org rule: %d", code)
	}
	if orgRule.OwnerProjectID != nil || orgRule.OwnerAssetID != nil {
		t.Fatalf("org rule has an owner: %+v", orgRule)
	}

	// Who may read and change Alpha's notifications.
	o.grant(t, "alpha-admin@x.io", o.id("alpha-project"), 0, auth.RoleAdmin)
	o.grant(t, "alpha-security@x.io", o.id("alpha-project"), 0, auth.RoleSecurity)
	o.grant(t, "alpha-engineer@x.io", o.id("alpha-project"), 0, auth.RoleEngineer)
	pa, ps, pe := e.signIn("alpha-admin@x.io"), e.signIn("alpha-security@x.io"), e.signIn("alpha-engineer@x.io")
	var view scopeView
	if code := pa.do("GET", base, nil, &view); code != 200 || !view.CanManage {
		t.Fatalf("alpha admin reads: %d %+v", code, view)
	}
	if view.state(orgRule.ID) != "on" || view.ProjectChatApps || len(view.OrgAdmins) == 0 {
		t.Fatalf("alpha inherits: %+v", view)
	}
	if code := ps.do("GET", base, nil, &view); code != 200 || view.CanManage {
		t.Fatalf("alpha security reads: %d, can_manage %v", code, view.CanManage)
	}
	if code := pe.do("GET", base, nil, nil); code != 403 {
		t.Errorf("alpha engineer reads: %d", code)
	}
	for _, s := range []*session{ps, pe} {
		if code := s.do("PUT", base+fmt.Sprintf("/inherited/%d", orgRule.ID), map[string]string{"state": "off"}, nil); code != 403 {
			t.Errorf("turn off below admin: %d", code)
		}
		if code := s.do("POST", base+"/routes", map[string]any{"name": "mine", "channel_id": orgCh.ID}, nil); code != 403 {
			t.Errorf("add a rule below admin: %d", code)
		}
	}
	// Another project, and the organisation's own routes, are out of reach.
	if code := pa.do("GET", "/api/v1/projects/"+beta+"/notifications", nil, nil); code != 404 {
		t.Errorf("alpha admin reads beta: %d", code)
	}
	if code := pa.do("POST", "/api/v1/projects/"+beta+"/notifications/routes", map[string]any{"name": "x", "channel_id": orgCh.ID}, nil); code != 404 {
		t.Errorf("alpha admin adds a rule to beta: %d", code)
	}
	if code := pa.do("PUT", base+fmt.Sprintf("/routes/%d", orgRule.ID), map[string]any{"name": "hacked", "channel_id": orgCh.ID}, nil); code != 404 {
		t.Errorf("alpha admin edits the org rule as alpha's: %d", code)
	}
	if code := pa.do("DELETE", base+fmt.Sprintf("/routes/%d", orgRule.ID), nil, nil); code != 404 {
		t.Errorf("alpha admin deletes the org rule: %d", code)
	}
	if code := pa.do("PUT", fmt.Sprintf("/api/v1/routes/%d", orgRule.ID), map[string]any{"name": "hacked", "channel_id": orgCh.ID}, nil); code != 403 {
		t.Errorf("alpha admin on the organisation's route: %d", code)
	}
	if code := pa.do("PUT", "/api/v1/settings/notifications", map[string]bool{"project_chat_apps": true}, nil); code != 403 {
		t.Errorf("alpha admin changes the organisation's setting: %d", code)
	}

	// Turn off for alpha, then on again.
	if code := pa.do("PUT", base+fmt.Sprintf("/inherited/%d", orgRule.ID), map[string]string{"state": "off"}, &view); code != 200 || view.state(orgRule.ID) != "off" {
		t.Fatalf("turn off: %d %+v", code, view)
	}
	routes, err := e.st.ListRoutes(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		if r.ID == orgRule.ID && (r.Covers(o.id("alpha-asset")) || !r.Covers(o.id("shared-asset")) || !r.Covers(o.id("beta-asset"))) {
			t.Errorf("turned off for alpha: alpha %v, shared (also in beta) %v, beta %v",
				r.Covers(o.id("alpha-asset")), r.Covers(o.id("shared-asset")), r.Covers(o.id("beta-asset")))
		}
	}
	if code := pa.do("PUT", base+fmt.Sprintf("/inherited/%d", orgRule.ID), map[string]string{"state": "on"}, &view); code != 200 || view.state(orgRule.ID) != "on" {
		t.Fatalf("turn on: %d %+v", code, view)
	}

	// Edit for alpha: alpha gets a copy, and changes it.
	if code := pa.do("PUT", base+fmt.Sprintf("/inherited/%d", orgRule.ID), map[string]string{"state": "edit"}, &view); code != 200 || view.state(orgRule.ID) != "edited" || len(view.Routes) != 1 {
		t.Fatalf("edit: %d %+v", code, view)
	}
	cp := view.Routes[0]
	if cp.InheritsRouteID == nil || *cp.InheritsRouteID != orgRule.ID || cp.OwnerProjectID == nil || *cp.OwnerProjectID != o.id("alpha-project") {
		t.Fatalf("copy: %+v", cp)
	}
	var changed store.Route
	if code := pa.do("PUT", base+fmt.Sprintf("/routes/%d", cp.ID), map[string]any{"name": "everything", "channel_id": orgCh.ID, "enabled": true,
		"min_priority": "P2", "project_ids": []int64{o.id("beta-project")}, "owner_project_id": o.id("beta-project")}, &changed); code != 200 {
		t.Fatalf("change the copy: %d", code)
	}
	if changed.MinPriority != "P2" || len(changed.ProjectIDs) != 1 || changed.ProjectIDs[0] != o.id("alpha-project") || *changed.OwnerProjectID != o.id("alpha-project") {
		t.Fatalf("the copy left alpha or kept its priority: %+v", changed)
	}
	// Deleting the copy puts the organisation's rule back.
	if code := pa.do("DELETE", base+fmt.Sprintf("/routes/%d", cp.ID), nil, nil); code != 204 {
		t.Fatalf("delete copy: %d", code)
	}
	if pa.do("GET", base, nil, &view); view.state(orgRule.ID) != "on" || len(view.Routes) != 0 {
		t.Fatalf("after deleting the copy: %+v", view)
	}

	// Channels: a project admin adds email sent by Stackurity only; an
	// organisation admin adds any kind for the project.
	if code := pa.do("POST", base+"/channels", map[string]any{"kind": "webhook", "name": "mine",
		"config": map[string]string{"url": "https://hooks.example/alpha"}}, nil); code != 403 {
		t.Errorf("alpha admin adds a webhook: %d", code)
	}
	var alphaCh store.Channel
	if code := o.admin.do("POST", base+"/channels", map[string]any{"kind": "webhook", "name": "alpha-hook",
		"config": map[string]string{"url": "https://hooks.example/alpha"}}, &alphaCh); code != 201 || alphaCh.OwnerProjectID == nil {
		t.Fatalf("org admin adds alpha's webhook: %d %+v", code, alphaCh)
	}
	// Alpha's admin renames it, but cannot point it elsewhere.
	if code := pa.do("PATCH", base+fmt.Sprintf("/channels/%d", alphaCh.ID), map[string]any{"name": "alpha alerts"}, nil); code != 200 {
		t.Errorf("rename: %d", code)
	}
	if code := pa.do("PATCH", base+fmt.Sprintf("/channels/%d", alphaCh.ID), map[string]any{"config": map[string]string{"url": "https://evil.example"}}, nil); code != 403 {
		t.Errorf("alpha admin changes the URL: %d", code)
	}
	if code := pa.do("PATCH", base+fmt.Sprintf("/channels/%d", orgCh.ID), map[string]any{"name": "taken"}, nil); code != 404 {
		t.Errorf("alpha admin renames the organisation's channel: %d", code)
	}
	// Alpha's rule to alpha's channel; the organisation's rules cannot use it.
	var mine store.Route
	if code := pa.do("POST", base+"/routes", map[string]any{"name": "alpha urgent", "channel_id": alphaCh.ID, "enabled": true}, &mine); code != 201 ||
		mine.OwnerProjectID == nil || len(mine.ProjectIDs) != 1 || mine.ProjectIDs[0] != o.id("alpha-project") {
		t.Fatalf("alpha rule: %+v", mine)
	}
	if code := o.admin.do("POST", "/api/v1/routes", map[string]any{"name": "wide", "channel_id": alphaCh.ID, "enabled": true}, nil); code != 400 {
		t.Errorf("org rule to alpha's channel: %d", code)
	}
	var betaCh store.Channel
	if code := o.admin.do("POST", "/api/v1/projects/"+beta+"/notifications/channels", map[string]any{"kind": "webhook", "name": "beta-hook",
		"config": map[string]string{"url": "https://hooks.example/beta"}}, &betaCh); code != 201 {
		t.Fatalf("beta channel: %d", code)
	}
	if code := pa.do("POST", base+"/routes", map[string]any{"name": "leak", "channel_id": betaCh.ID, "enabled": true}, nil); code != 400 {
		t.Errorf("alpha rule to beta's channel: %d", code)
	}

	// An asset inherits the organisation's and its project's rules.
	var av scopeView
	if code := pa.do("GET", "/api/v1/assets/"+o.s("alpha-asset")+"/notifications", nil, &av); code != 200 ||
		av.state(orgRule.ID) != "on" || av.state(mine.ID) != "on" {
		t.Fatalf("alpha asset inherits: %d %+v", code, av)
	}
	if code := pa.do("PUT", "/api/v1/assets/"+o.s("alpha-asset")+fmt.Sprintf("/notifications/inherited/%d", mine.ID), map[string]string{"state": "off"}, &av); code != 200 ||
		av.state(mine.ID) != "off" {
		t.Fatalf("turn alpha's rule off for the asset: %d %+v", code, av)
	}
	if code := pa.do("GET", "/api/v1/assets/"+o.s("beta-asset")+"/notifications", nil, nil); code != 404 {
		t.Errorf("alpha admin reads beta's asset: %d", code)
	}
	// A rule of beta is not inherited by alpha.
	var betaRule store.Route
	if code := o.admin.do("POST", "/api/v1/projects/"+beta+"/notifications/routes", map[string]any{"name": "beta only", "channel_id": betaCh.ID, "enabled": true}, &betaRule); code != 201 {
		t.Fatalf("beta rule: %d", code)
	}
	if code := pa.do("PUT", base+fmt.Sprintf("/inherited/%d", betaRule.ID), map[string]string{"state": "off"}, nil); code != 404 {
		t.Errorf("alpha turns off beta's rule: %d", code)
	}
}

// Project admins connect their own Slack only when the organisation allows
// it; organisation admins always may. The channel belongs to the project.
func TestProjectSlackInstall(t *testing.T) {
	f := slackAppSetup(t)
	e := f.e
	admin := e.login("admin@x.io")
	var pr store.Project
	if code := admin.do("POST", "/api/v1/projects", map[string]any{"name": "Shop"}, &pr); code != 201 {
		t.Fatalf("project: %d", code)
	}
	for _, g := range []struct {
		email string
		role  auth.Role
	}{{"shop-admin@x.io", auth.RoleAdmin}, {"shop-security@x.io", auth.RoleSecurity}} {
		if code := admin.do("POST", "/api/v1/access-grants", map[string]any{"email": g.email, "password": pw, "role": g.role, "project_id": pr.ID}, nil); code != 201 && code != 200 {
			t.Fatalf("grant %s: %d", g.email, code)
		}
	}
	shopAdmin, shopSec := e.signIn("shop-admin@x.io"), e.signIn("shop-security@x.io")
	install := fmt.Sprintf("/api/v1/projects/%d/notifications/slack/install", pr.ID)

	var refused struct{ Error struct{ Message string } }
	if code := shopAdmin.do("POST", install, map[string]string{"return_to": "/projects"}, &refused); code != 403 ||
		!strings.Contains(refused.Error.Message, "organisation admin") || !strings.Contains(refused.Error.Message, "admin@x.io") {
		t.Fatalf("shop admin while not allowed: %d %q", code, refused.Error.Message)
	}
	if code := shopAdmin.do("POST", fmt.Sprintf("/api/v1/projects/%d/notifications/teams/install", pr.ID), map[string]string{}, nil); code != 403 {
		t.Errorf("shop admin Teams while not allowed: %d", code)
	}
	if code := shopSec.do("POST", install, map[string]string{}, nil); code != 403 {
		t.Errorf("shop security: %d", code)
	}
	// The organisation admin turns it on.
	if code := admin.do("PUT", "/api/v1/settings/notifications", map[string]bool{"project_chat_apps": true}, nil); code != 200 {
		t.Fatalf("turn on: %d", code)
	}
	var started struct{ URL string }
	if code := shopAdmin.do("POST", install, map[string]string{"return_to": "/projects"}, &started); code != 200 {
		t.Fatalf("shop admin while allowed: %d", code)
	}
	u, _ := url.Parse(started.URL)
	state := u.Query().Get("state")
	var got installAnswer
	if code := shopAdmin.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "good-code", "state": state}, &got); code != 201 {
		t.Fatalf("finish as shop admin: %d", code)
	}
	if got.Channel.OwnerProjectID == nil || *got.Channel.OwnerProjectID != pr.ID {
		t.Fatalf("the channel is not shop's: %+v", got.Channel)
	}
	var cfg notify.ChannelConfig
	_ = json.Unmarshal(got.Channel.Config, &cfg)
	if !cfg.SlackApp || cfg.SlackChannel != "#security" {
		t.Fatalf("channel config: %+v", cfg)
	}
	// Turned off again: a state started before is refused when it finishes.
	if code := shopAdmin.do("POST", install, map[string]string{}, &started); code != 200 {
		t.Fatalf("second start: %d", code)
	}
	u, _ = url.Parse(started.URL)
	if code := admin.do("PUT", "/api/v1/settings/notifications", map[string]bool{"project_chat_apps": false}, nil); code != 200 {
		t.Fatalf("turn off: %d", code)
	}
	if code := shopAdmin.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "ops-code", "state": u.Query().Get("state")}, nil); code != 403 {
		t.Errorf("finish after the organisation turned it off: %d", code)
	}
	// An organisation-wide install by a project admin is refused.
	if code := shopAdmin.do("POST", "/api/v1/integrations/slack/install", map[string]string{}, nil); code != 403 {
		t.Errorf("shop admin starts an organisation install: %d", code)
	}
}
