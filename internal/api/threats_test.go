package api_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// The threat catalogue is for every member; the organisation's notices are
// for organisation-wide security and admin roles, each with their own
// banner state.
func TestThreatNoticesAPI(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("sec@x.io", auth.RoleSecurity)
	e.user("eng@x.io", auth.RoleEngineer)
	admin, sec, eng := e.login("admin@x.io"), e.login("sec@x.io"), e.login("eng@x.io")

	var cat struct {
		Serial  int64
		Threats []struct {
			ID       string `json:"id"`
			HasCheck bool   `json:"has_check"`
			Needs    []struct{ Connection, Help string }
		}
	}
	if code := eng.do("GET", "/api/v1/threats", nil, &cat); code != 200 || cat.Serial < 1 || len(cat.Threats) == 0 || cat.Threats[0].ID == "" {
		t.Fatalf("catalogue: %d %+v", code, cat)
	}

	if err := e.st.RecordThreatsSeen(tenant.System(ctx), []store.ThreatSeen{{ID: "artex", Name: "ARTEX", Revision: 1, Source: "embedded"}}); err != nil {
		t.Fatal(err)
	}
	n, err := e.st.SaveThreatNotice(ctx, store.ThreatNotice{ThreatID: "artex", Verdict: "needs_connection", Missing: []string{"host_agent", "repository"},
		Connected: map[string]int{"docker": 2}}, store.NoticeTell)
	if err != nil {
		t.Fatal(err)
	}

	type notice struct {
		ID      int64
		Verdict string
		Name    string
		Title   string
		Lines   []string
		Action  *struct{ Label, Link string }
		Missing []struct {
			Connection, Help string
		} `json:"missing_connections"`
		Dismissed bool
	}
	var list struct{ Items []notice }
	if code := eng.do("GET", "/api/v1/threat-notices", nil, &list); code != 403 {
		t.Errorf("engineer: %d", code)
	}
	if code := sec.do("GET", "/api/v1/threat-notices", nil, &list); code != 200 || len(list.Items) != 1 {
		t.Fatalf("security: %d %+v", code, list)
	}
	got := list.Items[0]
	if got.Name != "ARTEX" || got.Action == nil || got.Action.Label != "Connect" || got.Action.Link != "/help/add-server" ||
		len(got.Missing) != 2 || got.Title == "" || len(got.Lines) == 0 || got.Dismissed {
		t.Errorf("notice: %+v", got)
	}

	// Dismissing is per person.
	if code := sec.do("POST", fmt.Sprintf("/api/v1/threat-notices/%d/dismiss", n.ID), nil, nil); code != 204 {
		t.Fatalf("dismiss: %d", code)
	}
	if code := eng.do("POST", fmt.Sprintf("/api/v1/threat-notices/%d/dismiss", n.ID), nil, nil); code != 403 {
		t.Errorf("engineer dismiss: %d", code)
	}
	if code := sec.do("POST", "/api/v1/threat-notices/999999/dismiss", nil, nil); code != 404 {
		t.Errorf("unknown notice: %d", code)
	}
	sec.do("GET", "/api/v1/threat-notices", nil, &list)
	if !list.Items[0].Dismissed {
		t.Error("dismissed for security")
	}
	admin.do("GET", "/api/v1/threat-notices", nil, &list)
	if list.Items[0].Dismissed {
		t.Error("dismissed for the admin too")
	}
	// Found: the banner shows again, with its findings.
	if _, err := e.st.SaveThreatNotice(ctx, store.ThreatNotice{ThreatID: "artex", Verdict: "found", Findings: 1, Assets: 1}, store.NoticeTell); err != nil {
		t.Fatal(err)
	}
	sec.do("GET", "/api/v1/threat-notices", nil, &list)
	if list.Items[0].Dismissed || list.Items[0].Action == nil || list.Items[0].Action.Label != "See findings" {
		t.Errorf("found: %+v", list.Items[0])
	}
}

// Webhook routes opt in to threat notices: defaults and mode changes never
// add them; naming them in events does, and keeping events keeps them.
func TestWebhookThreatNoticesOptIn(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	var ch struct{ ID int64 }
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "webhook", "name": "h", "config": map[string]string{"url": "https://h.example/x"}}, &ch); code != 201 {
		t.Fatalf("channel: %d", code)
	}
	type route struct {
		ID     int64
		Events []string
	}
	has := func(r route) bool { return slices.Contains(r.Events, "threat_notices") }
	var r route
	if code := admin.do("POST", "/api/v1/routes", map[string]any{"name": "default", "channel_id": ch.ID}, &r); code != 201 || has(r) {
		t.Fatalf("default webhook route: %d %v", code, r.Events)
	}
	if code := admin.do("PUT", fmt.Sprint("/api/v1/routes/", r.ID), map[string]any{"name": "default", "channel_id": ch.ID, "mode": "urgent_only"}, &r); code != 200 || has(r) {
		t.Fatalf("mode change: %d %v", code, r.Events)
	}
	if code := admin.do("PUT", fmt.Sprint("/api/v1/routes/", r.ID), map[string]any{"name": "default", "channel_id": ch.ID,
		"events": []string{"urgent", "threat_notices"}}, &r); code != 200 || !has(r) {
		t.Fatalf("opted in: %d %v", code, r.Events)
	}
	if code := admin.do("PUT", fmt.Sprint("/api/v1/routes/", r.ID), map[string]any{"name": "renamed", "channel_id": ch.ID}, &r); code != 200 || !has(r) {
		t.Fatalf("kept: %d %v", code, r.Events)
	}
	// Other channels get it by default.
	var sl struct{ ID int64 }
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "email", "name": "e", "config": map[string]any{"host": "smtp.example.org", "port": 587, "from": "a@example.org", "to": []string{"b@example.org"}}}, &sl); code != 201 {
		t.Skipf("email channel: %d", code)
	}
	if code := admin.do("POST", "/api/v1/routes", map[string]any{"name": "mail", "channel_id": sl.ID}, &r); code != 201 || !has(r) {
		t.Errorf("default email route: %d %v", code, r.Events)
	}
}
