package api_test

import (
	"context"
	"fmt"
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
