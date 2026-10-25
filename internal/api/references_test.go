package api_test

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// TestCrossWorkspaceReferences: B cannot point its own objects at A's
// (foreign keys are checked without row-level security, so the database
// alone would accept them), and A can still change and delete its objects.
func TestCrossWorkspaceReferences(t *testing.T) {
	e := newEnv(t)
	box, _ := secrets.NewBox([]byte("0123456789abcdef0123456789abcdef"))
	e.api.SecretBox = box
	ctx := context.Background()
	e.user("admin-alpha@x.io", auth.RoleAdmin)
	betaWS, _, err := e.st.CreateWorkspace(ctx, "Beta Corp", "", "admin-beta@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	a := e.tenant(t, tenant.DefaultWorkspace, "alpha", e.login("admin-alpha@x.io"))
	b := e.tenant(t, betaWS.ID, "beta", e.login("admin-beta@x.io"))
	bs := b.sess["admin"]
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/v1/routes", map[string]any{"name": "x", "channel_id": a.int("channel"), "enabled": true}},
		{"PUT", "/api/v1/routes/" + b.ids["route"], map[string]any{"name": "x", "channel_id": a.int("channel"), "enabled": true}},
		{"PATCH", "/api/v1/assets/" + b.ids["asset"], map[string]any{"owner_team_id": a.int("team")}},
		{"POST", "/api/v1/findings/" + b.ids["finding"] + "/actions", map[string]any{"action": "assign", "team_id": a.int("team")}},
		{"POST", "/api/v1/findings/" + b.ids["finding"] + "/actions", map[string]any{"action": "assign", "user_id": a.int("user")}},
		{"POST", "/api/v1/findings/actions", map[string]any{"action": "assign", "team_id": a.int("team"), "ids": []int64{b.int("finding")}}},
		{"POST", "/api/v1/incidents/" + b.ids["incident"] + "/actions", map[string]any{"action": "assign", "team_id": a.int("team")}},
		{"POST", "/api/v1/assets/" + b.ids["asset"] + "/relations", map[string]any{"to_asset": a.int("asset"), "kind": "depends_on"}},
		{"POST", "/api/v1/conflicts/" + b.ids["conflict"] + "/resolve", map[string]any{"target_asset_id": a.int("asset2")}},
		{"POST", "/api/v1/teams", map[string]any{"name": "x", "members": []int64{a.int("user")}}},
		{"PATCH", "/api/v1/teams/" + b.ids["team"], map[string]any{"members": []int64{a.int("user")}}},
	} {
		resp := bs.req(c.method, c.path, strings.NewReader(mustJSON(c.body)), map[string]string{"X-Stackurity-CSRF": "1", "Content-Type": "application/json"})
		out, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			t.Errorf("%s %s %v: %d %s", c.method, c.path, c.body, resp.StatusCode, out)
		} else if resp.StatusCode < 300 && !strings.Contains(c.path, "/teams") {
			t.Errorf("%s %s %v accepted a reference to A's object: %d %s", c.method, c.path, c.body, resp.StatusCode, out)
		}
	}
	// Teams must only ever hold the workspace's own members.
	var teams struct{ Items []store.Team }
	bs.do("GET", "/api/v1/teams", nil, &teams)
	for _, tm := range teams.Items {
		for _, m := range tm.Members {
			if m == a.int("user") {
				t.Errorf("B's team %s lists A's admin as a member", tm.Name)
			}
		}
	}
	// A keeps full control of its objects.
	as := a.sess["admin"]
	for _, p := range []string{"/api/v1/routes/" + a.ids["route"], "/api/v1/channels/" + a.ids["channel"], "/api/v1/teams/" + a.ids["team"]} {
		if code := as.do("DELETE", p, nil, nil); code != 204 {
			t.Errorf("A could not delete %s: %d", p, code)
		}
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
