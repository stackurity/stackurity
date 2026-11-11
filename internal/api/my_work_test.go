package api_test

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/tenant"
)

// My work (Fixes ▸ My work): assignee=mine keeps issues and fixes assigned
// to the caller or to a team they are in; checks?failed=true keeps the
// latest check of a fix that did not clear it.
func TestMyWorkFilters(t *testing.T) {
	e := newEnv(t)
	e.user("eng@x.io", auth.RoleEngineer)
	e.user("ops@x.io", auth.RoleEngineer)
	e.user("other@x.io", auth.RoleEngineer)
	eng := e.login("eng@x.io")
	ops := e.login("ops@x.io")
	other := e.login("other@x.io")
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	a := actionCentreHost(t, e, ctx, "web-1", "4.17.15")
	b := actionCentreHost(t, e, ctx, "web-2", "4.17.10")
	if _, err := planner.Rebuild(ctx, e.st, time.Now()); err != nil {
		t.Fatal(err)
	}
	userID := func(s *session) int64 {
		var me struct {
			User struct{ ID int64 } `json:"user"`
		}
		if code := s.do("GET", "/api/v1/auth/me", nil, &me); code != 200 || me.User.ID == 0 {
			t.Fatalf("me: %d %+v", code, me)
		}
		return me.User.ID
	}
	engID, opsID := userID(eng), userID(ops)
	team, err := e.st.CreateTeam(ctx, "ops", "")
	if err != nil {
		t.Fatal(err)
	}
	members := []int64{opsID}
	if err := e.st.UpdateTeam(ctx, team.ID, nil, nil, &members); err != nil {
		t.Fatal(err)
	}
	findingsOf := func(asset int64) []int64 {
		var fs struct {
			Items []struct{ ID int64 } `json:"items"`
		}
		if code := eng.do("GET", fmt.Sprintf("/api/v1/findings?asset_id=%d", asset), nil, &fs); code != 200 || len(fs.Items) != 2 {
			t.Fatalf("findings of %d: %d %+v", asset, code, fs)
		}
		return []int64{fs.Items[0].ID, fs.Items[1].ID}
	}
	fa, fb := findingsOf(a), findingsOf(b)
	// One issue on web-1 to the engineer, one on web-2 to the ops team.
	if code := eng.do("POST", "/api/v1/findings/actions", map[string]any{"action": "assign", "ids": []int64{fa[0]}, "user_id": engID}, nil); code != 200 {
		t.Fatalf("assign user: %d", code)
	}
	if code := eng.do("POST", "/api/v1/findings/actions", map[string]any{"action": "assign", "ids": []int64{fb[0]}, "team_id": team.ID}, nil); code != 200 {
		t.Fatalf("assign team: %d", code)
	}

	count := func(s *session, path string, want int) {
		t.Helper()
		var l struct {
			Total int `json:"total"`
		}
		if code := s.do("GET", path, nil, &l); code != 200 || l.Total != want {
			t.Errorf("%s: %d total %d, want %d", path, code, l.Total, want)
		}
	}
	count(eng, "/api/v1/findings?assignee=me", 1)
	count(eng, "/api/v1/findings?assignee=mine", 1)
	count(ops, "/api/v1/findings?assignee=me", 0)
	count(ops, "/api/v1/findings?assignee=mine", 1)
	count(other, "/api/v1/findings?assignee=mine", 0)
	count(eng, "/api/v1/fix-groups?group_by=asset&assignee=mine", 1)
	count(ops, "/api/v1/fix-groups?group_by=asset&assignee=mine", 1)
	count(ops, "/api/v1/fix-groups?group_by=asset&assignee=me", 0)
	count(other, "/api/v1/fix-groups?group_by=asset&assignee=mine", 0)
	if code := eng.do("GET", "/api/v1/fix-groups?assignee=team", nil, nil); code != 400 {
		t.Errorf("assignee=team: %d, want 400", code)
	}
	if code := e.anon().do("GET", "/api/v1/findings?assignee=mine", nil, nil); code != 401 {
		t.Errorf("anonymous assignee=mine: %d, want 401", code)
	}

	// Checks: on web-1 a failed check replaced by a passed one; on web-2 a
	// passed check then a still-open one; an old failure; a waiting one.
	ins := func(asset int64, group, outcome string, ago time.Duration) {
		t.Helper()
		var done any
		if outcome != "" {
			done = time.Now().Add(-ago)
		}
		if _, err := e.st.Pool.Exec(ctx, `INSERT INTO checks (asset_id, fix_group, method, requested_at, completed_at, outcome)
			VALUES ($1, $2, 'agent', $3, $4, $5)`, asset, group, time.Now().Add(-ago-time.Minute), done, outcome); err != nil {
			t.Fatal(err)
		}
	}
	ins(a, "g1", "still_open", 3*time.Hour)
	ins(a, "g1", "passed", 2*time.Hour)
	ins(b, "g2", "passed", 3*time.Hour)
	ins(b, "g2", "still_open", 2*time.Hour)
	ins(b, "g3", "expired", 40*24*time.Hour)
	ins(b, "g4", "partly_fixed", time.Hour)
	ins(a, "g5", "incomplete", 3*time.Hour)
	ins(a, "g5", "", time.Hour)
	var checks struct {
		Items []struct {
			FixGroup string `json:"fix_group"`
		} `json:"items"`
		Total int `json:"total"`
	}
	if code := eng.do("GET", "/api/v1/checks?failed=true", nil, &checks); code != 200 || checks.Total != 2 {
		t.Fatalf("failed checks: %d %+v", code, checks)
	}
	got := map[string]bool{}
	for _, c := range checks.Items {
		got[c.FixGroup] = true
	}
	if !got["g2"] || !got["g4"] {
		t.Errorf("failed checks = %+v, want g2 and g4", checks.Items)
	}
	count(eng, "/api/v1/checks?failed=true&asset_id="+url.QueryEscape(fmt.Sprint(a)), 0)
	count(eng, "/api/v1/checks", 8)
}
