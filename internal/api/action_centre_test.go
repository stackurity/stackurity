package api_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// actionCentreHost ingests a host with lodash at version and two
// vulnerabilities on it, and returns the asset.
func actionCentreHost(t *testing.T, e *env, ctx context.Context, name, version string) int64 {
	t.Helper()
	b := model.NewBatch(model.Collector{ID: "agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: name,
		Identifiers: []model.Identifier{{Scheme: "machine-id", Value: name}}})
	b.Observations = []model.Observation{{Purl: "pkg:npm/lodash@" + version, Confidence: model.ConfidenceConfirmed}}
	b.Complete = true
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	res, err := e.st.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := e.st.ListInventory(ctx, store.InventoryFilter{AssetID: res.AssetID})
	if err != nil || len(rows) != 1 {
		t.Fatalf("inventory: %v %v", rows, err)
	}
	r := rows[0]
	in := []store.FindingInput{
		{Kind: "vulnerability", Key: "CVE-2021-23337", InventoryID: r.ID, AssetID: res.AssetID, ComponentID: r.ComponentID,
			Verification: "confirmed", Severity: "high", FixedVersion: "4.17.21", Sources: []string{"GHSA-1"}, Evidence: map[string]any{}},
		{Kind: "vulnerability", Key: "CVE-2020-8203", InventoryID: r.ID, AssetID: res.AssetID, ComponentID: r.ComponentID,
			Verification: "confirmed", Severity: "high", FixedVersion: "4.17.19", Sources: []string{"GHSA-2"}, Evidence: map[string]any{}}}
	if _, _, err := e.st.SyncFindings(ctx, []string{"vulnerability"}, []int64{r.ID}, in); err != nil {
		t.Fatal(err)
	}
	return res.AssetID
}

type acGroup struct {
	ID          string `json:"id"`
	TopPriority string `json:"top_priority"`
}

type acList struct {
	Items []acGroup `json:"items"`
	Total int       `json:"total"`
}

// The Fixes table: where the work on each fix stands (owner, deadline,
// overdue, in progress), the summary tiles' counts, and the filters the
// tiles and built-in views open.
func TestFixGroupWorkAndFilters(t *testing.T) {
	e := newEnv(t)
	e.user("view@x.io", auth.RoleViewer)
	e.user("eng@x.io", auth.RoleEngineer)
	view := e.login("view@x.io")
	eng := e.login("eng@x.io")
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	a := actionCentreHost(t, e, ctx, "web-1", "4.17.15")
	actionCentreHost(t, e, ctx, "web-2", "4.17.10")
	if _, err := planner.Rebuild(ctx, e.st, time.Now()); err != nil {
		t.Fatal(err)
	}
	var all acList
	if code := view.do("GET", "/api/v1/fix-groups?group_by=asset", nil, &all); code != 200 || all.Total != 2 {
		t.Fatalf("fixes: %d %+v", code, all)
	}
	var g1 string
	for _, g := range all.Items {
		if strings.HasPrefix(g.ID, itoa(a)+":") {
			g1 = g.ID
		}
	}
	if g1 == "" {
		t.Fatalf("no group on asset %d: %+v", a, all.Items)
	}
	var me struct {
		User struct{ ID int64 } `json:"user"`
	}
	if code := eng.do("GET", "/api/v1/auth/me", nil, &me); code != 200 || me.User.ID == 0 {
		t.Fatalf("me: %d %+v", code, me)
	}
	// Assign one issue of g1 to the engineer; make the other overdue.
	var fs struct {
		Items []struct{ ID int64 } `json:"items"`
	}
	if code := view.do("GET", "/api/v1/findings?fix_group="+url.QueryEscape(g1), nil, &fs); code != 200 || len(fs.Items) != 2 {
		t.Fatalf("findings of %s: %d %+v", g1, code, fs)
	}
	if code := eng.do("POST", "/api/v1/findings/actions", map[string]any{"action": "assign", "ids": []int64{fs.Items[0].ID}, "user_id": me.User.ID}, nil); code != 200 {
		t.Fatalf("assign: %d", code)
	}
	if _, err := e.st.Pool.Exec(ctx, `UPDATE findings SET fix_due = now() - interval '2 days' WHERE id = $1`, fs.Items[1].ID); err != nil {
		t.Fatal(err)
	}

	var work struct {
		Items []store.FixWork `json:"items"`
	}
	ids := all.Items[0].ID + "," + all.Items[1].ID + ",9999:nope"
	if code := eng.do("GET", "/api/v1/fix-groups/work?ids="+url.QueryEscape(ids), nil, &work); code != 200 || len(work.Items) != 2 {
		t.Fatalf("work: %d %+v", code, work)
	}
	for _, w := range work.Items {
		if w.GroupID != g1 {
			if w.Mine != 0 || w.Overdue != 0 || len(w.Owners) != 0 || w.Unassigned != 2 {
				t.Errorf("other group work = %+v", w)
			}
			continue
		}
		if w.Active != 2 || w.Mine != 1 || w.Overdue != 1 || w.Unassigned != 1 || len(w.Owners) != 1 || w.Owners[0] != "eng@x.io" || w.Due == nil || !w.Due.Before(time.Now()) {
			t.Errorf("g1 work = %+v", w)
		}
	}
	// The viewer sees the same owners, but none is theirs.
	work.Items = nil
	if view.do("GET", "/api/v1/fix-groups/work?ids="+url.QueryEscape(g1), nil, &work); len(work.Items) != 1 || work.Items[0].Mine != 0 {
		t.Errorf("viewer work = %+v", work)
	}
	many := make([]string, 501)
	for i := range many {
		many[i] = "g" + itoa(int64(i))
	}
	if code := view.do("GET", "/api/v1/fix-groups/work?ids="+strings.Join(many, ","), nil, nil); code != 400 {
		t.Errorf("too many ids: %d", code)
	}

	// Filters.
	check := func(s *session, q string, want int) {
		t.Helper()
		var l acList
		if code := s.do("GET", "/api/v1/fix-groups?group_by=asset&"+q, nil, &l); code != 200 || l.Total != want {
			t.Errorf("%s: %d total %d, want %d", q, code, l.Total, want)
		}
	}
	check(view, "overdue=true", 1)
	check(eng, "assignee=me", 1)
	check(view, "assignee=me", 0)
	check(view, "exploited=true", 0)
	byPrio := map[string]int{}
	for _, g := range all.Items {
		byPrio[g.TopPriority]++
	}
	for p, n := range byPrio {
		check(view, "priority="+p, n)
	}
	check(view, "priority=P1,P2,P3,P4", 2)
	for _, q := range []string{"priority=P9", "assignee=someone"} {
		if code := view.do("GET", "/api/v1/fix-groups?"+q, nil, nil); code != 400 {
			t.Errorf("%s: %d, want 400", q, code)
		}
	}

	// Summary tiles.
	var sum struct {
		Groups     int            `json:"groups"`
		ByPriority map[string]int `json:"by_priority"`
		Overdue    int            `json:"overdue"`
		Exploited  int            `json:"exploited"`
	}
	if code := view.do("GET", "/api/v1/fix-groups/summary?group_by=asset", nil, &sum); code != 200 || sum.Groups != 2 || sum.Overdue != 1 || sum.Exploited != 0 {
		t.Fatalf("summary: %d %+v", code, sum)
	}
	for p, n := range byPrio {
		if sum.ByPriority[p] != n {
			t.Errorf("summary by priority %v, list %v", sum.ByPriority, byPrio)
		}
	}
	sum.ByPriority = nil
	if view.do("GET", "/api/v1/fix-groups/summary?group_by=asset&asset_id="+itoa(a), nil, &sum); sum.Groups != 1 || sum.Overdue != 1 {
		t.Errorf("one asset summary: %+v", sum)
	}
}

// Saved views belong to the person who saved them: nobody else lists or
// deletes them, a name saved again replaces its query, and a page keeps a
// bounded number.
func TestSavedViews(t *testing.T) {
	e := newEnv(t)
	e.user("a@x.io", auth.RoleViewer)
	e.user("b@x.io", auth.RoleAdmin)
	a := e.login("a@x.io")
	b := e.login("b@x.io")
	type view struct {
		ID    int64  `json:"id"`
		Page  string `json:"page"`
		Name  string `json:"name"`
		Query string `json:"query"`
	}
	type views struct {
		Items []view `json:"items"`
	}
	var v view
	if code := a.do("POST", "/api/v1/saved-views", map[string]string{"page": "fixes", "name": " Urgent ", "query": "?priority=P1"}, &v); code != 200 || v.ID == 0 || v.Name != "Urgent" || v.Query != "priority=P1" {
		t.Fatalf("save: %d %+v", code, v)
	}
	var again view
	if code := a.do("POST", "/api/v1/saved-views", map[string]string{"name": "Urgent", "query": "priority=P1,P2"}, &again); code != 200 || again.ID != v.ID || again.Query != "priority=P1,P2" || again.Page != "fixes" {
		t.Fatalf("save again: %d %+v", code, again)
	}
	var l views
	if code := a.do("GET", "/api/v1/saved-views?page=fixes", nil, &l); code != 200 || len(l.Items) != 1 || l.Items[0].Query != "priority=P1,P2" {
		t.Fatalf("list: %d %+v", code, l)
	}
	// Another person, even an admin, sees none and cannot delete it.
	l.Items = nil
	if code := b.do("GET", "/api/v1/saved-views", nil, &l); code != 200 || len(l.Items) != 0 {
		t.Errorf("other person's list: %d %+v", code, l)
	}
	if code := b.do("DELETE", "/api/v1/saved-views/"+itoa(v.ID), nil, nil); code != 404 {
		t.Errorf("other person's delete: %d", code)
	}
	for _, bad := range []map[string]string{
		{"page": "assets", "name": "x"},
		{"name": ""},
		{"name": strings.Repeat("n", 61)},
		{"name": "x", "query": strings.Repeat("q", 2001)},
		{"name": "x", "query": "a=1#frag"},
	} {
		if code := a.do("POST", "/api/v1/saved-views", bad, nil); code != 400 {
			t.Errorf("save %v: %d, want 400", bad, code)
		}
	}
	if code := a.do("GET", "/api/v1/saved-views?page=assets", nil, nil); code != 400 {
		t.Errorf("list unknown page: %d", code)
	}
	for i := 1; i < store.SavedViewsMax; i++ {
		if code := a.do("POST", "/api/v1/saved-views", map[string]string{"name": "v" + itoa(int64(i)), "query": "q=" + itoa(int64(i))}, nil); code != 200 {
			t.Fatalf("save %d: %d", i, code)
		}
	}
	if code := a.do("POST", "/api/v1/saved-views", map[string]string{"name": "one too many"}, nil); code != 400 {
		t.Errorf("past the limit: %d", code)
	}
	// Replacing an existing one is still allowed at the limit.
	if code := a.do("POST", "/api/v1/saved-views", map[string]string{"name": "Urgent", "query": "priority=P1"}, nil); code != 200 {
		t.Errorf("replace at the limit: %d", code)
	}
	if code := a.do("DELETE", "/api/v1/saved-views/"+itoa(v.ID), nil, nil); code != 204 {
		t.Errorf("delete: %d", code)
	}
	if code := a.do("DELETE", "/api/v1/saved-views/"+itoa(v.ID), nil, nil); code != 404 {
		t.Errorf("delete again: %d", code)
	}
}
