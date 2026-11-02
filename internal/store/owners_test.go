package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

// owner says who an issue is assigned to: "user:<email>", "team:<name>",
// both, or "".
func owner(t *testing.T, s *store.Store, ctx context.Context, asset int64, key string) string {
	t.Helper()
	fs := findings(t, s, ctx, store.FindingFilter{AssetID: asset, Key: key, Status: "open"})
	if len(fs) != 1 {
		t.Fatalf("%d %s: %d findings", asset, key, len(fs))
	}
	var out []string
	if fs[0].AssigneeEmail != "" {
		out = append(out, "user:"+fs[0].AssigneeEmail)
	}
	if fs[0].AssigneeTeam != "" {
		out = append(out, "team:"+fs[0].AssigneeTeam)
	}
	return strings.Join(out, " ")
}

// Owner rules assign issues nobody assigned: the most specific matching
// rule wins (asset and stack, asset, project, stack, organisation), a
// person's assignment is never changed, a changed rule moves what rules
// assigned only through ApplyOwnerRules, which previews first.
func TestOwnerRules(t *testing.T) {
	ctx, s := loopStore(t)
	shop := ingestImage(t, s, ctx, "registry.example.com/shop/api:1", digestA, "pkg:deb/debian/openssl@3.0.11?distro=debian-12", "pkg:npm/lodash@4.17.20")
	blog := ingestImage(t, s, ctx, "registry.example.com/blog/web:1", digestB, "pkg:npm/lodash@4.17.20")
	syncOpen(t, s, ctx, shop, map[string]string{"CVE-OS": "openssl", "CVE-LIB": "lodash"})
	syncOpen(t, s, ctx, blog, map[string]string{"CVE-LIB": "lodash", "CVE-HAND": "lodash"})

	ravi, err := s.CreateUser(ctx, "ravi@example.com", "Ravi", "engineer", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	anita, err := s.CreateUser(ctx, "anita@example.com", "Anita", "engineer", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := s.CreateTeam(ctx, "Security", "")
	if err != nil {
		t.Fatal(err)
	}
	web, err := s.CreateTeam(ctx, "Web", "")
	if err != nil {
		t.Fatal(err)
	}
	proj, err := s.CreateProject(ctx, "Blog", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddProjectAssets(ctx, proj.ID, []int64{blog}); err != nil {
		t.Fatal(err)
	}

	// A person assigned this one before any rule: it stays theirs.
	if err := s.ApplyFindingAction(ctx, findings(t, s, ctx, store.FindingFilter{AssetID: blog, Key: "CVE-HAND"})[0].ID,
		store.FindingAction{Action: "assign", AssignUser: &anita.ID}, store.Actor{Type: "user", ID: anita.ID, Name: "anita@example.com"}); err != nil {
		t.Fatal(err)
	}

	// No rules: nothing happens.
	if n, err := s.AssignByOwnerRules(ctx); err != nil || n != 0 {
		t.Fatalf("no rules: %d %v", n, err)
	}

	save := func(id int64, in store.OwnerRuleInput) *store.OwnerRule {
		t.Helper()
		r, err := s.SaveOwnerRule(ctx, id, in, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	save(0, store.OwnerRuleInput{TeamID: &sec.ID})                                                  // organisation default
	save(0, store.OwnerRuleInput{Layer: "os", UserID: &ravi.ID})                                    // OS packages anywhere
	blogRule := save(0, store.OwnerRuleInput{ProjectID: &proj.ID, UserID: &anita.ID})               // the Blog project
	shopLodash := save(0, store.OwnerRuleInput{AssetID: &shop, Component: "lod*", TeamID: &web.ID}) // lodash on shop
	if shopLodash.Level != 6 || blogRule.Level != 3 || shopLodash.Describe != "packages lod* on registry.example.com/shop/api:1" {
		t.Errorf("rule levels/describe: %d %d %q", shopLodash.Level, blogRule.Level, shopLodash.Describe)
	}

	if n, err := s.AssignByOwnerRules(ctx); err != nil || n != 3 {
		t.Fatalf("pass: %d %v", n, err)
	}
	for _, c := range []struct {
		asset int64
		key   string
		want  string
	}{
		{shop, "CVE-OS", "user:ravi@example.com"}, // stack rule beats the organisation default
		{shop, "CVE-LIB", "team:Web"},             // asset and package beat everything
		{blog, "CVE-LIB", "user:anita@example.com"},
		{blog, "CVE-HAND", "user:anita@example.com"}, // assigned by a person, untouched
	} {
		if got := owner(t, s, ctx, c.asset, c.key); got != c.want {
			t.Errorf("%d %s: %q, want %q", c.asset, c.key, got, c.want)
		}
	}
	evs, err := s.FindingEvents(ctx, findings(t, s, ctx, store.FindingFilter{AssetID: shop, Key: "CVE-LIB"})[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if last := evs[len(evs)-1]; last.Action != "assign" || !strings.Contains(last.Note, "packages lod* on") {
		t.Errorf("history: %+v", last)
	}
	// Checked: a second pass does nothing.
	if n, err := s.AssignByOwnerRules(ctx); err != nil || n != 0 {
		t.Fatalf("second pass: %d %v", n, err)
	}

	// The Blog rule now names Ravi: the pass leaves what rules assigned,
	// the preview says what would move, applying moves it.
	save(blogRule.ID, store.OwnerRuleInput{ProjectID: &proj.ID, UserID: &ravi.ID})
	if _, err := s.AssignByOwnerRules(ctx); err != nil {
		t.Fatal(err)
	}
	if got := owner(t, s, ctx, blog, "CVE-LIB"); got != "user:anita@example.com" {
		t.Errorf("pass moved a rule's assignment: %q", got)
	}
	plan, err := s.ApplyOwnerRules(ctx, true)
	if err != nil || plan.Total != 1 || plan.Applied || plan.Moves[0].FromUser != "anita@example.com" || plan.Moves[0].ToUser != "ravi@example.com" {
		t.Fatalf("preview: %+v %v", plan, err)
	}
	if got := owner(t, s, ctx, blog, "CVE-LIB"); got != "user:anita@example.com" {
		t.Errorf("preview changed something: %q", got)
	}
	if plan, err = s.ApplyOwnerRules(ctx, false); err != nil || plan.Total != 1 || !plan.Applied {
		t.Fatalf("apply: %+v %v", plan, err)
	}
	if got := owner(t, s, ctx, blog, "CVE-LIB"); got != "user:ravi@example.com" {
		t.Errorf("applied: %q", got)
	}
	if got := owner(t, s, ctx, blog, "CVE-HAND"); got != "user:anita@example.com" {
		t.Errorf("apply moved a person's assignment: %q", got)
	}

	// Without the lodash rule, shop's lodash falls back to the default.
	if err := s.DeleteOwnerRule(ctx, shopLodash.ID); err != nil {
		t.Fatal(err)
	}
	if plan, err = s.ApplyOwnerRules(ctx, false); err != nil || plan.Total != 1 {
		t.Fatalf("after delete: %+v %v", plan, err)
	}
	if got := owner(t, s, ctx, shop, "CVE-LIB"); got != "team:Security" {
		t.Errorf("fallback: %q", got)
	}
	if plan, err = s.ApplyOwnerRules(ctx, true); err != nil || plan.Total != 0 {
		t.Errorf("in line: %+v %v", plan, err)
	}

	// Rules for an asset list its own, its projects' and the organisation's.
	rules, err := s.ListOwnerRules(ctx, store.OwnerRuleFilter{AssetID: blog})
	if err != nil || len(rules) != 3 || rules[0].ID != blogRule.ID {
		t.Errorf("rules for blog: %+v %v", rules, err)
	}

	// Refused: both a project and an asset, no owner, an unknown layer.
	for _, in := range []store.OwnerRuleInput{
		{ProjectID: &proj.ID, AssetID: &blog, TeamID: &sec.ID},
		{Layer: "os"},
		{Layer: "kernel", TeamID: &sec.ID},
	} {
		if _, err := s.SaveOwnerRule(ctx, 0, in, 0); err == nil {
			t.Errorf("saved %+v", in)
		}
	}
}
