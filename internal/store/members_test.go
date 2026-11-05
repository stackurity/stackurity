package store_test

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func id64(v int64) *int64 { return &v }

// TestCreateMemberScope: adding someone always says what they can see.
// No scope, an ambiguous one, or a grant on another workspace's project or
// asset is refused and creates nothing (account, membership or grant); a
// member given chosen projects and assets sees exactly those.
func TestCreateMemberScope(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	wsB, _, err := s.CreateWorkspace(bg, "B", "", "b@x.io", "", "Correct horse battery 1!")
	if err != nil {
		t.Fatal(err)
	}
	a, b := tenant.WithWorkspace(bg, tenant.DefaultWorkspace), tenant.WithWorkspace(bg, wsB.ID)
	asset := func(ctx context.Context, id string) int64 {
		bt := model.NewBatch(model.Collector{ID: "t", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: id,
			Identifiers: []model.Identifier{{Scheme: "machine-id", Value: id}}})
		if err := bt.Validate(); err != nil {
			t.Fatal(err)
		}
		r, err := s.Ingest(ctx, bt, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}
	a1, a2, a3, b1 := asset(a, "a1"), asset(a, "a2"), asset(a, "a3"), asset(b, "b1")
	proj, err := s.CreateProject(a, "site", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddProjectAssets(a, proj.ID, []int64{a1}); err != nil {
		t.Fatal(err)
	}
	projB, err := s.CreateProject(b, "other", "")
	if err != nil {
		t.Fatal(err)
	}
	archived, err := s.CreateProject(a, "old", "")
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	if err := s.UpdateProject(a, archived.ID, store.ProjectUpdate{Archived: &yes}); err != nil {
		t.Fatal(err)
	}
	grants := func() int {
		gs, err := s.ListGrants(a, store.GrantFilter{})
		if err != nil {
			t.Fatal(err)
		}
		return len(gs)
	}
	before := grants()

	const pw = "Correct horse battery 1!"
	refused := []struct {
		name string
		m    store.NewMember
	}{
		{"no scope at all", store.NewMember{Email: "n@x.io", Password: pw}},
		{"role none without grants", store.NewMember{Email: "n@x.io", Password: pw, Role: store.RoleNone}},
		{"role none with an empty list", store.NewMember{Email: "n@x.io", Password: pw, Role: store.RoleNone, Grants: []store.ScopeGrant{}}},
		{"org role and grants", store.NewMember{Email: "n@x.io", Password: pw, Role: auth.RoleViewer,
			Grants: []store.ScopeGrant{{ProjectID: &proj.ID, Role: auth.RoleViewer}}}},
		{"unknown role", store.NewMember{Email: "n@x.io", Password: pw, Role: "owner"}},
		{"grant without a role", store.NewMember{Email: "n@x.io", Password: pw, Grants: []store.ScopeGrant{{ProjectID: &proj.ID}}}},
		{"grant naming both", store.NewMember{Email: "n@x.io", Password: pw,
			Grants: []store.ScopeGrant{{ProjectID: &proj.ID, AssetID: &a2, Role: auth.RoleViewer}}}},
		{"grant naming neither", store.NewMember{Email: "n@x.io", Password: pw, Grants: []store.ScopeGrant{{Role: auth.RoleViewer}}}},
		{"project twice", store.NewMember{Email: "n@x.io", Password: pw, Grants: []store.ScopeGrant{
			{ProjectID: &proj.ID, Role: auth.RoleViewer}, {ProjectID: &proj.ID, Role: auth.RoleEngineer}}}},
		{"asset twice", store.NewMember{Email: "n@x.io", Password: pw, Grants: []store.ScopeGrant{
			{AssetID: &a2, Role: auth.RoleViewer}, {AssetID: &a2, Role: auth.RoleEngineer}}}},
		// Atomicity: the first grant is good, the second is not; neither the
		// account nor the membership nor the first grant may remain.
		{"another workspace's asset", store.NewMember{Email: "n@x.io", Password: pw, Grants: []store.ScopeGrant{
			{ProjectID: &proj.ID, Role: auth.RoleViewer}, {AssetID: &b1, Role: auth.RoleEngineer}}}},
		{"another workspace's project", store.NewMember{Email: "n@x.io", Password: pw, Grants: []store.ScopeGrant{
			{AssetID: &a2, Role: auth.RoleViewer}, {ProjectID: &projB.ID, Role: auth.RoleViewer}}}},
		{"no such project", store.NewMember{Email: "n@x.io", Password: pw, Grants: []store.ScopeGrant{
			{AssetID: &a2, Role: auth.RoleViewer}, {ProjectID: id64(987654), Role: auth.RoleViewer}}}},
		{"archived project", store.NewMember{Email: "n@x.io", Password: pw, Grants: []store.ScopeGrant{
			{AssetID: &a2, Role: auth.RoleViewer}, {ProjectID: &archived.ID, Role: auth.RoleViewer}}}},
		{"bad phone", store.NewMember{Email: "n@x.io", Password: pw, Phone: "call me", Role: auth.RoleViewer}},
	}
	for _, c := range refused {
		_, _, err := s.CreateMember(a, c.m, 0)
		if !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", c.name, err)
		}
		if ok, _ := s.UserExists(a, "n@x.io"); ok {
			t.Fatalf("%s: the account was left behind", c.name)
		}
		if n := grants(); n != before {
			t.Fatalf("%s: grants left behind: %d, want %d", c.name, n, before)
		}
	}

	// Specific: one project (its assets, and later ones) and one asset.
	u, ids, err := s.CreateMember(a, store.NewMember{Email: "Spec@X.io ", Name: " Spec ", Phone: "  +91 98450  12345 ", Password: pw,
		Grants: []store.ScopeGrant{{ProjectID: &proj.ID, Role: auth.RoleViewer}, {AssetID: &a2, Role: auth.RoleEngineer}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "spec@x.io" || u.Name != "Spec" || u.Role != "" || u.Access != "projects" || u.Phone != "+91 98450 12345" ||
		u.ProjectGrants != 1 || u.AssetGrants != 1 || len(ids) != 2 {
		t.Fatalf("specific member: %+v ids %v", u, ids)
	}
	acc, err := s.UserAccess(a, tenant.DefaultWorkspace, u.ID)
	if err != nil || !acc.Restricted() || acc.ProjectRole != auth.RoleEngineer {
		t.Fatalf("access: %+v %v", acc, err)
	}
	// What the database shows them: a1 through the project, a2 through
	// its asset grant; not a3, and nothing of workspace B.
	seen := func() []int64 {
		as, _, err := s.ListAssets(tenant.WithMember(a, u.ID), store.AssetFilter{})
		if err != nil {
			t.Fatal(err)
		}
		var out []int64
		for _, x := range as {
			out = append(out, x.ID)
		}
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out
	}
	if got := seen(); len(got) != 2 || got[0] != a1 || got[1] != a2 {
		t.Fatalf("specific member sees %v, want [%d %d] (not %d)", got, a1, a2, a3)
	}
	// A project grant covers assets added to the project later.
	if _, err := s.AddProjectAssets(a, proj.ID, []int64{a3}); err != nil {
		t.Fatal(err)
	}
	if got := seen(); len(got) != 3 {
		t.Fatalf("after adding a3 to the project: %v", got)
	}
	if role, err := s.GrantRoleOn(a, u.ID, []int64{a2}); err != nil || role != auth.RoleEngineer {
		t.Errorf("role on a2: %q %v", role, err)
	}
	if role, err := s.GrantRoleOn(a, u.ID, []int64{a1}); err != nil || role != auth.RoleViewer {
		t.Errorf("role on a1: %q %v", role, err)
	}

	// Already a member: 409, and their grants are untouched.
	if _, _, err := s.CreateMember(a, store.NewMember{Email: "spec@x.io", Role: auth.RoleAdmin}, 0); !errors.Is(err, store.ErrConflict) {
		t.Errorf("again: %v", err)
	}

	// All: an organisation-wide role and no grants.
	all, ids, err := s.CreateMember(a, store.NewMember{Email: "all@x.io", Password: pw, Role: auth.RoleEngineer}, 0)
	if err != nil || all.Role != auth.RoleEngineer || all.Access != "organisation" || len(ids) != 0 || all.ProjectGrants+all.AssetGrants != 0 {
		t.Fatalf("all: %+v %v %v", all, ids, err)
	}

	// The phone belongs to the membership: another workspace adding the
	// same account keeps its own.
	if _, _, err := s.CreateMember(b, store.NewMember{Email: "all@x.io", Phone: "020 7946 0000", Role: auth.RoleViewer}, 0); err != nil {
		t.Fatal(err)
	}
	if u, err := s.GetUser(a, all.ID); err != nil || u.Phone != "" {
		t.Errorf("phone in A after B set one: %q %v", u.Phone, err)
	}
	// UpdateUser keeps an active admin in the workspace.
	if _, _, err := s.CreateMember(a, store.NewMember{Email: "boss@x.io", Password: pw, Role: auth.RoleAdmin}, 0); err != nil {
		t.Fatal(err)
	}
	phone := "+1 (555) 010-9999"
	if err := s.UpdateUser(a, all.ID, store.UserUpdate{Phone: &phone}, false); err != nil {
		t.Fatalf("an admin of A changes the phone of a shared account: %v", err)
	}
	if u, _ := s.GetUser(b, all.ID); u.Phone != "020 7946 0000" {
		t.Errorf("B's phone changed: %q", u.Phone)
	}
	bad := "12"
	if err := s.UpdateUser(a, all.ID, store.UserUpdate{Phone: &bad}, false); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("short phone: %v", err)
	}
}

func TestNormalizePhone(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "   ": "", "+91 98450 12345": "+91 98450 12345", " 020  7946\t0000 ": "020 7946 0000",
		"+1 (555) 010-9999": "+1 (555) 010-9999", "555.010.9999": "555.010.9999", "123456": "123456",
	} {
		if got, err := store.NormalizePhone(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"12345", "1234567890123456", "98450+12345", "++91 98450", "phone", "+91 98450 12345 ext 2",
		"<script>", "+1 (555) 010-9999 0000000000000000000000", "１２３４５６７"} {
		if _, err := store.NormalizePhone(in); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%q: accepted", in)
		}
	}
}
