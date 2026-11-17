package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// gateFixture: four hosts, as for scoped routes.
//
//	shop: web, db    blog: db, wiki    in no project: loose
//
// web (production, internet-facing) has openssl 3.0.2 with a known
// exploited, critical CVE first seen 30 days ago; db has python 3.8, past
// its end of life; wiki serves a high leaked key; loose has a medium CVE.
type gateFixture struct {
	s                    *store.Store
	ctx                  context.Context
	web, db, wiki, loose int64
	shop, blog           int64
	kevFinding, eolFind  int64
	leakID               int64
	admin                store.Actor
}

func syncFindings(t *testing.T, s *store.Store, ctx context.Context, asset int64, mk func(r store.InventoryRow) []store.FindingInput) {
	t.Helper()
	rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: asset})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	var in []store.FindingInput
	for _, r := range rows {
		ids = append(ids, r.ID)
		in = append(in, mk(r)...)
	}
	if _, _, err := s.SyncFindings(ctx, []string{"vulnerability", "end_of_life"}, ids, in); err != nil {
		t.Fatal(err)
	}
}

func newGateFixture(t *testing.T) *gateFixture {
	t.Helper()
	s := store.New(testdb.New(t))
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := &gateFixture{s: s, ctx: ctx, admin: store.Actor{Type: "system", Name: "test"}}
	f.web = ingestHost(t, s, ctx, "web", "pkg:generic/openssl@3.0.2")
	f.db = ingestHost(t, s, ctx, "db", "pkg:generic/python@3.8.10")
	f.wiki = ingestHost(t, s, ctx, "wiki")
	f.loose = ingestHost(t, s, ctx, "loose", "pkg:generic/zlib@1.2.11")
	project := func(name string, assets ...int64) int64 {
		p, err := s.CreateProject(ctx, name, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.AddProjectAssets(ctx, p.ID, assets); err != nil {
			t.Fatal(err)
		}
		return p.ID
	}
	f.shop, f.blog = project("shop", f.web, f.db), project("blog", f.db, f.wiki)
	syncFindings(t, s, ctx, f.web, func(r store.InventoryRow) []store.FindingInput {
		return []store.FindingInput{{Kind: "vulnerability", Key: "CVE-2026-1234", InventoryID: r.ID, AssetID: f.web, ComponentID: r.ComponentID,
			Verification: "confirmed", Severity: "critical", FixedVersion: "3.0.15", Sources: []string{"GHSA-x"},
			Evidence: map[string]any{"known_exploited": true}}}
	})
	syncFindings(t, s, ctx, f.db, func(r store.InventoryRow) []store.FindingInput {
		return []store.FindingInput{{Kind: "end_of_life", Key: "python:3.8", InventoryID: r.ID, AssetID: f.db, ComponentID: r.ComponentID,
			Verification: "confirmed", Severity: "medium", Title: "Python 3.8 is end-of-life since 2024-10-07", Sources: []string{"endoflife"},
			Evidence: map[string]any{"product": "python", "cycle": "3.8", "eol_date": "2024-10-07"}}}
	})
	syncFindings(t, s, ctx, f.loose, func(r store.InventoryRow) []store.FindingInput {
		return []store.FindingInput{{Kind: "vulnerability", Key: "CVE-2026-9999", InventoryID: r.ID, AssetID: f.loose, ComponentID: r.ComponentID,
			Verification: "confirmed", Severity: "medium", Sources: []string{"GHSA-y"}, Evidence: map[string]any{}}}
	})
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := s.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE assets SET environment = 'Prod', internet_exposed = true WHERE id = $1`, f.web)
	exec(`UPDATE findings SET first_seen = now() - interval '30 days' WHERE asset_id = $1`, f.web)
	if err := s.Pool.QueryRow(ctx, `SELECT id FROM findings WHERE asset_id = $1`, f.web).Scan(&f.kevFinding); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool.QueryRow(ctx, `SELECT id FROM findings WHERE asset_id = $1`, f.db).Scan(&f.eolFind); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool.QueryRow(ctx, `INSERT INTO leaks (asset_id, collector_id, fingerprint, path, line, rule, title, severity, exposure)
		VALUES ($1, 'test', $2, '/var/www/.env', 3, 'aws-access-key', 'AWS access key', 'high', 'served') RETURNING id`,
		f.wiki, strings.Repeat("a", 32)).Scan(&f.leakID); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *gateFixture) create(t *testing.T, p store.GatePolicy) *store.GatePolicy {
	t.Helper()
	out, err := f.s.CreateGatePolicy(f.ctx, p, f.admin)
	if err != nil {
		t.Fatalf("create %s: %v", p.Name, err)
	}
	return out
}

// violations returns "policy@asset" for each violation.
func (f *gateFixture) violations(t *testing.T, flt store.GateViolationFilter) []string {
	t.Helper()
	vs, err := f.s.GateViolations(f.ctx, flt)
	if err != nil {
		t.Fatal(err)
	}
	names := map[int64]string{f.web: "web", f.db: "db", f.wiki: "wiki", f.loose: "loose"}
	out := []string{}
	for _, v := range vs {
		out = append(out, v.PolicyName+"@"+names[v.AssetID])
	}
	slices.Sort(out)
	return out
}

func wantViolations(t *testing.T, got []string, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("violations %v, want %v", got, want)
	}
}

func TestGatePolicyViolations(t *testing.T) {
	f := newGateFixture(t)
	s, ctx := f.s, f.ctx
	kev := f.create(t, store.GatePolicy{Name: "kev", Kind: store.GateKnownExploited, Filters: store.GateFilters{Exposure: "exposed"}})
	if kev.Mode != store.GateModeWarn || kev.RuleVersion != 1 || string(kev.Params) != "{}" {
		t.Fatalf("new policy: %+v", kev)
	}
	f.create(t, store.GatePolicy{Name: "age", Kind: store.GateFindingAge, Params: json.RawMessage(`{"min_severity":"critical","max_days":14}`),
		Filters: store.GateFilters{Environments: []string{"production"}}})
	eol := f.create(t, store.GatePolicy{Name: "eol", Kind: store.GateEndOfLife, Params: json.RawMessage(`{"products":["Python"]}`)})
	leak := f.create(t, store.GatePolicy{Name: "leak", Kind: store.GateLeakedKey, Params: json.RawMessage(`{"served_only":true}`)})
	f.create(t, store.GatePolicy{Name: "medium-age", Kind: store.GateFindingAge, Params: json.RawMessage(`{"min_severity":"medium","max_days":1}`),
		Filters: store.GateFilters{AssetKinds: []string{"host"}, Tags: []string{"pci"}}})

	wantViolations(t, f.violations(t, store.GateViolationFilter{}), "kev@web", "age@web", "eol@db", "leak@wiki")
	wantViolations(t, f.violations(t, store.GateViolationFilter{ProjectID: f.blog}), "eol@db", "leak@wiki")
	wantViolations(t, f.violations(t, store.GateViolationFilter{AssetID: f.web}), "kev@web", "age@web")
	wantViolations(t, f.violations(t, store.GateViolationFilter{PolicyID: eol.ID}), "eol@db")

	vs, err := s.GateViolations(ctx, store.GateViolationFilter{AssetID: f.web})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		switch v.PolicyName {
		case "kev":
			if v.Reason != "CVE-2026-1234 in openssl 3.0.2 is known to be exploited" || v.Component != "openssl 3.0.2" ||
				v.FindingID == nil || *v.FindingID != f.kevFinding || v.Link != "/findings/"+itoa64(f.kevFinding) || v.Mode != "warn" {
				t.Errorf("kev violation: %+v", v)
			}
		case "age":
			if !strings.Contains(v.Reason, "has been open for 30 days; the limit is 14") {
				t.Errorf("age reason: %q", v.Reason)
			}
		}
	}
	lv, err := s.GateViolations(ctx, store.GateViolationFilter{PolicyID: leak.ID})
	if err != nil || len(lv) != 1 || lv[0].LeakID == nil || *lv[0].LeakID != f.leakID ||
		lv[0].Reason != "A high AWS access key is written in /var/www/.env:3, which the asset serves to the network" {
		t.Errorf("leak violation: %+v %v", lv, err)
	}

	// The tag filter: loose's medium CVE counts once loose is tagged pci.
	if _, err := s.Pool.Exec(ctx, `UPDATE assets SET tags = '{pci}' WHERE id = $1`, f.loose); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE findings SET first_seen = now() - interval '3 days' WHERE asset_id = $1`, f.loose); err != nil {
		t.Fatal(err)
	}
	wantViolations(t, f.violations(t, store.GateViolationFilter{AssetID: f.loose}), "medium-age@loose")

	// Risk-accepted findings never count.
	if _, err := s.Pool.Exec(ctx, `UPDATE findings SET state = 'risk_accepted' WHERE id = $1`, f.kevFinding); err != nil {
		t.Fatal(err)
	}
	wantViolations(t, f.violations(t, store.GateViolationFilter{AssetID: f.web}))
	if _, err := s.Pool.Exec(ctx, `UPDATE findings SET state = 'new' WHERE id = $1`, f.kevFinding); err != nil {
		t.Fatal(err)
	}

	// An approved exception for the finding takes it out of kev only;
	// once expired, it counts again.
	var exID int64
	if err := s.Pool.QueryRow(ctx, `INSERT INTO gate_policy_exceptions (policy_id, target_kind, asset_id, finding_id, reason, status,
		decided_at, expires_at) VALUES ($1, 'finding', $2, $3, 'mitigated', 'approved', now(), now() + interval '1 day') RETURNING id`,
		kev.ID, f.web, f.kevFinding).Scan(&exID); err != nil {
		t.Fatal(err)
	}
	wantViolations(t, f.violations(t, store.GateViolationFilter{AssetID: f.web}), "age@web")
	if _, err := s.Pool.Exec(ctx, `UPDATE gate_policy_exceptions SET expires_at = now() - interval '1 second' WHERE id = $1`, exID); err != nil {
		t.Fatal(err)
	}
	wantViolations(t, f.violations(t, store.GateViolationFilter{AssetID: f.web}), "kev@web", "age@web")
	// A component exception (openssl) on web covers both of its policies'
	// findings for that policy only.
	if _, err := s.Pool.Exec(ctx, `INSERT INTO gate_policy_exceptions (policy_id, target_kind, asset_id, component_key, reason, status,
		decided_at, expires_at) VALUES ($1, 'component', $2, (SELECT c.purl_key FROM components c JOIN findings fi ON fi.component_id = c.id
		WHERE fi.id = $3), 'no_fix', 'approved', now(), now() + interval '1 day')`, kev.ID, f.web, f.kevFinding); err != nil {
		t.Fatal(err)
	}
	wantViolations(t, f.violations(t, store.GateViolationFilter{AssetID: f.web}), "age@web")

	// Off: no violations.
	kev.Mode = store.GateModeOff
	if _, err := s.UpdateGatePolicy(ctx, *kev, f.admin); err != nil {
		t.Fatal(err)
	}
	if vs := f.violations(t, store.GateViolationFilter{PolicyID: kev.ID}); len(vs) != 0 {
		t.Errorf("an off policy has violations: %v", vs)
	}
}

func TestGatePolicyScopes(t *testing.T) {
	f := newGateFixture(t)
	s, ctx := f.s, f.ctx
	eol := f.create(t, store.GatePolicy{Name: "eol", Kind: store.GateEndOfLife})
	leak := f.create(t, store.GatePolicy{Name: "leak", Kind: store.GateLeakedKey})
	wantViolations(t, f.violations(t, store.GateViolationFilter{}), "eol@db", "leak@wiki")

	// Off for shop: db is still in blog, so eol still reaches it; off for
	// blog too, it does not.
	if err := s.SetGatePolicyExcluded(ctx, eol.ID, store.Owner{ProjectID: &f.shop}, true, f.admin); err != nil {
		t.Fatal(err)
	}
	wantViolations(t, f.violations(t, store.GateViolationFilter{PolicyID: eol.ID}), "eol@db")
	if err := s.SetGatePolicyExcluded(ctx, eol.ID, store.Owner{ProjectID: &f.blog}, true, f.admin); err != nil {
		t.Fatal(err)
	}
	wantViolations(t, f.violations(t, store.GateViolationFilter{PolicyID: eol.ID}))
	if err := s.SetGatePolicyExcluded(ctx, eol.ID, store.Owner{ProjectID: &f.blog}, false, f.admin); err != nil {
		t.Fatal(err)
	}
	// Off for the asset itself.
	if err := s.SetGatePolicyExcluded(ctx, eol.ID, store.Owner{AssetID: &f.db}, true, f.admin); err != nil {
		t.Fatal(err)
	}
	wantViolations(t, f.violations(t, store.GateViolationFilter{PolicyID: eol.ID}))
	if err := s.SetGatePolicyExcluded(ctx, eol.ID, store.Owner{}, true, f.admin); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("turning off for the organisation: %v", err)
	}

	// A project's own policy reaches its assets only.
	shopKEV := f.create(t, store.GatePolicy{Name: "shop kev", Kind: store.GateKnownExploited, OwnerProjectID: &f.shop})
	wantViolations(t, f.violations(t, store.GateViolationFilter{PolicyID: shopKEV.ID}), "shop kev@web")
	if _, err := s.CreateGatePolicy(ctx, store.GatePolicy{Name: "shop kev", Kind: store.GateKnownExploited, OwnerProjectID: &f.shop}, f.admin); !errors.Is(err, store.ErrConflict) {
		t.Errorf("a second policy of the same name in shop: %v", err)
	}
	// ... the same name elsewhere is fine.
	f.create(t, store.GatePolicy{Name: "shop kev", Kind: store.GateKnownExploited, OwnerProjectID: &f.blog})

	// Blog replaces leak with a copy that counts only critical keys.
	cp := *leak
	cp.ID, cp.OwnerProjectID, cp.InheritsPolicyID = 0, &f.blog, &leak.ID
	cp.Params = json.RawMessage(`{"min_severity":"critical"}`)
	copied, err := s.CustomiseGatePolicy(ctx, cp, f.admin)
	if err != nil {
		t.Fatal(err)
	}
	wantViolations(t, f.violations(t, store.GateViolationFilter{AssetID: f.wiki}))
	eff, err := s.EffectiveGatePolicies(ctx, f.wiki)
	if err != nil {
		t.Fatal(err)
	}
	// wiki: eol (turned off for db only), blog's copy of leak and blog's
	// own policy.
	var ids []int64
	for _, p := range eff {
		ids = append(ids, p.ID)
	}
	if len(eff) != 3 || !slices.Contains(ids, copied.ID) || slices.Contains(ids, leak.ID) || !slices.Contains(ids, eol.ID) {
		t.Errorf("wiki's policies: %+v", eff)
	}
	// Deleting the copy turns the inherited policy back on.
	if err := s.DeleteGatePolicy(ctx, copied.ID, f.admin); err != nil {
		t.Fatal(err)
	}
	wantViolations(t, f.violations(t, store.GateViolationFilter{AssetID: f.wiki}), "leak@wiki")
	if ex, err := s.GatePolicyExclusions(ctx, store.Owner{ProjectID: &f.blog}); err != nil || len(ex) != 0 {
		t.Errorf("blog's exclusions after the copy went: %+v %v", ex, err)
	}

	// web: the organisation's leak and shop's kev (eol is off for shop,
	// web's only project).
	eff, err = s.EffectiveGatePolicies(ctx, f.web)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range eff {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "leak,shop kev" {
		t.Errorf("web's policies: %v", names)
	}
}

func TestGatePolicyValidationAndAudit(t *testing.T) {
	f := newGateFixture(t)
	s, ctx := f.s, f.ctx
	for name, p := range map[string]store.GatePolicy{
		"no name":         {Kind: store.GateKnownExploited},
		"bad kind":        {Name: "x", Kind: "nope"},
		"bad mode":        {Name: "x", Kind: store.GateKnownExploited, Mode: "block"},
		"kev params":      {Name: "x", Kind: store.GateKnownExploited, Params: json.RawMessage(`{"max_days":3}`)},
		"age no severity": {Name: "x", Kind: store.GateFindingAge, Params: json.RawMessage(`{"max_days":3}`)},
		"age zero days":   {Name: "x", Kind: store.GateFindingAge, Params: json.RawMessage(`{"min_severity":"high","max_days":0}`)},
		"eol bad date":    {Name: "x", Kind: store.GateEndOfLife, Params: json.RawMessage(`{"after":"next year"}`)},
		"leak severity":   {Name: "x", Kind: store.GateLeakedKey, Params: json.RawMessage(`{"min_severity":"urgent"}`)},
		"exposure":        {Name: "x", Kind: store.GateKnownExploited, Filters: store.GateFilters{Exposure: "public"}},
		"two owners":      {Name: "x", Kind: store.GateKnownExploited, OwnerProjectID: &f.shop, OwnerAssetID: &f.web},
	} {
		if _, err := s.CreateGatePolicy(ctx, p, f.admin); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%s: %v, want invalid", name, err)
		}
	}
	p := f.create(t, store.GatePolicy{Name: "age", Kind: store.GateFindingAge, Params: json.RawMessage(`{"min_severity":"HIGH","max_days":14}`)})
	if !strings.Contains(strings.ReplaceAll(string(p.Params), " ", ""), `"min_severity":"high"`) || p.Filters.Exposure != "any" || p.Filters.Tags == nil {
		t.Errorf("stored form: %s %+v", p.Params, p.Filters)
	}
	// Renaming keeps the rule version; changing params raises it; a mode
	// change alone is gate_policy.mode.
	p.Name = "old criticals"
	if p, _ = s.UpdateGatePolicy(ctx, *p, f.admin); p.RuleVersion != 1 {
		t.Errorf("rename raised the rule version: %d", p.RuleVersion)
	}
	p.Params = json.RawMessage(`{"min_severity":"critical","max_days":14}`)
	if p, _ = s.UpdateGatePolicy(ctx, *p, f.admin); p.RuleVersion != 2 {
		t.Errorf("params change: rule version %d", p.RuleVersion)
	}
	p.Filters.Tags = []string{"pci"}
	if p, _ = s.UpdateGatePolicy(ctx, *p, f.admin); p.RuleVersion != 3 {
		t.Errorf("filters change: rule version %d", p.RuleVersion)
	}
	if _, err := s.UpdateGatePolicy(ctx, *p, f.admin); err != nil { // nothing changed: not audited
		t.Fatal(err)
	}
	p.Mode = store.GateModeEnforce
	if p, _ = s.UpdateGatePolicy(ctx, *p, f.admin); p.RuleVersion != 3 || p.Mode != "enforce" {
		t.Errorf("mode change: %+v", p)
	}
	p.Mode, p.Description = store.GateModeWarn, "softer"
	if _, err := s.UpdateGatePolicy(ctx, *p, f.admin); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGatePolicyExcluded(ctx, p.ID, store.Owner{ProjectID: &f.shop}, true, f.admin); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGatePolicyExcluded(ctx, p.ID, store.Owner{ProjectID: &f.shop}, true, f.admin); err != nil { // again: no event
		t.Fatal(err)
	}
	if err := s.DeleteGatePolicy(ctx, p.ID, f.admin); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGatePolicy(ctx, p.ID, f.admin); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("delete twice: %v", err)
	}
	events, _, err := s.ListAudit(ctx, "gate_policy", itoa64(p.ID), store.Page{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for i := len(events) - 1; i >= 0; i-- {
		actions = append(actions, events[i].Action)
		var d store.GatePolicyAudit
		if err := json.Unmarshal(events[i].Detail, &d); err != nil || d.Summary == "" || d.PolicyID != p.ID {
			t.Errorf("%s detail: %s", events[i].Action, events[i].Detail)
		}
	}
	want := "gate_policy.create,gate_policy.update,gate_policy.update,gate_policy.update,gate_policy.mode,gate_policy.update,gate_policy.exclude,gate_policy.delete"
	if strings.Join(actions, ",") != want {
		t.Errorf("audit\n got %s\nwant %s", strings.Join(actions, ","), want)
	}
}

func TestGatePolicyRollup(t *testing.T) {
	f := newGateFixture(t)
	s, ctx := f.s, f.ctx
	kev := f.create(t, store.GatePolicy{Name: "kev", Kind: store.GateKnownExploited})
	leak := f.create(t, store.GatePolicy{Name: "leak", Kind: store.GateLeakedKey})
	day1 := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	if err := s.RollupGatePolicies(ctx, day1); err != nil {
		t.Fatal(err)
	}
	// The leak goes, the kev finding stays: one closed on day 2.
	if _, err := s.Pool.Exec(ctx, `UPDATE leaks SET status = 'resolved', resolution = 'gone', resolved_at = now() WHERE id = $1`, f.leakID); err != nil {
		t.Fatal(err)
	}
	day2 := day1.AddDate(0, 0, 1)
	for range 2 { // twice the same day: the counts add up once
		if err := s.RollupGatePolicies(ctx, day2); err != nil {
			t.Fatal(err)
		}
	}
	days, err := s.GatePolicyDays(ctx, day1, day2)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]store.GatePolicyDay{}
	for _, d := range days {
		got[d.Day.Format(time.DateOnly)+" "+d.PolicyName] = d
	}
	check := func(key string, violations, assets, opened, closed int) {
		t.Helper()
		d, ok := got[key]
		if !ok || d.Violations != violations || d.Assets != assets || d.Opened != opened || d.Closed != closed {
			t.Errorf("%s: %+v (found %v), want %d/%d/%d/%d", key, d, ok, violations, assets, opened, closed)
		}
	}
	check("2026-11-16 kev", 1, 1, 1, 0)
	check("2026-11-16 leak", 1, 1, 1, 0)
	check("2026-11-17 kev", 1, 1, 0, 0)
	check("2026-11-17 leak", 0, 0, 0, 1)
	// Deleting a policy keeps its history.
	if err := s.DeleteGatePolicy(ctx, leak.ID, f.admin); err != nil {
		t.Fatal(err)
	}
	if days, _ := s.GatePolicyDays(ctx, day1, day2); len(days) != 4 {
		t.Errorf("history after delete: %+v", days)
	}
	_ = kev
}

func TestGatePolicyExceptionsWindow(t *testing.T) {
	f := newGateFixture(t)
	s, ctx := f.s, f.ctx
	p := f.create(t, store.GatePolicy{Name: "kev", Kind: store.GateKnownExploited})
	at := func(day int) time.Time { return time.Date(2026, 10, day, 12, 0, 0, 0, time.UTC) }
	add := func(label string, requested time.Time, status string, decided, expires, ended *time.Time, endReason string) {
		t.Helper()
		if _, err := s.Pool.Exec(ctx, `INSERT INTO gate_policy_exceptions (policy_id, target_kind, asset_id, target_label, reason, status,
			requested_by_name, requested_at, decided_by_name, decided_at, expires_at, ended_at, end_reason)
			VALUES ($1, 'asset', $2, $3, 'accepted_risk', $4, 'eng', $5, 'sec', $6, $7, $8, $9)`,
			p.ID, f.web, label, status, requested, decided, expires, ended, endReason); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
	}
	ptr := func(t time.Time) *time.Time { return &t }
	// The window is 10 to 20 October.
	add("before, ended before", at(1), "ended", ptr(at(1)), ptr(at(30)), ptr(at(5)), "revoked")
	add("before, expired before", at(1), "approved", ptr(at(1)), ptr(at(9)), nil, "")
	add("before, expired inside", at(1), "approved", ptr(at(1)), ptr(at(15)), nil, "")
	add("inside, fixed later", at(12), "ended", ptr(at(12)), ptr(at(30)), ptr(at(25)), "fixed")
	add("after", at(21), "approved", ptr(at(21)), ptr(at(30)), nil, "")
	add("pending inside", at(14), "pending", nil, nil, nil, "")
	add("declined before", at(2), "declined", ptr(at(3)), nil, nil, "")
	list, err := s.GatePolicyExceptions(ctx, at(10), at(20))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range list {
		got = append(got, e.TargetLabel)
		switch e.TargetLabel {
		case "before, expired inside":
			if e.EndReason != "expired" || e.EndedAt == nil || !e.EndedAt.Equal(at(15)) || e.ApprovedByName == nil || *e.ApprovedByName != "sec" {
				t.Errorf("expired inside: %+v", e)
			}
		case "inside, fixed later":
			if e.EndReason != "fixed" || e.TargetKind != "asset" || e.AssetID != f.web {
				t.Errorf("fixed: %+v", e)
			}
		case "pending inside":
			if e.ApprovedAt != nil || e.ApprovedByName != nil {
				t.Errorf("pending: %+v", e)
			}
		}
	}
	if strings.Join(got, "|") != "before, expired inside|inside, fixed later|pending inside" {
		t.Errorf("exceptions in the window: %q", got)
	}
}
