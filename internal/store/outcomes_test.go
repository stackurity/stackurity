package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

var fixDays = map[string]int{"P1": 3, "P2": 14, "P3": 45, "P4": 90}

type outcomeFixture struct {
	s      *store.Store
	ctx    context.Context
	asset  int64
	before time.Time // before any finding was resolved
}

func ingestHost(t *testing.T, s *store.Store, ctx context.Context, name string, purls ...string) int64 {
	t.Helper()
	b := model.NewBatch(model.Collector{ID: "test", Version: "1", Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: name, Identifiers: []model.Identifier{{Scheme: "machine-id", Value: name}}})
	for _, p := range purls {
		b.Observations = append(b.Observations, model.Observation{Purl: p, Confidence: model.ConfidenceConfirmed})
	}
	b.Complete = true
	if err := b.Validate(); err != nil { // fills versions from the purls
		t.Fatal(err)
	}
	r, err := s.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	return r.AssetID
}

// sync makes the open findings on the asset's current inventory exactly want
// (key -> purl name), as the matcher would.
func syncOpen(t *testing.T, s *store.Store, ctx context.Context, asset int64, want map[string]string) {
	t.Helper()
	rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: asset})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	var in []store.FindingInput
	for _, r := range rows {
		if r.RemovedAt != nil {
			continue // the matcher evaluates current inventory only
		}
		ids = append(ids, r.ID)
		for key, name := range want {
			if r.Name == name {
				in = append(in, store.FindingInput{Kind: "vulnerability", Key: key, InventoryID: r.ID, AssetID: asset, ComponentID: r.ComponentID,
					Verification: "confirmed", Severity: "high", FixedVersion: "9.9.9", Sources: []string{"GHSA-" + key}, Evidence: map[string]any{}})
			}
		}
	}
	if _, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, ids, in); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveRemovedFindings(ctx); err != nil {
		t.Fatal(err)
	}
}

func setFinding(t *testing.T, s *store.Store, ctx context.Context, key, priority string, age time.Duration) {
	t.Helper()
	if _, err := s.Pool.Exec(ctx, `UPDATE findings SET priority = $2, first_seen = now() - make_interval(secs => $3) WHERE key = $1`,
		key, priority, age.Seconds()); err != nil {
		t.Fatal(err)
	}
}

// newOutcomeFixture: CVE-1 closes because its advisory changed, is
// reopened and is then fixed by an upgrade; CVE-2 is fixed by the same
// upgrade, CVE-3 by removal; CVE-5 closes because its advisory changed
// (not remediation); CVE-4 stays open.
func newOutcomeFixture(t *testing.T) *outcomeFixture {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	f := &outcomeFixture{s: s, ctx: ctx}
	f.asset = ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15", "pkg:deb/debian/openssl@3.0.2-1?distro=debian-12", "pkg:npm/express@4.0.0")
	all := map[string]string{"CVE-1": "lodash", "CVE-2": "lodash", "CVE-3": "openssl", "CVE-4": "express", "CVE-5": "express"}
	syncOpen(t, s, ctx, f.asset, all)
	setFinding(t, s, ctx, "CVE-1", "P2", 10*24*time.Hour)
	setFinding(t, s, ctx, "CVE-3", "P1", 100*24*time.Hour)
	setFinding(t, s, ctx, "CVE-4", "P1", 20*24*time.Hour)
	setFinding(t, s, ctx, "CVE-5", "P1", 30*24*time.Hour)
	f.before = time.Now().Add(-time.Second)
	syncOpen(t, s, ctx, f.asset, map[string]string{"CVE-2": "lodash", "CVE-3": "openssl", "CVE-4": "express"})                    // CVE-1, CVE-5 close
	syncOpen(t, s, ctx, f.asset, map[string]string{"CVE-1": "lodash", "CVE-2": "lodash", "CVE-3": "openssl", "CVE-4": "express"}) // CVE-1 reopened
	// A newer complete inventory: lodash upgraded, openssl gone.
	ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.21", "pkg:npm/express@4.0.0")
	syncOpen(t, s, ctx, f.asset, map[string]string{"CVE-4": "express"})
	return f
}

func TestOutcomesReport(t *testing.T) {
	f := newOutcomeFixture(t)
	s, ctx := f.s, f.ctx
	now := time.Now()
	r, err := s.OutcomesReport(ctx, now.AddDate(0, 0, -30), now.Add(time.Minute), fixDays)
	if err != nil {
		t.Fatal(err)
	}
	// CVE-5 closed with nothing changed on the asset: not remediation.
	if r.Resolved != 3 || r.Remediated != 2 || r.Removed != 1 || r.NotRemediation.Total != 1 ||
		r.NotRemediation.ByKind["advisory_changed"] != 1 {
		t.Errorf("resolved = %d (remediated %d, removed %d), not remediation %+v; want 3 (2, 1), 1 advisory_changed",
			r.Resolved, r.Remediated, r.Removed, r.NotRemediation)
	}
	causes := map[string]int64{}
	for _, c := range r.Causes {
		causes[c.Cause] = c.Count
		if (c.Cause == "advisory_changed") != (c.Evidence == "intelligence") || c.Remediation == (c.Cause == "advisory_changed") {
			t.Errorf("cause %+v", c)
		}
	}
	if causes["advisory_changed"] != 1 || causes["upgraded"] != 2 || causes["removed"] != 1 {
		t.Errorf("causes = %+v", r.Causes)
	}
	if r.Reopened.Events != 1 || r.Reopened.Findings != 1 || r.Reopened.ResolutionEvents != 5 || r.Reopened.LaterReopened != 1 ||
		r.Reopened.Rate == nil || *r.Reopened.Rate != 0.2 || len(r.Reopened.Recent) != 1 || r.Reopened.Recent[0].Key != "CVE-1" ||
		r.Reopened.Recent[0].PreviousResolution == "" {
		t.Errorf("reopened = %+v", r.Reopened)
	}
	if r.EventsSince == nil {
		t.Error("events_since is not set")
	}
	timing := map[string]store.OutcomeTiming{}
	for _, x := range r.TimeToRemedy {
		timing[x.Priority+"/"+x.Kind] = x
	}
	// CVE-1's last open episode started when it was reopened, not 10 days ago.
	if p2 := timing["P2/all"]; p2.Resolved != 1 || p2.MeanDays == nil || *p2.MeanDays > 0.01 {
		t.Errorf("P2 timing = %+v", p2)
	}
	if p1 := timing["P1/vulnerability"]; p1.Resolved != 1 || p1.MedianDays == nil || *p1.MedianDays < 99.9 || *p1.MedianDays > 100.1 {
		t.Errorf("P1 timing = %+v", p1)
	}
	if all := timing["all/all"]; all.Resolved != 3 {
		t.Errorf("total timing = %+v", all)
	}
	sla := map[string]store.OutcomeSLA{}
	for _, x := range r.SLA {
		sla[x.Priority] = x
	}
	// CVE-5 (P1) is not in the SLA: only CVE-3 was remediated.
	if p := sla["P1"]; p.FixDays != 3 || p.Resolved != 1 || p.ResolvedInSLA != 0 || p.Rate == nil || *p.Rate != 0 ||
		p.OpenActive != 1 || p.OpenOverdue != 1 {
		t.Errorf("P1 SLA = %+v", p)
	}
	if p := sla["P2"]; p.Resolved != 1 || p.ResolvedInSLA != 1 {
		t.Errorf("P2 SLA = %+v", p)
	}
	if p := sla["P3"]; p.Resolved != 0 || p.Rate != nil {
		t.Errorf("P3 SLA must have no rate without resolutions: %+v", p)
	}
	if r.Open.Active != 1 || r.Open.Overdue != 1 {
		t.Errorf("open = %+v", r.Open)
	}
	var byEvidence int64
	for _, n := range r.Open.ByEvidence {
		byEvidence += n
	}
	if byEvidence != r.Open.Active+r.Open.Excepted || r.Open.ByEvidence["confirmed"] == 0 {
		t.Errorf("open by evidence state = %v, open = %+v", r.Open.ByEvidence, r.Open)
	}
	if r.Remediation != nil {
		t.Errorf("remediation without plans = %+v", r.Remediation)
	}

	// Remediation outcomes, as the paid edition records them.
	var comp, plan int64
	if err := s.Pool.QueryRow(ctx, `SELECT component_id FROM inventory WHERE asset_id = $1 LIMIT 1`, f.asset).Scan(&comp); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool.QueryRow(ctx, `INSERT INTO remediation_plans (policy_name, target, component_id, package, target_version, change_type, status)
		VALUES ('p', 'host_package', $1, 'lodash', '4.17.21', 'patch', 'partially_failed') RETURNING id`, comp).Scan(&plan); err != nil {
		t.Fatal(err)
	}
	for i, st := range []string{"verified", "failed", "rolled_back"} {
		if _, err := s.Pool.Exec(ctx, `INSERT INTO remediation_actions (plan_id, asset_id, kind, package, from_version, to_version, status, error)
			VALUES ($1, $2, 'package_upgrade', $3, '1', '2', $4, CASE WHEN $4 = 'verified' THEN '' ELSE 'apt failed' END)`,
			plan, f.asset, "pkg"+string(rune('a'+i)), st); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO remediation_actions (plan_id, asset_id, kind, package, from_version, to_version, status)
		VALUES ($1, $2, 'package_rollback', 'pkgc', '2', '1', 'verified')`, plan, f.asset); err != nil {
		t.Fatal(err)
	}
	r, err = s.OutcomesReport(ctx, now.AddDate(0, 0, -30), now.Add(time.Minute), fixDays)
	if err != nil {
		t.Fatal(err)
	}
	m := r.Remediation
	if m == nil || m.Plans["partially_failed"] != 1 || m.Verified != 1 || m.Failed != 1 || m.RolledBack != 1 || m.Finished != 3 ||
		m.SuccessRate == nil || *m.SuccessRate < 0.33 || *m.SuccessRate > 0.34 || m.Rollbacks["verified"] != 1 || len(m.Failures) != 2 {
		t.Errorf("remediation = %+v", m)
	}

	// A window before anything happened is empty, not zero-filled rates.
	r, err = s.OutcomesReport(ctx, now.AddDate(0, 0, -60), now.AddDate(0, 0, -30), fixDays)
	if err != nil {
		t.Fatal(err)
	}
	if r.Resolved != 0 || len(r.Causes) != 0 || r.Reopened.Rate != nil || r.Remediation != nil {
		t.Errorf("empty window = %+v", r)
	}
}

func TestVerifySince(t *testing.T) {
	f := newOutcomeFixture(t)
	r, err := f.s.VerifySince(f.ctx, f.before, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Resolved.Total != 4 || r.StillOpen.Total != 1 || r.StillOpen.Items[0].Key != "CVE-4" || !r.StillOpen.Items[0].Rescanned {
		t.Fatalf("verify = %+v", r)
	}
	if r.Remediated != 3 || r.ClosedNotRemediation != 1 || r.ResolvedByKind["remediated"] != 2 || r.ResolvedByKind["advisory_changed"] != 1 {
		t.Errorf("remediated %d, not remediation %d, by kind %v", r.Remediated, r.ClosedNotRemediation, r.ResolvedByKind)
	}
	causes := map[string]string{}
	for _, x := range r.Resolved.Items {
		causes[x.Key] = x.Cause
		if x.Remediation != (x.Key != "CVE-5") {
			t.Errorf("%s counts as remediation = %v (%s)", x.Key, x.Remediation, x.ResolutionKind)
		}
	}
	if causes["CVE-1"] != "upgraded" || causes["CVE-2"] != "upgraded" || causes["CVE-3"] != "removed" || causes["CVE-5"] != "advisory_changed" {
		t.Errorf("causes = %v", causes)
	}
	if len(r.Assets) != 1 || r.Assets[0].LastComplete == nil || !r.Assets[0].Rescanned {
		t.Errorf("assets = %+v", r.Assets)
	}
	// Asked from now: nothing resolved since, the open finding not rescanned.
	r, err = f.s.VerifySince(f.ctx, time.Now(), f.asset, 1)
	if err != nil {
		t.Fatal(err)
	}
	if r.Resolved.Total != 0 || r.StillOpen.Total != 1 || r.StillOpen.Items[0].Rescanned || len(r.Assets) != 1 || r.Assets[0].Rescanned {
		t.Errorf("verify from now = %+v", r)
	}
}

// TestOutcomesAreWorkspaceScoped: another workspace sees none of it.
func TestOutcomesAreWorkspaceScoped(t *testing.T) {
	f := newOutcomeFixture(t)
	ws, _, err := f.s.CreateWorkspace(context.Background(), "Beta", "", "beta@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	beta := tenant.WithWorkspace(context.Background(), ws.ID)
	now := time.Now()
	r, err := f.s.OutcomesReport(beta, now.AddDate(0, 0, -30), now.Add(time.Minute), fixDays)
	if err != nil {
		t.Fatal(err)
	}
	if r.Resolved != 0 || r.Reopened.Events != 0 || r.Reopened.ResolutionEvents != 0 || r.Open.Active != 0 || len(r.Causes) != 0 ||
		len(r.Open.ByEvidence) != 0 {
		t.Errorf("beta sees alpha's outcomes: %+v", r)
	}
	v, err := f.s.VerifySince(beta, f.before, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v.Resolved.Total != 0 || v.StillOpen.Total != 0 || len(v.Assets) != 0 {
		t.Errorf("beta sees alpha's findings: %+v", v)
	}
	if v, err := f.s.VerifySince(beta, f.before, f.asset, 0); err != nil || len(v.Assets) != 0 {
		t.Errorf("beta sees alpha's asset by id: %+v %v", v, err)
	}
}
