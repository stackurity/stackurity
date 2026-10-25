package store_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// riskFixture is one host with four findings whose evidence differs the way
// the matcher records it.
func riskFixture(t *testing.T) (context.Context, *store.Store, int64) {
	t.Helper()
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	host := ingestHost(t, s, ctx, "web-1", "pkg:deb/ubuntu/openssl@3.0.2?distro=ubuntu-22.04",
		"pkg:deb/ubuntu/linux-image-5.15.0-91-generic@5.15.0-91.101?distro=ubuntu-22.04", "pkg:deb/ubuntu/curl@7.81.0?distro=ubuntu-22.04")
	rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: host})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	var in []store.FindingInput
	for _, r := range rows {
		ids = append(ids, r.ID)
		add := func(key, fixed string, ev map[string]any) {
			in = append(in, store.FindingInput{Kind: "vulnerability", Key: key, InventoryID: r.ID, AssetID: host, ComponentID: r.ComponentID,
				Verification: "confirmed", Severity: "high", FixedVersion: fixed, Title: key, Sources: []string{"USN-" + key}, Evidence: ev})
		}
		switch {
		case strings.HasPrefix(r.Name, "openssl"):
			add("CVE-KEV", "3.0.2-0ubuntu1.12", map[string]any{"known_exploited": true})
			add("CVE-PRO", "3.0.2-0ubuntu1.13+esm1", map[string]any{"requires_ubuntu_pro": true})
		case strings.HasPrefix(r.Name, "linux-image"):
			add("CVE-KERNEL", "5.15.0-92.102", map[string]any{"known_exploited": true, "not_running_kernel": true})
		case strings.HasPrefix(r.Name, "curl"):
			add("CVE-NOFIX", "", map[string]any{})
		}
	}
	if len(in) != 4 {
		t.Fatalf("fixture built %d findings from %d inventory rows", len(in), len(rows))
	}
	if _, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, ids, in); err != nil {
		t.Fatal(err)
	}
	return ctx, s, host
}

type stored struct {
	Priority string
	Score    float32
	Factors  string
	SOS      bool
	SOSRule  string
	Policy   string
}

func snapshot(t *testing.T, ctx context.Context, s *store.Store) map[string]stored {
	t.Helper()
	fs, _, err := s.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]stored{}
	for _, f := range fs {
		out[f.Key] = stored{f.Priority, f.PriorityScore, string(f.PriorityFactors), f.SOS, f.SOSRule, f.PriorityPolicy}
	}
	return out
}

func factorNames(t *testing.T, raw string) []string {
	t.Helper()
	var fs []risk.Factor
	if err := json.Unmarshal([]byte(raw), &fs); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range fs {
		names = append(names, f.Name)
	}
	return names
}

// The store assembles the risk inputs from the asset and the finding's
// evidence: KEV, an Ubuntu Pro-only fix (not "fix available"), an idle
// kernel, a missing environment and an operator's exposure.
func TestPrioritizeAssemblesEvidence(t *testing.T) {
	ctx, s, host := riskFixture(t)
	if _, err := s.Prioritize(ctx, risk.DefaultPolicy(), time.Now()); err != nil {
		t.Fatal(err)
	}
	got := snapshot(t, ctx, s)
	want := map[string]string{
		"CVE-KEV":    "Severity,Known exploited,Exposure unknown,Environment unknown,Fix available",
		"CVE-PRO":    "Severity,Exposure unknown,Environment unknown",
		"CVE-KERNEL": "Severity,Known exploited,Exposure unknown,Environment unknown,Fix available,Kernel not running",
		"CVE-NOFIX":  "Severity,Exposure unknown,Environment unknown",
	}
	for k, w := range want {
		if n := strings.Join(factorNames(t, got[k].Factors), ","); n != w {
			t.Errorf("%s factors = %s, want %s", k, n, w)
		}
	}
	// KEV with no environment recorded is SOS (it may be production); the
	// same KEV on a kernel that is not running is not.
	if !got["CVE-KEV"].SOS || got["CVE-KERNEL"].SOS {
		t.Errorf("SOS: KEV %v, idle kernel %v", got["CVE-KEV"].SOS, got["CVE-KERNEL"].SOS)
	}

	prod, crit, yes := "production", "critical", true
	if err := s.UpdateAsset(ctx, host, store.AssetUpdate{Environment: &prod, Criticality: &crit,
		InternetExposed: store.Nullable[bool]{Set: true, Value: &yes}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prioritize(ctx, risk.DefaultPolicy(), time.Now()); err != nil {
		t.Fatal(err)
	}
	got = snapshot(t, ctx, s)
	if n := strings.Join(factorNames(t, got["CVE-KEV"].Factors), ","); n != "Severity,Known exploited,Internet exposed,Production,Asset criticality,Fix available" {
		t.Errorf("CVE-KEV factors on exposed production = %s", n)
	}
	if !strings.Contains(got["CVE-KEV"].Factors, "marked internet exposed on the asset") {
		t.Errorf("exposure evidence not named: %s", got["CVE-KEV"].Factors)
	}
	if got["CVE-KEV"].Priority != "P1" || got["CVE-KEV"].SOSRule != "Known exploited in production" {
		t.Errorf("CVE-KEV = %+v", got["CVE-KEV"])
	}
}

// Prioritising again with the same policy and evidence changes nothing, each
// finding records the policy version that produced it, and going back to an
// earlier policy reproduces the earlier result exactly.
func TestPrioritizeIsReproducible(t *testing.T) {
	ctx, s, _ := riskFixture(t)
	now := time.Now()
	def := risk.DefaultPolicy()
	if _, err := s.Prioritize(ctx, def, now); err != nil {
		t.Fatal(err)
	}
	first := snapshot(t, ctx, s)
	for k, f := range first {
		if f.Policy != def.Version() {
			t.Errorf("%s recorded policy %q, want %q", k, f.Policy, def.Version())
		}
	}
	if _, err := s.Prioritize(ctx, def, now); err != nil {
		t.Fatal(err)
	}
	if again := snapshot(t, ctx, s); !reflect.DeepEqual(first, again) {
		t.Errorf("same policy and inputs gave different results:\n%+v\n%+v", first, again)
	}

	changed := risk.DefaultPolicy()
	changed.KnownExploited = 5
	if _, err := s.Prioritize(ctx, changed, now); err != nil {
		t.Fatal(err)
	}
	mid := snapshot(t, ctx, s)
	if mid["CVE-KEV"].Policy != changed.Version() || mid["CVE-KEV"].Score <= first["CVE-KEV"].Score {
		t.Errorf("after a KEV weight change: %+v (was %+v)", mid["CVE-KEV"], first["CVE-KEV"])
	}

	// The policy rebuilt from its JSON (as stored and audited) has the same
	// version and gives the same result.
	raw, _ := json.Marshal(def)
	var rebuilt risk.Policy
	if err := json.Unmarshal(raw, &rebuilt); err != nil || rebuilt.Version() != def.Version() {
		t.Fatalf("rebuilt policy version %s, want %s (%v)", rebuilt.Version(), def.Version(), err)
	}
	if _, err := s.Prioritize(ctx, rebuilt, now); err != nil {
		t.Fatal(err)
	}
	if back := snapshot(t, ctx, s); !reflect.DeepEqual(first, back) {
		t.Errorf("returning to the first policy did not reproduce its results:\n%+v\n%+v", first, back)
	}
}

// Every policy change made through ReplaceRiskPolicy is in the audit log with
// the policy before and after, both versions and the fields that changed, and
// either policy can be rebuilt from the event.
func TestReplaceRiskPolicyIsAudited(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	actor := store.Actor{Type: "user", Name: "admin@x.io", RemoteAddr: "192.0.2.1"}

	p := risk.DefaultPolicy()
	p.KnownExploited = 4
	p.ExceptionMaxDays = 0 // stands for the default and is stored as it
	ch, err := s.ReplaceRiskPolicy(ctx, p, actor)
	if err != nil {
		t.Fatal(err)
	}
	if ch.BeforeVersion != risk.DefaultPolicy().Version() || strings.Join(ch.Changed, ",") != "known_exploited" {
		t.Errorf("first change = %s -> %s %v", ch.BeforeVersion, ch.AfterVersion, ch.Changed)
	}
	cur, err := s.RiskPolicy(ctx)
	if err != nil || cur.Version() != ch.AfterVersion {
		t.Fatalf("stored policy version %s, audited %s (%v)", cur.Version(), ch.AfterVersion, err)
	}

	q := cur
	q.Thresholds.P1 = 13
	q.SLA = map[string]risk.SLA{"P1": {AckHours: 2, FixDays: 2}, "P2": cur.SLA["P2"], "P3": cur.SLA["P3"], "P4": cur.SLA["P4"]}
	if _, err := s.ReplaceRiskPolicy(ctx, q, actor); err != nil {
		t.Fatal(err)
	}
	bad := q
	bad.KnownExploited = -1
	if _, err := s.ReplaceRiskPolicy(ctx, bad, actor); err == nil {
		t.Error("invalid policy stored")
	}

	evs, total, err := s.ListAudit(ctx, "settings", "risk_policy", store.Page{Limit: 10})
	if err != nil || total != 2 {
		t.Fatalf("audit events = %d (%v)", total, err)
	}
	var last store.RiskPolicyChange
	if err := json.Unmarshal(evs[0].Detail, &last); err != nil {
		t.Fatal(err)
	}
	if evs[0].Action != "risk_policy.update" || evs[0].ActorName != "admin@x.io" || evs[0].RemoteAddr != "192.0.2.1" {
		t.Errorf("event = %+v", evs[0])
	}
	if strings.Join(last.Changed, ",") != "sla,thresholds" || last.BeforeVersion != ch.AfterVersion {
		t.Errorf("second change = %s -> %s %v", last.BeforeVersion, last.AfterVersion, last.Changed)
	}
	if last.Before.Version() != last.BeforeVersion || last.After.Version() != last.AfterVersion {
		t.Errorf("policies rebuilt from the log have versions %s, %s; audited %s, %s",
			last.Before.Version(), last.After.Version(), last.BeforeVersion, last.AfterVersion)
	}
}
