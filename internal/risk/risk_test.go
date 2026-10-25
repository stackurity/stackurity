package risk

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func f32(v float32) *float32 { return &v }
func b(v bool) *bool         { return &v }

func TestPriorities(t *testing.T) {
	p := DefaultPolicy()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		in   Input
		pri  string
		sos  bool
	}{
		{"KEV in exposed production", Input{Kind: "vulnerability", Severity: "high", Score: f32(7.5), KnownExploited: true,
			InternetExposed: b(true), Environment: "production", Criticality: "high", FixAvailable: true, Verification: "confirmed"}, "P1", true},
		{"critical but internal staging", Input{Kind: "vulnerability", Severity: "critical", Score: f32(9.8),
			InternetExposed: b(false), Environment: "staging", Verification: "confirmed"}, "P2", false},
		{"critical exposure unknown in prod", Input{Kind: "vulnerability", Severity: "critical", Score: f32(9.1),
			Environment: "prod", Verification: "confirmed"}, "P2", true},
		{"medium dev dependency", Input{Kind: "vulnerability", Severity: "medium", InternetExposed: b(false), Scope: "dev",
			Verification: "confirmed"}, "P4", false},
		{"unverified critical is never SOS", Input{Kind: "vulnerability", Severity: "unknown", KnownExploited: true,
			Environment: "production", Verification: "needs_validation"}, "P3", false},
		{"EOL in production", Input{Kind: "end_of_life", Severity: "medium", InternetExposed: b(true), Environment: "production",
			Verification: "confirmed"}, "P2", false},
		{"high on exposed critical prod app is P2, not SOS", Input{Kind: "vulnerability", Severity: "high", Score: f32(7.5),
			InternetExposed: b(true), Environment: "production", Criticality: "high", FixAvailable: true, Verification: "confirmed"}, "P2", false},
		{"critical on exposed prod is P1 SOS", Input{Kind: "vulnerability", Severity: "critical", Score: f32(9.8),
			InternetExposed: b(true), Environment: "production", Criticality: "high", FixAvailable: true, Verification: "confirmed"}, "P1", true},
		{"KEV on a kernel that is not running is cleanup, not SOS", Input{Kind: "vulnerability", Severity: "high", Score: f32(7.8), KnownExploited: true,
			InternetExposed: b(true), Environment: "production", Criticality: "high", FixAvailable: true, Verification: "confirmed", KernelNotRunning: true}, "P4", false},
		{"EOL internal staging", Input{Kind: "end_of_life", Severity: "medium", InternetExposed: b(false), Environment: "staging",
			Verification: "confirmed"}, "P3", false},
	}
	for _, c := range cases {
		r := p.Evaluate(c.in)
		if r.Priority != c.pri || r.SOS != c.sos {
			t.Errorf("%s: got %s sos=%v score=%.1f factors=%+v", c.name, r.Priority, r.SOS, r.Score, r.Factors)
		}
		sum := 0.0
		for _, f := range r.Factors {
			sum += f.Points
		}
		if diff := sum - r.Score; diff > 0.11 || diff < -0.11 {
			t.Errorf("%s: factors sum to %.2f but score is %.1f", c.name, sum, r.Score)
		}
	}
}

func TestValidateRejectsSeverityOnlySOS(t *testing.T) {
	p := DefaultPolicy()
	p.SOS = append(p.SOS, SOSRule{Name: "all criticals", MinSeverity: "critical"})
	if p.Validate() == nil {
		t.Error("severity-only SOS rule must be rejected (PRD §9)")
	}
	p = DefaultPolicy()
	p.Thresholds.P2 = 20
	if p.Validate() == nil {
		t.Error("bad thresholds accepted")
	}
}

func TestPolicyJSONRoundTrip(t *testing.T) {
	p := DefaultPolicy()
	b, _ := json.Marshal(p)
	var q Policy
	if err := json.Unmarshal(b, &q); err != nil || q.Validate() != nil || len(q.SOS) != 2 {
		t.Fatalf("round trip: %v %+v", err, q)
	}
}

func TestDeadlines(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ack, fix := DefaultPolicy().Deadlines("P1", start)
	if !ack.Equal(start.Add(4*time.Hour)) || !fix.Equal(start.AddDate(0, 0, 3)) {
		t.Errorf("deadlines %v %v", ack, fix)
	}
}

func TestPolicyVersion(t *testing.T) {
	a, b := DefaultPolicy(), DefaultPolicy()
	if a.Version() != b.Version() || !strings.HasPrefix(a.Version(), "sha256:") {
		t.Fatalf("versions differ for the same policy: %s %s", a.Version(), b.Version())
	}
	b.SLA["P1"] = SLA{AckHours: 4, FixDays: 2}
	if a.Version() == b.Version() {
		t.Error("a changed SLA kept the same version")
	}
}

// A missing environment must not score like a known non-production one, and
// SOS rules that require production treat it as possibly production, the way
// unknown exposure is treated as possibly exposed.
func TestUnknownEnvironmentIsNotSilentlyLower(t *testing.T) {
	p := DefaultPolicy()
	base := Input{Kind: "vulnerability", Severity: "high", Score: f32(8.1), KnownExploited: true, InternetExposed: b(true), Verification: "confirmed"}
	staging, none, prod := base, base, base
	staging.Environment, prod.Environment = "staging", "production"
	rs, rn, rp := p.Evaluate(staging), p.Evaluate(none), p.Evaluate(prod)
	if !(rs.Score < rn.Score && rn.Score <= rp.Score) {
		t.Errorf("scores staging %.1f, none %.1f, production %.1f", rs.Score, rn.Score, rp.Score)
	}
	if rs.SOS || !rn.SOS || !rp.SOS {
		t.Errorf("SOS staging %v, none %v, production %v", rs.SOS, rn.SOS, rp.SOS)
	}
	if !hasFactor(rn, "Environment unknown") || hasFactor(rs, "Environment unknown") || hasFactor(rp, "Environment unknown") {
		t.Errorf("factors: none %+v staging %+v production %+v", rn.Factors, rs.Factors, rp.Factors)
	}
}

func TestEmptyCriticalityIsUnknown(t *testing.T) {
	p := DefaultPolicy()
	p.CriticalityBonus["unknown"] = 0.5
	in := Input{Kind: "vulnerability", Severity: "medium", Environment: "dev", InternetExposed: b(false), Verification: "confirmed"}
	a := p.Evaluate(in)
	in.Criticality = "unknown"
	if c := p.Evaluate(in); a.Score != c.Score {
		t.Errorf("empty criticality %.1f, unknown %.1f", a.Score, c.Score)
	}
}

// Low confidence scales a positive score down; it must never raise a score
// that other factors already took below zero.
func TestConfidenceNeverRaisesScore(t *testing.T) {
	p := DefaultPolicy()
	in := Input{Kind: "vulnerability", Severity: "low", Environment: "dev", Criticality: "low", Scope: "dev", InternetExposed: b(false),
		KernelNotRunning: true, Verification: "confirmed"}
	conf := p.Evaluate(in)
	in.Verification = "needs_validation"
	nv := p.Evaluate(in)
	if nv.Score > conf.Score || hasFactor(nv, "Evidence confidence") {
		t.Errorf("confirmed %.1f, needs_validation %.1f %+v", conf.Score, nv.Score, nv.Factors)
	}
}

func TestValidateRejectsInvertedWeights(t *testing.T) {
	for name, mut := range map[string]func(*Policy){
		"negative KEV":                  func(p *Policy) { p.KnownExploited = -1 },
		"negative exposure":             func(p *Policy) { p.InternetExposed = -1 },
		"unknown exposure over exposed": func(p *Policy) { p.ExposureUnknown = 2 },
		"unknown env over production":   func(p *Policy) { p.EnvironmentUnknown = 2 },
		"negative overdue":              func(p *Policy) { p.Overdue = -1 },
		"positive dev dependency":       func(p *Policy) { p.DevDependency = 1 },
		"positive kernel not running":   func(p *Policy) { p.KernelNotRunning = 1 },
		"high above critical":           func(p *Policy) { p.SeverityBase["high"] = 10 },
		"low criticality above high":    func(p *Policy) { p.CriticalityBonus["low"] = 2 },
	} {
		p := DefaultPolicy()
		mut(&p)
		if p.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func hasFactor(r Result, name string) bool {
	for _, f := range r.Factors {
		if f.Name == name {
			return true
		}
	}
	return false
}
