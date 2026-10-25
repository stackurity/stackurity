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
