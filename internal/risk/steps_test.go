package risk

import "testing"

// A plan step runs after the thresholds and before SOS, and is part of the
// policy version; without steps nothing changes.
func TestPolicySteps(t *testing.T) {
	in := Input{Kind: "vulnerability", Severity: "critical", Score: f32(9.8), InternetExposed: b(true),
		Environment: "production", Criticality: "high", FixAvailable: true, Verification: "confirmed",
		Reachability: "not_imported", ReachabilityEvidence: []string{"no import"}}
	p := DefaultPolicy()
	// A rule that depends on the priority shows whether SOS runs after the
	// step. (The default rules do not: lowering a priority never ends SOS.)
	p.SOS = []SOSRule{{Name: "P1 in production", MinPriority: "P1", Production: ptr(true)}}
	base := p.Evaluate(in)
	if base.Priority != "P1" || !base.SOS {
		t.Fatalf("base = %s sos=%v, want P1 SOS", base.Priority, base.SOS)
	}
	// Community: reachability alone changes nothing.
	if r := p.Evaluate(in); r.Priority != base.Priority || len(r.Factors) != len(base.Factors) {
		t.Fatalf("reachability without a step changed the result: %+v", r)
	}
	v := p.Version()
	var saw string
	p.Steps = []Step{{Name: StepReachability, Apply: func(in Input, r *Result) {
		saw = r.Priority
		r.Priority = "P2"
		r.Factors = append(r.Factors, Factor{Name: FactorNotReached, Detail: in.ReachabilityEvidence[0]})
	}}}
	r := p.Evaluate(in)
	if saw != "P1" {
		t.Errorf("step saw priority %q, want the thresholds' P1", saw)
	}
	if r.Priority != "P2" || r.Factors[len(r.Factors)-1].Name != FactorNotReached {
		t.Errorf("step result = %+v", r)
	}
	// SOS rules see the adjusted priority.
	if r.SOS {
		t.Error("SOS evaluated before the step")
	}
	if p.Version() == v {
		t.Error("a step does not change the policy version")
	}
}
