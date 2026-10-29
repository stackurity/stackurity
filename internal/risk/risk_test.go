package risk

import (
	"encoding/json"
	"reflect"
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

// A saved SOS rule must be read back exactly as written. Decoding it over the
// default rules let it inherit conditions (production: true) it never had.
func TestDecodePolicyKeepsRulesAsWritten(t *testing.T) {
	p, err := DecodePolicy([]byte(`{"sos_rules": [{"name": "KEV anywhere", "known_exploited": true}]}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.SOS) != 1 || p.SOS[0].Production != nil || p.SOS[0].KnownExploited == nil || !*p.SOS[0].KnownExploited {
		t.Fatalf("rules = %+v", p.SOS)
	}
	r := p.Evaluate(Input{Kind: "vulnerability", Severity: "high", KnownExploited: true, Environment: "staging",
		InternetExposed: b(false), Verification: "confirmed"})
	if !r.SOS || r.SOSRule != "KEV anywhere" {
		t.Errorf("KEV on staging under a KEV-anywhere rule: sos=%v %q", r.SOS, r.SOSRule)
	}
	// Omitted fields and an omitted sos_rules keep their defaults.
	p, err = DecodePolicy([]byte(`{"known_exploited": 4}`), false)
	if err != nil || p.KnownExploited != 4 || p.Production != DefaultPolicy().Production || len(p.SOS) != 2 {
		t.Errorf("partial policy = %+v %v", p, err)
	}
	if _, err := DecodePolicy([]byte(`{"known_exploitd": 4}`), true); err == nil {
		t.Error("strict decoding accepted an unknown field")
	}
	// The JSON a policy is stored as decodes to the same version.
	def := DefaultPolicy()
	raw, _ := json.Marshal(def)
	if q, err := DecodePolicy(raw, true); err != nil || q.Version() != def.Version() {
		t.Errorf("round trip changed the version: %v", err)
	}
}

// EPSS adds its points from the threshold up, and a finding that crossed it
// keeps them until its EPSS falls below EPSSRelease × the threshold, so daily
// movement around the threshold does not change its priority. The factor's
// text names the threshold, not the day's score, so stored factors do not
// change with every daily score either.
func TestEPSSThresholdAndHysteresis(t *testing.T) {
	p := DefaultPolicy()
	in := Input{Kind: "vulnerability", Severity: "high", Score: f32(7.5), InternetExposed: b(false), Environment: "staging",
		Verification: "confirmed"}
	eval := func(score float32, counted bool) Result {
		x := in
		x.EPSS, x.EPSSCounted = f32(score), counted
		return p.Evaluate(x)
	}
	none := p.Evaluate(in)
	if hasFactor(none, FactorEPSS) {
		t.Fatal("EPSS factor without a score")
	}
	for _, c := range []struct {
		score   float32
		counted bool
		want    bool
	}{
		{0.05, false, false}, {0.0999, false, false}, {0.1, false, true}, {0.6, false, true},
		{0.0999, true, true}, {0.08, true, true}, {0.0799, true, false}, {0.01, true, false},
	} {
		r := eval(c.score, c.counted)
		if hasFactor(r, FactorEPSS) != c.want {
			t.Errorf("EPSS %.4f (counted before: %v): factor %v, want %v", c.score, c.counted, hasFactor(r, FactorEPSS), c.want)
		}
	}
	a, b2 := eval(0.11, false), eval(0.93, true)
	if !reflect.DeepEqual(a.Factors, b2.Factors) {
		t.Errorf("factors differ for two scores above the threshold:\n%+v\n%+v", a.Factors, b2.Factors)
	}
	if got := eval(0.2, false).Score - none.Score; got != p.EPSS {
		t.Errorf("EPSS added %.1f points, want %.1f", got, p.EPSS)
	}
	// A KEV entry already counts exploitation; EPSS adds nothing more.
	k := in
	k.KnownExploited, k.EPSS = true, f32(0.97)
	if r := p.Evaluate(k); hasFactor(r, FactorEPSS) || !hasFactor(r, "Known exploited") {
		t.Errorf("KEV with EPSS: %+v", r.Factors)
	}
	// Zero points turn the factor off.
	p.EPSS = 0
	if hasFactor(eval(0.9, false), FactorEPSS) {
		t.Error("EPSS factor with zero points")
	}
}

// A daily wobble across the threshold changes nothing once the finding has
// crossed it; only a real drop does.
func TestEPSSWobbleKeepsPriority(t *testing.T) {
	p := DefaultPolicy()
	in := Input{Kind: "vulnerability", Severity: "high", Score: f32(7.5), InternetExposed: b(false), Environment: "staging",
		Verification: "confirmed"}
	counted := false
	var priorities []string
	for _, s := range []float32{0.098, 0.101, 0.097, 0.102, 0.095, 0.099, 0.085, 0.07} {
		x := in
		x.EPSS, x.EPSSCounted = f32(s), counted
		r := p.Evaluate(x)
		counted = hasFactor(r, FactorEPSS)
		priorities = append(priorities, r.Priority)
	}
	if got := strings.Join(priorities, " "); got != "P3 P2 P2 P2 P2 P2 P2 P3" {
		t.Errorf("priorities over the days: %s", got)
	}
}

func TestEPSSPolicyRules(t *testing.T) {
	for name, mut := range map[string]func(*Policy){
		"negative EPSS":          func(p *Policy) { p.EPSS = -1 },
		"EPSS above KEV":         func(p *Policy) { p.EPSS = p.KnownExploited + 1 },
		"zero threshold":         func(p *Policy) { p.EPSSThreshold = 0 },
		"threshold above one":    func(p *Policy) { p.EPSSThreshold = 1.5 },
		"threshold as a percent": func(p *Policy) { p.EPSSThreshold = 10 },
	} {
		p := DefaultPolicy()
		mut(&p)
		if p.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A policy saved before EPSS gets the default, capped by its own KEV weight.
	p, err := DecodePolicy([]byte(`{"known_exploited": 1}`), false)
	if err != nil || p.EPSS != 1 || p.EPSSThreshold != 0.1 || p.Validate() != nil {
		t.Errorf("old policy with KEV 1: epss %v threshold %v, %v %v", p.EPSS, p.EPSSThreshold, err, p.Validate())
	}
	p, err = DecodePolicy([]byte(`{"known_exploited": 1, "epss": 0.5, "epss_threshold": 0.3}`), true)
	if err != nil || p.EPSS != 0.5 || p.EPSSThreshold != 0.3 {
		t.Errorf("saved EPSS settings: %v %v %v", p.EPSS, p.EPSSThreshold, err)
	}
	for v, want := range map[float64]string{0.1: "10%", 0.08: "8%", 0.025: "2.5%", 0.123456: "12.3%", 0.00042: "0.042%", 1: "100%", 0: "0%", 0.99999: "99.99%"} {
		if got := Percent(v); got != want {
			t.Errorf("Percent(%v) = %q, want %q", v, got, want)
		}
	}
}
