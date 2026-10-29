package risk

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// This file is the risk-scoring validation suite (docs/risk.md). Scenarios
// pin what the default policy decides for representative findings, each with
// the reason a security engineer should agree; the property tests below check
// invariants over thousands of generated findings. When a scenario has to
// change, change the reason with it, and update docs/risk.md.

const (
	kevProd     = "Known exploited in production"
	critExposed = "Critical, exposed production asset"
)

type scenario struct {
	name string
	why  string // the rationale a reviewer should agree with
	in   Input
	pri  string
	sos  string // the SOS rule that fires, "" for none
	// factors is the complete explanation, in order, as "Name +points".
	factors []string
	// evidence: factor name -> text its detail must contain.
	evidence map[string]string
}

func cvss(v float32) *float32 { return &v }

var (
	exposed  = b(true)
	internal = b(false)
	unknown  *bool
)

// vuln is a confirmed runtime vulnerability; scenarios change what they test.
func vuln(sev string, score *float32) Input {
	return Input{Kind: "vulnerability", Severity: sev, Score: score, Verification: "confirmed", Criticality: "unknown"}
}

func with(in Input, f func(*Input)) Input { f(&in); return in }

func scenarios() []scenario {
	prodExposed := func(in *Input) {
		in.Environment, in.InternetExposed, in.ExposureSource = "production", exposed, ExposureOperator
	}
	devInternal := func(in *Input) {
		in.Environment, in.InternetExposed, in.ExposureSource, in.Criticality = "development", internal, ExposureOperator, "low"
	}
	return []scenario{
		// --- Known exploitation
		{name: "KEV critical on exposed critical production", why: "actively exploited, reachable, and the asset matters most: the top of the queue and a page",
			in: with(vuln("critical", cvss(9.8)), func(in *Input) {
				prodExposed(in)
				in.KnownExploited, in.Criticality, in.FixAvailable = true, "critical", true
			}),
			pri: "P1", sos: kevProd,
			factors: []string{"CVSS base score +9.8", "Known exploited +3", "Internet exposed +1.5", "Production +1", "Asset criticality +1.5", "Fix available +0.5"},
			evidence: map[string]string{"CVSS base score": "CVSS 9.8", "Known exploited": "CISA KEV", "Internet exposed": "marked internet exposed on the asset",
				"Production": "environment production", "Asset criticality": "criticality critical"}},
		{name: "same KEV critical on an internal dev box", why: "still P1 on score (KEV and CVSS 9.8 alone pass the P1 threshold) but 5 points lower and never SOS: dev is not treated like exposed production",
			in: with(vuln("critical", cvss(9.8)), func(in *Input) {
				devInternal(in)
				in.KnownExploited, in.FixAvailable = true, true
			}),
			pri: "P1", factors: []string{"CVSS base score +9.8", "Known exploited +3", "Asset criticality -1", "Fix available +0.5"}},
		{name: "KEV high on exposed production", why: "exploitation plus reachability in production makes a high-severity issue P1 and SOS",
			in: with(vuln("high", cvss(7.5)), func(in *Input) {
				prodExposed(in)
				in.KnownExploited, in.FixAvailable = true, true
			}),
			pri: "P1", sos: kevProd, factors: []string{"CVSS base score +7.5", "Known exploited +3", "Internet exposed +1.5", "Production +1", "Fix available +0.5"}},
		{name: "same KEV high on an internal dev box", why: "the same CVE where it cannot be reached and does not serve customers drops to P2",
			in: with(vuln("high", cvss(7.5)), func(in *Input) {
				devInternal(in)
				in.KnownExploited, in.FixAvailable = true, true
			}),
			pri: "P2", factors: []string{"CVSS base score +7.5", "Known exploited +3", "Asset criticality -1", "Fix available +0.5"}},
		{name: "KEV in internal production, no fix", why: "exploited in production is SOS even when not internet exposed (lateral movement)",
			in: with(vuln("high", cvss(7.5)), func(in *Input) {
				in.Environment, in.InternetExposed, in.KnownExploited = "production", internal, true
			}),
			pri: "P2", sos: kevProd, factors: []string{"CVSS base score +7.5", "Known exploited +3", "Production +1"}},
		{name: "ransomware-flagged KEV", why: "CISA's ransomware flag is not a separate input: such an entry scores exactly as any KEV entry (documented in docs/risk.md)",
			in: with(vuln("high", cvss(8.1)), func(in *Input) {
				prodExposed(in)
				in.KnownExploited = true
			}),
			pri: "P1", sos: kevProd, factors: []string{"CVSS base score +8.1", "Known exploited +3", "Internet exposed +1.5", "Production +1"}},
		{name: "KEV on an installed kernel that is not running", why: "nothing is exposed until it is booted: cleanup work, never SOS",
			in: with(vuln("high", cvss(7.8)), func(in *Input) {
				prodExposed(in)
				in.KnownExploited, in.Criticality, in.FixAvailable, in.KernelNotRunning = true, "high", true, true
			}),
			pri: "P4", factors: []string{"CVSS base score +7.8", "Known exploited +3", "Internet exposed +1.5", "Production +1", "Asset criticality +1", "Fix available +0.5", "Kernel not running -10"}},

		// --- Predicted exploitation (EPSS)
		{name: "medium with a likely exploit (EPSS 42%) on internal production", why: "a high predicted chance of exploitation lifts a medium production issue to P2, below KEV and never SOS on its own",
			in: with(vuln("medium", cvss(6.5)), func(in *Input) {
				in.Environment, in.InternetExposed, in.ExposureSource, in.EPSS = "production", internal, ExposureOperator, cvss(0.42)
			}),
			pri: "P2", factors: []string{"CVSS base score +6.5", "Exploit prediction (EPSS) +1.5", "Production +1"},
			evidence: map[string]string{"Exploit prediction (EPSS)": "EPSS of 10% or more"}},
		{name: "same medium, EPSS 3%", why: "an unlikely exploit adds nothing: P3 as without EPSS",
			in: with(vuln("medium", cvss(6.5)), func(in *Input) {
				in.Environment, in.InternetExposed, in.ExposureSource, in.EPSS = "production", internal, ExposureOperator, cvss(0.03)
			}),
			pri: "P3", factors: []string{"CVSS base score +6.5", "Production +1"}},
		{name: "same medium, EPSS fell to 9% after crossing 10%", why: "a finding that crossed the threshold keeps the factor down to 8%, so a daily dip does not move its priority",
			in: with(vuln("medium", cvss(6.5)), func(in *Input) {
				in.Environment, in.InternetExposed, in.ExposureSource, in.EPSS, in.EPSSCounted = "production", internal, ExposureOperator, cvss(0.09), true
			}),
			pri: "P2", factors: []string{"CVSS base score +6.5", "Exploit prediction (EPSS) +1.5", "Production +1"}},
		{name: "same medium, EPSS 9% never crossed", why: "below the threshold and not counted before: no points",
			in: with(vuln("medium", cvss(6.5)), func(in *Input) {
				in.Environment, in.InternetExposed, in.ExposureSource, in.EPSS = "production", internal, ExposureOperator, cvss(0.09)
			}),
			pri: "P3", factors: []string{"CVSS base score +6.5", "Production +1"}},
		{name: "KEV with EPSS 97%", why: "known exploitation is evidence; the prediction adds nothing on top of it",
			in: with(vuln("high", cvss(7.5)), func(in *Input) {
				prodExposed(in)
				in.KnownExploited, in.FixAvailable, in.EPSS = true, true, cvss(0.97)
			}),
			pri: "P1", sos: kevProd, factors: []string{"CVSS base score +7.5", "Known exploited +3", "Internet exposed +1.5", "Production +1", "Fix available +0.5"}},

		// --- Severity without exploitation
		{name: "critical on exposed production", why: "a critical, reachable production issue is P1 and SOS without KEV",
			in: with(vuln("critical", cvss(9.8)), func(in *Input) {
				prodExposed(in)
				in.Criticality, in.FixAvailable = "high", true
			}),
			pri: "P1", sos: critExposed, factors: []string{"CVSS base score +9.8", "Internet exposed +1.5", "Production +1", "Asset criticality +1", "Fix available +0.5"}},
		{name: "critical on exposed staging", why: "not production, so no SOS; still P2",
			in: with(vuln("critical", cvss(9.8)), func(in *Input) {
				in.Environment, in.InternetExposed = "staging", exposed
			}),
			pri: "P2", factors: []string{"CVSS base score +9.8", "Internet exposed +1.5"}},
		{name: "high on exposed production, no fix", why: "high severity needs exploitation or a critical score to reach P1",
			in:  with(vuln("high", cvss(8.8)), prodExposed),
			pri: "P2", factors: []string{"CVSS base score +8.8", "Internet exposed +1.5", "Production +1"}},
		{name: "high on exposed production, fix available", why: "an available fix makes it more actionable, a small bump within P2",
			in:  with(vuln("high", cvss(8.8)), func(in *Input) { prodExposed(in); in.FixAvailable = true }),
			pri: "P2", factors: []string{"CVSS base score +8.8", "Internet exposed +1.5", "Production +1", "Fix available +0.5"},
			evidence: map[string]string{"Fix available": "an upgrade resolves it"}},
		{name: "fix only with Ubuntu Pro", why: "a fix that needs a subscription is not counted as available; it scores like no fix",
			in:  with(vuln("high", cvss(8.8)), prodExposed), // the store passes FixAvailable=false when requires_ubuntu_pro
			pri: "P2", factors: []string{"CVSS base score +8.8", "Internet exposed +1.5", "Production +1"}},
		{name: "medium on internal production", why: "a moderate issue that is not reachable from outside: P3",
			in:  with(vuln("medium", cvss(5.3)), func(in *Input) { in.Environment, in.InternetExposed = "production", internal }),
			pri: "P3", factors: []string{"CVSS base score +5.3", "Production +1"}},
		{name: "low on exposed production", why: "low severity stays P4 even when exposed",
			in:  with(vuln("low", cvss(3.1)), prodExposed),
			pri: "P4", factors: []string{"CVSS base score +3.1", "Internet exposed +1.5", "Production +1"}},
		{name: "severity only, no CVSS score", why: "the policy's severity base stands in for a missing CVSS score, and the explanation says so",
			in:  with(vuln("critical", nil), prodExposed),
			pri: "P1", sos: critExposed, factors: []string{"Severity +9.5", "Internet exposed +1.5", "Production +1"},
			evidence: map[string]string{"Severity": "advisory severity critical, no CVSS score"}},

		// --- Missing evidence
		{name: "unknown severity (SUSE) on exposed production", why: "SUSE publishes no severity: scored as the policy's 'unknown' (medium), visibly; not SOS by severity",
			in:  with(vuln("unknown", nil), prodExposed),
			pri: "P3", factors: []string{"Severity +5", "Internet exposed +1.5", "Production +1"},
			evidence: map[string]string{"Severity": "scored as unknown"}},
		{name: "unknown severity (SUSE) with KEV in production", why: "exploitation does not depend on severity: KEV in production is SOS",
			in:  with(vuln("unknown", nil), func(in *Input) { prodExposed(in); in.KnownExploited = true }),
			pri: "P2", sos: kevProd, factors: []string{"Severity +5", "Known exploited +3", "Internet exposed +1.5", "Production +1"}},
		{name: "unrecognised severity label", why: "a label the policy does not know scores as unknown, never zero",
			in:  with(vuln("moderate", nil), prodExposed),
			pri: "P3", factors: []string{"Severity +5", "Internet exposed +1.5", "Production +1"},
			evidence: map[string]string{"Severity": "scored as unknown"}},
		{name: "Kubernetes exposure undecidable on production", why: "Services unreadable: scored above internal, and SOS treats it as exposed",
			in: with(vuln("critical", cvss(9.1)), func(in *Input) {
				in.Environment, in.InternetExposed, in.ExposureSource = "prod", unknown, ExposureCollector
			}),
			pri: "P2", sos: critExposed, factors: []string{"CVSS base score +9.1", "Exposure unknown +0.5", "Production +1"},
			evidence: map[string]string{"Exposure unknown": "could not decide exposure"}},
		{name: "same critical, known internal production", why: "known internal is below unknown exposure and is not SOS",
			in:  with(vuln("critical", cvss(9.1)), func(in *Input) { in.Environment, in.InternetExposed = "prod", internal }),
			pri: "P2", factors: []string{"CVSS base score +9.1", "Production +1"}},
		{name: "image exposed through a workload", why: "the explanation names the workload as the evidence",
			in: with(vuln("high", cvss(7.5)), func(in *Input) {
				in.Environment, in.InternetExposed, in.ExposureSource = "production", exposed, ExposureWorkloads
			}),
			pri: "P2", factors: []string{"CVSS base score +7.5", "Internet exposed +1.5", "Production +1"},
			evidence: map[string]string{"Internet exposed": "workload deployed as this image is reachable"}},
		{name: "workload exposed by its Service", why: "the explanation names the collector's observation as the evidence",
			in: with(vuln("high", cvss(7.5)), func(in *Input) {
				in.Environment, in.InternetExposed, in.ExposureSource = "production", exposed, ExposureCollector
			}),
			pri: "P2", factors: []string{"CVSS base score +7.5", "Internet exposed +1.5", "Production +1"},
			evidence: map[string]string{"Internet exposed": "collector reports it reachable"}},
		{name: "KEV with no environment and no exposure recorded", why: "missing labels never make it look safe: it may be production, so SOS",
			in:  with(vuln("high", cvss(7.5)), func(in *Input) { in.KnownExploited = true }),
			pri: "P2", sos: kevProd, factors: []string{"CVSS base score +7.5", "Known exploited +3", "Exposure unknown +0.5", "Environment unknown +0.5"},
			evidence: map[string]string{"Environment unknown": "may be production", "Exposure unknown": "not recorded"}},
		{name: "same KEV on labelled staging, internal", why: "a known non-production, internal asset scores below the unlabelled one and is not SOS",
			in:  with(vuln("high", cvss(7.5)), func(in *Input) { in.KnownExploited, in.Environment, in.InternetExposed = true, "staging", internal }),
			pri: "P2", factors: []string{"CVSS base score +7.5", "Known exploited +3"}},
		{name: "blank environment", why: "whitespace is no environment",
			in:  with(vuln("medium", cvss(6.5)), func(in *Input) { in.Environment, in.InternetExposed = "  ", internal }),
			pri: "P3", factors: []string{"CVSS base score +6.5", "Environment unknown +0.5"}},
		{name: "missing criticality", why: "no criticality is the policy's 'unknown' weight (0, as medium): never below a labelled medium asset",
			in:  with(vuln("high", cvss(7.5)), func(in *Input) { prodExposed(in); in.Criticality = "" }),
			pri: "P2", factors: []string{"CVSS base score +7.5", "Internet exposed +1.5", "Production +1"}},
		{name: "low-criticality asset", why: "an owner's 'low' lowers the score by one point",
			in:  with(vuln("high", cvss(7.5)), func(in *Input) { prodExposed(in); in.Criticality = "low" }),
			pri: "P2", factors: []string{"CVSS base score +7.5", "Internet exposed +1.5", "Production +1", "Asset criticality -1"}},
		{name: "production label in another case", why: "environment names match the policy case-insensitively, so PROD gets the production point",
			in:  with(vuln("high", cvss(7.5)), func(in *Input) { in.Environment, in.InternetExposed = "PROD", internal }),
			pri: "P2", factors: []string{"CVSS base score +7.5", "Production +1"}},

		// --- Confidence and freshness
		{name: "unconfirmed version (needs_validation)", why: "low-confidence inventory is scaled down and can never page",
			in: with(vuln("unknown", cvss(7.5)), func(in *Input) {
				prodExposed(in)
				in.KnownExploited, in.Verification = true, "needs_validation"
			}),
			pri: "P2", factors: []string{"CVSS base score +7.5", "Known exploited +3", "Internet exposed +1.5", "Production +1", "Evidence confidence -3.9"},
			evidence: map[string]string{"Evidence confidence": "installed version not confirmed"}},
		{name: "unconfirmed critical on exposed production", why: "never SOS until the version is confirmed",
			in:  with(vuln("unknown", cvss(9.8)), func(in *Input) { prodExposed(in); in.Verification = "needs_validation" }),
			pri: "P2", factors: []string{"CVSS base score +9.8", "Internet exposed +1.5", "Production +1", "Evidence confidence -3.7"}},
		{name: "stale asset", why: "the asset stopped reporting, so the component may be gone: scaled down, not SOS, still listed",
			in: with(vuln("high", cvss(7.5)), func(in *Input) {
				prodExposed(in)
				in.KnownExploited, in.Verification = true, "stale"
			}),
			pri: "P2", factors: []string{"CVSS base score +7.5", "Known exploited +3", "Internet exposed +1.5", "Production +1", "Evidence confidence -2.6"},
			evidence: map[string]string{"Evidence confidence": "asset has not reported recently"}},
		{name: "stale idle kernel", why: "a score already below zero is not scaled, which would raise it",
			in: with(vuln("high", cvss(7.8)), func(in *Input) {
				in.Environment, in.InternetExposed, in.KernelNotRunning, in.Verification = "production", internal, true, "stale"
			}),
			pri: "P4", factors: []string{"CVSS base score +7.8", "Production +1", "Kernel not running -10"}},

		// --- Scope, lifecycle and deadlines
		{name: "critical in a dev-only dependency", why: "not shipped at runtime: two points lower than the same runtime dependency",
			in:  with(vuln("critical", cvss(9.8)), func(in *Input) { in.Scope, in.Environment, in.InternetExposed = "dev", "production", internal }),
			pri: "P2", sos: "", factors: []string{"CVSS base score +9.8", "Production +1", "Development dependency -2"}},
		{name: "end-of-life runtime on exposed production", why: "no more security fixes for a reachable production runtime: P2",
			in:  Input{Kind: "end_of_life", Severity: "medium", Environment: "production", InternetExposed: exposed, Verification: "confirmed"},
			pri: "P2", factors: []string{"End of life +6", "Internet exposed +1.5", "Production +1"},
			evidence: map[string]string{"End of life": "no longer receives security fixes"}},
		{name: "end-of-life runtime on internal staging", why: "plan the upgrade: P3",
			in:  Input{Kind: "end_of_life", Severity: "medium", Environment: "staging", InternetExposed: internal, Verification: "confirmed"},
			pri: "P3", factors: []string{"End of life +6"}},
		{name: "overdue medium on internal staging", why: "missing the deadline raises it one point, never lowers it",
			in:  with(vuln("medium", cvss(6.1)), func(in *Input) { in.Environment, in.InternetExposed, in.Overdue = "staging", internal, true }),
			pri: "P3", factors: []string{"CVSS base score +6.1", "Overdue +1"},
			evidence: map[string]string{"Overdue": "past its remediation deadline"}},
	}
}

func fmtFactor(f Factor) string {
	return fmt.Sprintf("%s %+g", f.Name, math.Round(f.Points*10)/10)
}

func TestScenarios(t *testing.T) {
	p := DefaultPolicy()
	for _, sc := range scenarios() {
		t.Run(sc.name, func(t *testing.T) {
			r := p.Evaluate(sc.in)
			var got []string
			for _, f := range r.Factors {
				got = append(got, fmtFactor(f))
			}
			if r.Priority != sc.pri {
				t.Errorf("priority %s, want %s (score %.1f) - %s", r.Priority, sc.pri, r.Score, sc.why)
			}
			if r.SOSRule != sc.sos || r.SOS != (sc.sos != "") {
				t.Errorf("SOS %v %q, want %q - %s", r.SOS, r.SOSRule, sc.sos, sc.why)
			}
			if strings.Join(got, ", ") != strings.Join(sc.factors, ", ") {
				t.Errorf("factors\n got: %s\nwant: %s", strings.Join(got, ", "), strings.Join(sc.factors, ", "))
			}
			for name, text := range sc.evidence {
				found := false
				for _, f := range r.Factors {
					if f.Name == name {
						found = true
						if !strings.Contains(f.Detail, text) {
							t.Errorf("%s detail %q does not contain %q", name, f.Detail, text)
						}
					}
				}
				if !found {
					t.Errorf("no %s factor to carry evidence %q", name, text)
				}
			}
			checkExplanation(t, p, sc.in, r)
		})
	}
	if n := len(scenarios()); n < 30 {
		t.Errorf("only %d scenarios", n)
	}
}

// checkExplanation: the factors add up to the score, none is zero, and the
// factors present are exactly those whose condition holds (computed here
// independently of Evaluate).
func checkExplanation(t *testing.T, p Policy, in Input, r Result) {
	t.Helper()
	sum := 0.0
	names := map[string]bool{}
	for _, f := range r.Factors {
		if f.Points == 0 {
			t.Errorf("zero-point factor %s", f.Name)
		}
		if names[f.Name] {
			t.Errorf("factor %s listed twice", f.Name)
		}
		names[f.Name] = true
		sum += f.Points
	}
	if math.Abs(sum-r.Score) > 0.051 {
		t.Errorf("factors sum to %.3f, score is %.1f", sum, r.Score)
	}
	want := expectedFactors(p, in)
	for n := range names {
		if !want[n] {
			t.Errorf("factor %s listed but its condition does not hold: %+v", n, in)
		}
	}
	for n := range want {
		if !names[n] {
			t.Errorf("factor %s missing though its condition holds: %+v", n, in)
		}
	}
	if r.SOS && (in.Verification != "confirmed" || in.KernelNotRunning) {
		t.Errorf("SOS on %s evidence (kernel idle %v)", in.Verification, in.KernelNotRunning)
	}
}

func expectedFactors(p Policy, in Input) map[string]bool {
	w := map[string]bool{}
	set := func(name string, cond bool, pts float64) {
		if cond && pts != 0 {
			w[name] = true
		}
	}
	pre := 0.0 // the score before scaling, to know whether scaling applies
	add := func(name string, cond bool, pts float64) {
		set(name, cond, pts)
		if cond {
			pre += pts
		}
	}
	switch {
	case in.Kind == "end_of_life":
		add("End of life", true, p.EOLBase)
	case in.Score != nil && *in.Score > 0:
		add("CVSS base score", true, float64(*in.Score))
	default:
		base, ok := p.SeverityBase[in.Severity]
		if !ok {
			base = p.SeverityBase["unknown"]
		}
		add("Severity", true, base)
	}
	add("Known exploited", in.KnownExploited, p.KnownExploited)
	if in.EPSS != nil && !in.KnownExploited {
		limit := p.EPSSThreshold
		if in.EPSSCounted {
			limit *= EPSSRelease
		}
		add(FactorEPSS, *in.EPSS >= float32(limit), p.EPSS)
	}
	add("Exposure unknown", in.InternetExposed == nil, p.ExposureUnknown)
	add("Internet exposed", in.InternetExposed != nil && *in.InternetExposed, p.InternetExposed)
	prod := false
	for _, e := range p.ProductionEnvironments {
		prod = prod || strings.EqualFold(e, in.Environment)
	}
	add("Production", prod, p.Production)
	add("Environment unknown", !prod && strings.TrimSpace(in.Environment) == "", p.EnvironmentUnknown)
	crit := in.Criticality
	if crit == "" {
		crit = "unknown"
	}
	add("Asset criticality", true, p.CriticalityBonus[crit])
	add("Fix available", in.FixAvailable, p.FixAvailable)
	add("Overdue", in.Overdue, p.Overdue)
	add("Development dependency", in.Scope == "dev", p.DevDependency)
	add("Kernel not running", in.KernelNotRunning, p.KernelNotRunning)
	mul := map[string]float64{"needs_validation": p.NeedsValidationMul, "stale": p.StaleMul}[in.Verification]
	set("Evidence confidence", mul != 0 && mul != 1 && pre > 0, 1)
	return w
}

// --- Property tests

var (
	severities    = []string{"critical", "high", "medium", "low", "none", "unknown", "", "moderate"}
	environments  = []string{"production", "prod", "PROD", "staging", "development", "", " "}
	criticalities = []string{"critical", "high", "medium", "low", "unknown", ""}
	verifications = []string{"confirmed", "confirmed", "needs_validation", "stale"}
	sources       = []string{"", ExposureOperator, ExposureCollector, ExposureWorkloads}
)

func randInput(r *rand.Rand) Input {
	pick := func(s []string) string { return s[r.Intn(len(s))] }
	in := Input{Kind: "vulnerability", Severity: pick(severities), Environment: pick(environments), Criticality: pick(criticalities),
		Verification: pick(verifications), ExposureSource: pick(sources), KnownExploited: r.Intn(3) == 0, FixAvailable: r.Intn(2) == 0,
		Overdue: r.Intn(4) == 0, KernelNotRunning: r.Intn(8) == 0, EPSSCounted: r.Intn(3) == 0}
	if r.Intn(3) > 0 {
		in.EPSS = cvss(float32(math.Round(r.Float64()*1000) / 1000))
	}
	if r.Intn(8) == 0 {
		in.Kind = "end_of_life"
	}
	if r.Intn(3) > 0 {
		in.Score = cvss(float32(math.Round(r.Float64()*100) / 10))
	}
	switch r.Intn(3) {
	case 0:
		in.InternetExposed = exposed
	case 1:
		in.InternetExposed = internal
	}
	if r.Intn(4) == 0 {
		in.Scope = "dev"
	}
	return in
}

// randPolicy is a random policy that Validate accepts.
func randPolicy(r *rand.Rand) Policy {
	p := DefaultPolicy()
	w := func(max float64) float64 { return math.Round(r.Float64()*max*10) / 10 }
	p.KnownExploited, p.InternetExposed, p.Production, p.FixAvailable, p.Overdue = w(6), w(4), w(3), w(2), w(3)
	p.ExposureUnknown, p.EnvironmentUnknown = w(p.InternetExposed), w(p.Production)
	p.EPSS, p.EPSSThreshold = w(p.KnownExploited), 0.01+math.Round(r.Float64()*99)/100
	p.DevDependency, p.KernelNotRunning = -w(4), -w(12)
	p.NeedsValidationMul, p.StaleMul = 0.1+w(0.9), 0.1+w(0.9)
	low := w(3)
	p.SeverityBase = map[string]float64{"none": low / 4, "low": low, "medium": low + w(3), "unknown": w(10)}
	p.SeverityBase["high"] = p.SeverityBase["medium"] + w(3)
	p.SeverityBase["critical"] = p.SeverityBase["high"] + w(3)
	c := -w(2)
	p.CriticalityBonus = map[string]float64{"low": c, "medium": c + w(1), "unknown": w(2) - 1}
	p.CriticalityBonus["high"] = p.CriticalityBonus["medium"] + w(1)
	p.CriticalityBonus["critical"] = p.CriticalityBonus["high"] + w(1)
	if err := p.Validate(); err != nil {
		panic(err)
	}
	return p
}

// raise is a fact that, by the documented design, makes a finding at least as
// urgent. apply returns false when it does not apply to this input.
type raise struct {
	name  string
	apply func(*Input) bool
}

var raises = []raise{
	{"becomes known exploited", func(in *Input) bool { r := !in.KnownExploited; in.KnownExploited = true; return r }},
	{"EPSS rises", func(in *Input) bool {
		if in.EPSS == nil || *in.EPSS >= 1 {
			return false
		}
		in.EPSS = cvss(float32(math.Min(1, float64(*in.EPSS)+0.15)))
		return true
	}},
	{"EPSS published", func(in *Input) bool { r := in.EPSS == nil; in.EPSS = cvss(0.5); return r }},
	{"EPSS was counted before", func(in *Input) bool { r := !in.EPSSCounted; in.EPSSCounted = true; return r }},
	{"internal -> unknown exposure", func(in *Input) bool {
		r := in.InternetExposed != nil && !*in.InternetExposed
		if r {
			in.InternetExposed = unknown
		}
		return r
	}},
	{"unknown -> exposed", func(in *Input) bool { r := in.InternetExposed == nil; in.InternetExposed = exposed; return r }},
	{"internal -> exposed", func(in *Input) bool {
		r := in.InternetExposed != nil && !*in.InternetExposed
		in.InternetExposed = exposed
		return r
	}},
	{"non-production -> no environment", func(in *Input) bool {
		r := in.Environment == "staging" || in.Environment == "development"
		in.Environment = ""
		return r
	}},
	{"no environment -> production", func(in *Input) bool {
		r := strings.TrimSpace(in.Environment) == ""
		in.Environment = "production"
		return r
	}},
	{"criticality one step up", func(in *Input) bool {
		// Only along the labelled ladder: an admin may weigh "unknown"
		// pessimistically, so learning the real value can lower the score.
		next := map[string]string{"low": "medium", "medium": "high", "high": "critical"}[in.Criticality]
		in.Criticality = next
		return next != ""
	}},
	{"becomes overdue", func(in *Input) bool { r := !in.Overdue; in.Overdue = true; return r }},
	{"fix becomes available", func(in *Input) bool { r := !in.FixAvailable; in.FixAvailable = true; return r }},
	{"dev dependency -> runtime", func(in *Input) bool { r := in.Scope == "dev"; in.Scope = "runtime"; return r }},
	{"kernel is booted", func(in *Input) bool { r := in.KernelNotRunning; in.KernelNotRunning = false; return r }},
	{"evidence confirmed", func(in *Input) bool { r := in.Verification != "confirmed"; in.Verification = "confirmed"; return r }},
	{"severity one step up (no CVSS)", func(in *Input) bool {
		next := map[string]string{"none": "low", "low": "medium", "medium": "high", "high": "critical"}[in.Severity]
		r := next != "" && in.Kind == "vulnerability" && in.Score == nil
		in.Severity = next
		return r
	}},
	{"higher CVSS score", func(in *Input) bool {
		// A score of 0 means none was published (the severity base applies).
		if in.Score == nil || *in.Score <= 0 || *in.Score >= 10 || in.Kind != "vulnerability" {
			return false
		}
		in.Score = cvss(float32(math.Min(10, float64(*in.Score)+0.7)))
		return true
	}},
}

// Invariant 1 (monotonicity): adding a risk-raising fact never lowers the
// score or the priority, for every policy Validate accepts; under the default
// SOS rules it never removes SOS either.
func TestInvariantMonotonic(t *testing.T) {
	r := rand.New(rand.NewSource(20261025))
	for i := 0; i < 4000; i++ {
		p := DefaultPolicy()
		if i%2 == 1 {
			p = randPolicy(r)
		}
		in := randInput(r)
		before := p.Evaluate(in)
		for _, up := range raises {
			out := in
			if !up.apply(&out) {
				continue
			}
			after := p.Evaluate(out)
			if after.Score < before.Score || !PriorityAtLeast(after.Priority, before.Priority) {
				t.Fatalf("%s lowered %s %.1f -> %s %.1f\nbefore %+v\nafter  %+v\npolicy %s", up.name, before.Priority, before.Score,
					after.Priority, after.Score, in, out, p.Version())
			}
			if i%2 == 0 && before.SOS && !after.SOS {
				t.Fatalf("%s removed SOS (%s)\nbefore %+v\nafter  %+v", up.name, before.SOSRule, in, out)
			}
		}
	}
}

// Invariant 2 (missing evidence): for each piece of evidence that can be
// missing, the finding scores at least as high as with the benign value. The
// design intentionally differs from "as high as the worst value" in the ways
// listed in docs/risk.md; this test pins exactly those differences:
//
//   - exposure and environment: missing scores between benign and worst,
//     and SOS treats missing as the worst value;
//   - criticality: missing scores as the policy's "unknown" weight;
//   - severity: missing scores as the policy's "unknown" base, and does not
//     meet an SOS rule's min_severity.
func TestInvariantMissingEvidence(t *testing.T) {
	p := DefaultPolicy()
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 3000; i++ {
		in := randInput(r)
		in.KernelNotRunning = false

		benign, missing, worst := in, in, in
		benign.InternetExposed, missing.InternetExposed, worst.InternetExposed = internal, unknown, exposed
		between(t, p, "exposure", benign, missing, worst, true)

		benign, missing, worst = in, in, in
		benign.Environment, missing.Environment, worst.Environment = "staging", "", "production"
		between(t, p, "environment", benign, missing, worst, true)

		benign, missing, worst = in, in, in
		benign.Criticality, missing.Criticality, worst.Criticality = "low", "", "critical"
		between(t, p, "criticality", benign, missing, worst, false)
		unk := in
		unk.Criticality = "unknown"
		if p.Evaluate(missing).Score != p.Evaluate(unk).Score {
			t.Fatalf("empty criticality scores differently from unknown: %+v", in)
		}

		if in.Kind == "vulnerability" {
			benign, missing, worst = in, in, in
			benign.Score, missing.Score, worst.Score = nil, nil, nil
			benign.Severity, missing.Severity, worst.Severity = "none", "", "critical"
			between(t, p, "severity", benign, missing, worst, false)
			named := missing
			named.Severity = "unknown"
			if p.Evaluate(missing).Score != p.Evaluate(named).Score {
				t.Fatalf("missing severity scores differently from unknown: %+v", in)
			}
		}
	}
}

func between(t *testing.T, p Policy, what string, benign, missing, worst Input, sosAsWorst bool) {
	t.Helper()
	rb, rm, rw := p.Evaluate(benign), p.Evaluate(missing), p.Evaluate(worst)
	if rm.Score < rb.Score || !PriorityAtLeast(rm.Priority, rb.Priority) {
		t.Fatalf("missing %s scored below the benign value: %s %.1f < %s %.1f\n%+v", what, rm.Priority, rm.Score, rb.Priority, rb.Score, missing)
	}
	if rm.Score > rw.Score {
		t.Fatalf("missing %s scored above the worst value: %.1f > %.1f", what, rm.Score, rw.Score)
	}
	if sosAsWorst && rm.SOS != rw.SOS {
		t.Fatalf("missing %s: SOS %v, worst value SOS %v\n%+v", what, rm.SOS, rw.SOS, missing)
	}
	if rb.SOS && !rm.SOS {
		t.Fatalf("missing %s lost the SOS the benign value has", what)
	}
}

// Invariant 3 (explanation): for any finding the factors add up to the score
// and are exactly the factors whose conditions hold.
func TestInvariantExplanation(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for i := 0; i < 3000; i++ {
		p := DefaultPolicy()
		if i%2 == 1 {
			p = randPolicy(r)
		}
		in := randInput(r)
		checkExplanation(t, p, in, p.Evaluate(in))
		if t.Failed() {
			t.Fatalf("input %+v", in)
		}
	}
}

// Invariant 4 (reproducibility): the same policy and input always give the
// same result, also after the policy is stored as JSON and read back, and the
// version changes whenever anything that affects a result changes.
func TestInvariantReproducible(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	for i := 0; i < 500; i++ {
		p := randPolicy(r)
		raw, _ := json.Marshal(p)
		q, err := DecodePolicy(raw, true)
		if err != nil || q.Version() != p.Version() {
			t.Fatalf("stored policy reads back as version %s, want %s (%v)", q.Version(), p.Version(), err)
		}
		for j := 0; j < 10; j++ {
			in := randInput(r)
			a, b2, c := p.Evaluate(in), p.Evaluate(in), q.Evaluate(in)
			if !reflect.DeepEqual(a, b2) || !reflect.DeepEqual(a, c) {
				t.Fatalf("results differ for %+v:\n%+v\n%+v\n%+v", in, a, b2, c)
			}
		}
	}
	base := DefaultPolicy()
	for name, mut := range map[string]func(*Policy){
		"weight":         func(p *Policy) { p.KnownExploited += 0.1 },
		"map weight":     func(p *Policy) { p.CriticalityBonus["high"] += 0.1 },
		"threshold":      func(p *Policy) { p.Thresholds.P2 -= 0.1 },
		"SOS rule":       func(p *Policy) { p.SOS = p.SOS[:1] },
		"env list":       func(p *Policy) { p.ProductionEnvironments = append(p.ProductionEnvironments, "live") },
		"multiplier":     func(p *Policy) { p.StaleMul = 0.75 },
		"EPSS threshold": func(p *Policy) { p.EPSSThreshold = 0.2 },
	} {
		p := DefaultPolicy()
		mut(&p)
		if p.Version() == base.Version() {
			t.Errorf("changing the %s kept the version", name)
		}
	}
}
