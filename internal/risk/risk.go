// Package risk computes a finding's priority from configurable factors
// (PRD §9). Every point added or removed is reported as a factor so the
// operator can see why something is P1 — and the result is deliberately
// coarse (P1–P4) to avoid false precision.
package risk

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Policy is stored as JSON in settings and editable by admins.
type Policy struct {
	// Base score per severity when no CVSS score is available.
	SeverityBase map[string]float64 `json:"severity_base"`
	EOLBase      float64            `json:"eol_base"`

	KnownExploited float64 `json:"known_exploited"`
	// EPSS is added while FIRST's EPSS probability of exploitation in the
	// next 30 days is at or above EPSSThreshold (0 to 1), and not for a CVE
	// already in CISA KEV, which counts as evidence rather than a prediction.
	// A finding that crossed the threshold keeps the points until its EPSS
	// falls below EPSSRelease × the threshold, so a score that moves a
	// little around the threshold from day to day does not move its priority.
	EPSS               float64            `json:"epss"`
	EPSSThreshold      float64            `json:"epss_threshold"`
	InternetExposed    float64            `json:"internet_exposed"`
	ExposureUnknown    float64            `json:"exposure_unknown"`
	Production         float64            `json:"production"`
	EnvironmentUnknown float64            `json:"environment_unknown"` // asset has no environment
	FixAvailable       float64            `json:"fix_available"`
	Overdue            float64            `json:"overdue"`
	DevDependency      float64            `json:"dev_dependency"`
	KernelNotRunning   float64            `json:"kernel_not_running"`
	CriticalityBonus   map[string]float64 `json:"criticality"`
	NeedsValidationMul float64            `json:"needs_validation_multiplier"`
	StaleMul           float64            `json:"stale_multiplier"`

	ProductionEnvironments []string `json:"production_environments"`

	// Thresholds: score >= P1 -> P1, etc.
	Thresholds struct {
		P1 float64 `json:"p1"`
		P2 float64 `json:"p2"`
		P3 float64 `json:"p3"`
	} `json:"thresholds"`

	SLA map[string]SLA `json:"sla"` // by priority

	// ExceptionMaxDays is the longest a finding may stay suppressed or
	// risk-accepted before it returns for review. 0 means the default (365),
	// so policies saved before the field existed keep working.
	ExceptionMaxDays int `json:"exception_max_days"`

	// SOS fires when any rule matches. Rules never rely on severity alone.
	SOS []SOSRule `json:"sos_rules"`
}

type SLA struct {
	AckHours int `json:"ack_hours"`
	FixDays  int `json:"fix_days"`
}

// SOSRule matches when every set condition holds.
type SOSRule struct {
	Name            string `json:"name"`
	MinPriority     string `json:"min_priority,omitempty"`
	KnownExploited  *bool  `json:"known_exploited,omitempty"`
	Production      *bool  `json:"production,omitempty"`       // true matches production or no environment
	InternetExposed *bool  `json:"internet_exposed,omitempty"` // true matches exposed or unknown
	MinSeverity     string `json:"min_severity,omitempty"`
	FixAvailable    *bool  `json:"fix_available,omitempty"`
}

func ptr(b bool) *bool { return &b }

func DefaultPolicy() Policy {
	p := Policy{
		SeverityBase:           map[string]float64{"critical": 9.5, "high": 7.5, "medium": 5, "low": 2.5, "none": 0.5, "unknown": 5},
		EOLBase:                6,
		KnownExploited:         3,
		EPSS:                   1.5,
		EPSSThreshold:          0.1,
		InternetExposed:        1.5,
		ExposureUnknown:        0.5,
		Production:             1,
		EnvironmentUnknown:     0.5,
		FixAvailable:           0.5,
		Overdue:                1,
		DevDependency:          -2,
		KernelNotRunning:       -10,
		CriticalityBonus:       map[string]float64{"critical": 1.5, "high": 1, "medium": 0, "low": -1, "unknown": 0},
		NeedsValidationMul:     0.7,
		StaleMul:               0.8,
		ProductionEnvironments: []string{"production", "prod"},
		SLA: map[string]SLA{
			"P1": {AckHours: 4, FixDays: 3},
			"P2": {AckHours: 24, FixDays: 14},
			"P3": {AckHours: 72, FixDays: 45},
			"P4": {AckHours: 168, FixDays: 90},
		},
		ExceptionMaxDays: DefaultExceptionMaxDays,
		SOS: []SOSRule{
			{Name: "Known exploited in production", KnownExploited: ptr(true), Production: ptr(true)},
			{Name: "Critical, exposed production asset", MinSeverity: "critical", Production: ptr(true), InternetExposed: ptr(true)},
		},
	}
	// A high-severity issue on an exposed, critical production asset is P2;
	// reaching P1 takes a critical score or active exploitation.
	p.Thresholds.P1, p.Thresholds.P2, p.Thresholds.P3 = 12, 8.5, 6
	return p
}

func (p Policy) Validate() error {
	if !(p.Thresholds.P1 > p.Thresholds.P2 && p.Thresholds.P2 > p.Thresholds.P3) {
		return errors.New("thresholds must satisfy p1 > p2 > p3")
	}
	for _, pr := range []string{"P1", "P2", "P3", "P4"} {
		s, ok := p.SLA[pr]
		if !ok || s.AckHours <= 0 || s.FixDays <= 0 {
			return fmt.Errorf("sla for %s needs positive ack_hours and fix_days", pr)
		}
	}
	if p.ExceptionMaxDays < 0 || p.ExceptionMaxDays > 730 {
		return errors.New("exception_max_days must be between 1 and 730 (0 for the default of 365)")
	}
	if p.EPSSThreshold <= 0 || p.EPSSThreshold > 1 {
		return errors.New("epss_threshold must be a probability above 0 and at most 1 (0.1 is 10%)")
	}
	if p.NeedsValidationMul <= 0 || p.NeedsValidationMul > 1 || p.StaleMul <= 0 || p.StaleMul > 1 {
		return errors.New("multipliers must be in (0, 1]")
	}
	if err := p.validateDirections(); err != nil {
		return err
	}
	for _, r := range p.SOS {
		if r.Name == "" {
			return errors.New("every SOS rule needs a name")
		}
		onlySeverity := r.MinSeverity != "" && r.MinPriority == "" && r.KnownExploited == nil &&
			r.Production == nil && r.InternetExposed == nil && r.FixAvailable == nil
		if onlySeverity {
			return fmt.Errorf("SOS rule %q relies on severity alone; add an exposure, environment or exploitation condition", r.Name)
		}
		if r.MinPriority != "" && priorityRank[r.MinPriority] == 0 {
			return fmt.Errorf("SOS rule %q has an invalid min_priority", r.Name)
		}
	}
	return nil
}

// validateDirections rejects weights that point the wrong way, so that the
// invariants in docs/risk.md hold for every policy that can be saved: a fact
// that raises risk never lowers the score, and missing evidence never counts
// for more than the worst value it stands in for.
func (p Policy) validateDirections() error {
	for _, w := range []struct {
		name string
		v    float64
	}{{"known_exploited", p.KnownExploited}, {"epss", p.EPSS}, {"internet_exposed", p.InternetExposed}, {"exposure_unknown", p.ExposureUnknown},
		{"production", p.Production}, {"environment_unknown", p.EnvironmentUnknown}, {"overdue", p.Overdue}} {
		if w.v < 0 {
			return fmt.Errorf("%s must not be negative: it marks higher risk", w.name)
		}
	}
	if p.EPSS > p.KnownExploited {
		return errors.New("epss must not exceed known_exploited: a prediction of exploitation never counts for more than evidence of it")
	}
	if p.ExposureUnknown > p.InternetExposed {
		return errors.New("exposure_unknown must not exceed internet_exposed")
	}
	if p.EnvironmentUnknown > p.Production {
		return errors.New("environment_unknown must not exceed production")
	}
	if p.DevDependency > 0 || p.KernelNotRunning > 0 {
		return errors.New("dev_dependency and kernel_not_running must not be positive: they mark lower risk")
	}
	ordered := func(field string, m map[string]float64, keys ...string) error {
		for i := 1; i < len(keys); i++ {
			if m[keys[i-1]] < m[keys[i]] {
				return fmt.Errorf("%s: %s must not score below %s", field, keys[i-1], keys[i])
			}
		}
		return nil
	}
	if err := ordered("severity_base", p.SeverityBase, "critical", "high", "medium", "low", "none"); err != nil {
		return err
	}
	return ordered("criticality", p.CriticalityBonus, "critical", "high", "medium", "low")
}

// Input is everything the model looks at.
type Input struct {
	Kind           string // vulnerability, end_of_life
	Severity       string
	Score          *float32 // CVSS base score when known
	KnownExploited bool
	// EPSS is FIRST's EPSS probability for the finding's CVE, nil when it
	// has none (no CVE, not scored yet, or the feed is off).
	EPSS *float32
	// EPSSCounted says the finding had the EPSS factor when it was last
	// prioritised; it then keeps it down to EPSSRelease × the threshold.
	EPSSCounted     bool
	InternetExposed *bool
	// ExposureSource says where InternetExposed came from (Exposure*
	// constants), so the explanation names the evidence.
	ExposureSource string
	Environment    string // "" when the asset has none
	Criticality    string // "" is treated as "unknown"
	FixAvailable   bool
	Overdue        bool
	Scope          string // runtime, dev, os
	Verification   string
	// KernelNotRunning: the package belongs to an installed kernel that is
	// not the running one, so nothing is exposed until it is booted.
	KernelNotRunning bool
}

// Where an asset's exposure came from.
const (
	ExposureOperator  = "operator"  // set by hand on the asset
	ExposureCollector = "collector" // reported by the asset's collector (a Kubernetes workload)
	ExposureWorkloads = "workloads" // an image, from the current workloads deployed as it
)

func exposureDetail(exposed *bool, source string) string {
	switch {
	case exposed == nil && source == ExposureCollector:
		return "its collector could not decide exposure (e.g. Kubernetes Services or Ingresses unreadable)"
	case exposed == nil && source == ExposureWorkloads:
		return "a running workload deployed as this image has unknown exposure"
	case exposed == nil:
		return "asset exposure not recorded"
	case source == ExposureOperator:
		return "marked internet exposed on the asset"
	case source == ExposureCollector:
		return "its collector reports it reachable from outside (e.g. a LoadBalancer or NodePort Service, an Ingress)"
	case source == ExposureWorkloads:
		return "a running workload deployed as this image is reachable from outside"
	}
	return "asset is reachable from the internet"
}

// FactorEPSS names the EPSS factor in priority_factors. Prioritize reads it
// back to know whether a finding had already crossed the threshold, so it
// must not change.
const FactorEPSS = "Exploit prediction (EPSS)"

// EPSSRelease is the share of the EPSS threshold below which a finding that
// had crossed it loses the factor again (hysteresis): with the default
// threshold of 10% it is counted from 10% and kept down to 8%.
const EPSSRelease = 0.8

// EPSSCounts reports whether an EPSS probability earns the EPSS factor:
// at or above the threshold, or, for a finding that already had the factor,
// at or above EPSSRelease × the threshold.
func (p Policy) EPSSCounts(score float32, counted bool) bool {
	// Scores are stored as float32 (real): compare at that precision, so a
	// score of exactly 8% is at 80% of a 10% threshold.
	if counted {
		return score >= float32(p.EPSSThreshold*EPSSRelease)
	}
	return score >= float32(p.EPSSThreshold)
}

// Percent formats a probability as a percentage with at most one decimal
// (0.1 -> "10%", 0.025 -> "2.5%", 0.00042 -> "0.042%").
func Percent(v float64) string {
	pc := v * 100
	if pc > 0 && pc < 0.1 {
		return strconv.FormatFloat(pc, 'g', 2, 64) + "%"
	}
	// Never round a probability below 1 up to a certainty (0.99999 is 99.99%).
	if v < 1 && math.Round(pc*10)/10 >= 100 {
		return strconv.FormatFloat(math.Floor(pc*100)/100, 'f', -1, 64) + "%"
	}
	return strconv.FormatFloat(math.Round(pc*10)/10, 'f', -1, 64) + "%"
}

var verificationDetail = map[string]string{
	"needs_validation": "installed version not confirmed",
	"stale":            "asset has not reported recently",
}

type Factor struct {
	Name   string  `json:"name"`
	Points float64 `json:"points"`
	Detail string  `json:"detail"`
}

type Result struct {
	Score    float64  `json:"score"`
	Priority string   `json:"priority"`
	Factors  []Factor `json:"factors"`
	SOS      bool     `json:"sos"`
	SOSRule  string   `json:"sos_rule,omitempty"`
}

var priorityRank = map[string]int{"P4": 1, "P3": 2, "P2": 3, "P1": 4}
var severityRank = map[string]int{"unknown": 0, "none": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

// PriorityAtLeast reports whether p is as urgent as min.
func PriorityAtLeast(p, min string) bool { return priorityRank[p] >= priorityRank[min] }

func (p Policy) IsProduction(env string) bool {
	for _, e := range p.ProductionEnvironments {
		if strings.EqualFold(e, env) {
			return true
		}
	}
	return false
}

func (p Policy) Evaluate(in Input) Result {
	var r Result
	add := func(name string, pts float64, detail string) {
		if pts == 0 {
			return
		}
		r.Score += pts
		r.Factors = append(r.Factors, Factor{name, pts, detail})
	}
	switch {
	case in.Kind == "end_of_life":
		add("End of life", p.EOLBase, "release cycle no longer receives security fixes")
	case in.Score != nil && *in.Score > 0:
		add("CVSS base score", float64(*in.Score), fmt.Sprintf("CVSS %.1f", *in.Score))
	default:
		base, ok := p.SeverityBase[in.Severity]
		detail := "advisory severity " + in.Severity + ", no CVSS score"
		if !ok || in.Severity == "unknown" {
			base = p.SeverityBase["unknown"]
			detail = "no severity or CVSS score published; scored as unknown"
		}
		add("Severity", base, detail)
	}
	if in.KnownExploited {
		add("Known exploited", p.KnownExploited, "listed in CISA KEV")
	} else if in.EPSS != nil && p.EPSSCounts(*in.EPSS, in.EPSSCounted) {
		// The detail names the threshold, not the day's score, so the stored
		// factors stay the same while the score moves within the band.
		add(FactorEPSS, p.EPSS, fmt.Sprintf("FIRST EPSS of %s or more (the chance of exploitation in the next 30 days); kept until it falls below %s",
			Percent(p.EPSSThreshold), Percent(p.EPSSThreshold*EPSSRelease)))
	}
	switch {
	case in.InternetExposed == nil:
		add("Exposure unknown", p.ExposureUnknown, exposureDetail(nil, in.ExposureSource))
	case *in.InternetExposed:
		add("Internet exposed", p.InternetExposed, exposureDetail(in.InternetExposed, in.ExposureSource))
	}
	production := p.IsProduction(in.Environment)
	envUnknown := strings.TrimSpace(in.Environment) == ""
	switch {
	case production:
		add("Production", p.Production, "environment "+in.Environment)
	case envUnknown:
		add("Environment unknown", p.EnvironmentUnknown, "asset has no environment; it may be production")
	}
	crit := in.Criticality
	if crit == "" {
		crit = "unknown"
	}
	if c := p.CriticalityBonus[crit]; c != 0 {
		add("Asset criticality", c, "criticality "+crit)
	}
	if in.FixAvailable {
		add("Fix available", p.FixAvailable, "an upgrade resolves it")
	}
	if in.Overdue {
		add("Overdue", p.Overdue, "past its remediation deadline")
	}
	if in.Scope == "dev" {
		add("Development dependency", p.DevDependency, "not shipped at runtime")
	}
	if in.KernelNotRunning {
		add("Kernel not running", p.KernelNotRunning, "installed kernel that is not booted; remove old kernels")
	}
	// Confidence and freshness scale the result rather than add to it. A
	// score at or below zero is left alone: scaling it would raise it.
	mul := 1.0
	switch in.Verification {
	case "needs_validation":
		mul = p.NeedsValidationMul
	case "stale":
		mul = p.StaleMul
	}
	if mul != 1 && r.Score > 0 {
		before := r.Score
		r.Score *= mul
		r.Factors = append(r.Factors, Factor{"Evidence confidence", r.Score - before,
			fmt.Sprintf("%s (%s): ×%.2f", in.Verification, verificationDetail[in.Verification], mul)})
	}
	r.Score = math.Round(r.Score*10) / 10
	switch {
	case r.Score >= p.Thresholds.P1:
		r.Priority = "P1"
	case r.Score >= p.Thresholds.P2:
		r.Priority = "P2"
	case r.Score >= p.Thresholds.P3:
		r.Priority = "P3"
	default:
		r.Priority = "P4"
	}
	// SOS requires confirmed evidence about something actually exposed.
	if in.Verification == "confirmed" && !in.KernelNotRunning {
		for _, rule := range p.SOS {
			if rule.matches(in, r.Priority, production || envUnknown) {
				r.SOS, r.SOSRule = true, rule.Name
				break
			}
		}
	}
	return r
}

func (rule SOSRule) matches(in Input, priority string, production bool) bool {
	if rule.MinPriority != "" && !PriorityAtLeast(priority, rule.MinPriority) {
		return false
	}
	if rule.MinSeverity != "" && severityRank[in.Severity] < severityRank[rule.MinSeverity] {
		return false
	}
	if rule.KnownExploited != nil && *rule.KnownExploited != in.KnownExploited {
		return false
	}
	if rule.Production != nil && *rule.Production != production { // unknown environment counts as production
		return false
	}
	if rule.FixAvailable != nil && *rule.FixAvailable != in.FixAvailable {
		return false
	}
	if rule.InternetExposed != nil {
		exposed := in.InternetExposed == nil || *in.InternetExposed // unknown counts as exposed
		if *rule.InternetExposed != exposed {
			return false
		}
	}
	return true
}

// DecodePolicy reads a policy's JSON over the defaults: a field it leaves out
// (one added after it was saved) keeps its default value, and an omitted
// sos_rules keeps the default rules. Rules that are present replace the
// defaults entirely; decoding them into the default slice would let a saved
// rule inherit conditions it never had (json reuses existing elements). With
// strict, unknown fields are an error.
func DecodePolicy(raw []byte, strict bool) (Policy, error) {
	p := DefaultPolicy()
	defaultRules := p.SOS
	p.SOS = nil
	dec := json.NewDecoder(bytes.NewReader(raw))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(&p); err != nil {
		return Policy{}, err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return Policy{}, err
	}
	if _, ok := keys["sos_rules"]; !ok {
		p.SOS = defaultRules
	}
	// A policy saved before EPSS existed gets the default EPSS points, but
	// never more than its own known_exploited weight (Validate's rule): an
	// admin who lowered known exploitation lowered predicted exploitation too.
	if _, ok := keys["epss"]; !ok && p.EPSS > p.KnownExploited {
		p.EPSS = max(p.KnownExploited, 0)
	}
	return p, nil
}

// DefaultExceptionMaxDays is the exception limit when a policy leaves it at 0.
const DefaultExceptionMaxDays = 365

// Normalize fills the values that stand for "the default", so the policy that
// is stored, audited and versioned is exactly the one that is applied.
func (p Policy) Normalize() Policy {
	if p.ExceptionMaxDays == 0 {
		p.ExceptionMaxDays = DefaultExceptionMaxDays
	}
	return p
}

// Version identifies the policy's content: the same weights, thresholds,
// deadlines and rules always give the same version, so a stored priority can
// be traced to the policy that produced it.
func (p Policy) Version() string {
	b, _ := json.Marshal(p) // map keys are sorted, so the encoding is stable
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}

// Deadlines returns acknowledgement and fix deadlines from first detection.
func (p Policy) Deadlines(priority string, firstSeen time.Time) (ack, fix time.Time) {
	s := p.SLA[priority]
	return firstSeen.Add(time.Duration(s.AckHours) * time.Hour), firstSeen.AddDate(0, 0, s.FixDays)
}
