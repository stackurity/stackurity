package osv

import (
	"math"
	"strconv"
	"strings"
)

// cvss4Metrics is the CVSS v4.0 metric order and the values each metric
// accepts (metrics.js in the reference calculator). The first 11 (Base) are
// mandatory; the rest are optional, and X means Not Defined.
var cvss4Metrics = []struct {
	key    string
	values []string
}{
	// Base
	{"AV", []string{"N", "A", "L", "P"}},
	{"AC", []string{"L", "H"}},
	{"AT", []string{"N", "P"}},
	{"PR", []string{"N", "L", "H"}},
	{"UI", []string{"N", "P", "A"}},
	{"VC", []string{"H", "L", "N"}},
	{"VI", []string{"H", "L", "N"}},
	{"VA", []string{"H", "L", "N"}},
	{"SC", []string{"H", "L", "N"}},
	{"SI", []string{"H", "L", "N"}},
	{"SA", []string{"H", "L", "N"}},
	// Threat
	{"E", []string{"X", "A", "P", "U"}},
	// Environmental
	{"CR", []string{"X", "H", "M", "L"}},
	{"IR", []string{"X", "H", "M", "L"}},
	{"AR", []string{"X", "H", "M", "L"}},
	{"MAV", []string{"X", "N", "A", "L", "P"}},
	{"MAC", []string{"X", "L", "H"}},
	{"MAT", []string{"X", "N", "P"}},
	{"MPR", []string{"X", "N", "L", "H"}},
	{"MUI", []string{"X", "N", "P", "A"}},
	{"MVC", []string{"X", "H", "L", "N"}},
	{"MVI", []string{"X", "H", "L", "N"}},
	{"MVA", []string{"X", "H", "L", "N"}},
	{"MSC", []string{"X", "H", "L", "N"}},
	{"MSI", []string{"X", "S", "H", "L", "N"}},
	{"MSA", []string{"X", "S", "H", "L", "N"}},
	// Supplemental: validated, never scored
	{"S", []string{"X", "N", "P"}},
	{"AU", []string{"X", "N", "Y"}},
	{"R", []string{"X", "A", "U", "I"}},
	{"V", []string{"X", "D", "C"}},
	{"RE", []string{"X", "L", "M", "H"}},
	{"U", []string{"X", "Clear", "Green", "Amber", "Red"}},
}

const cvss4BaseMetrics = 11

// cvss4Vector holds the parsed metric values; absent optional metrics are "X".
type cvss4Vector map[string]string

// parseCVSS4 validates a vector the way the reference calculator does: the
// "CVSS:4.0" prefix, every Base metric, metrics in the specification's order
// (so no duplicates or unknown metrics) and only listed values. It is stricter
// in two places: all Base metrics must be present, and "K:V:extra" is rejected.
func parseCVSS4(vector string) (cvss4Vector, bool) {
	parts := strings.Split(vector, "/")
	if len(parts) < 1+cvss4BaseMetrics || parts[0] != "CVSS:4.0" {
		return nil, false
	}
	v := make(cvss4Vector, len(cvss4Metrics))
	for _, m := range cvss4Metrics[cvss4BaseMetrics:] {
		v[m.key] = "X"
	}
	next := 0
	for _, p := range parts[1:] {
		key, val, ok := strings.Cut(p, ":")
		if !ok || strings.Contains(val, ":") {
			return nil, false
		}
		for next < len(cvss4Metrics) && cvss4Metrics[next].key != key {
			if next < cvss4BaseMetrics {
				return nil, false // a Base metric is missing or out of order
			}
			next++
		}
		if next == len(cvss4Metrics) {
			return nil, false // unknown, repeated or out of order
		}
		valid := false
		for _, allowed := range cvss4Metrics[next].values {
			if val == allowed {
				valid = true
				break
			}
		}
		if !valid {
			return nil, false
		}
		v[key] = val
		next++
	}
	if next < cvss4BaseMetrics {
		return nil, false
	}
	return v, true
}

// m is the effective value of a metric: a Modified (environmental) value
// overrides the Base one, and Not Defined E, CR, IR and AR take their worst
// case (E:A, xR:H), as in the reference calculator.
func (v cvss4Vector) m(metric string) string {
	sel := v[metric]
	switch metric {
	case "E":
		if sel == "X" {
			return "A"
		}
	case "CR", "IR", "AR":
		if sel == "X" {
			return "H"
		}
	}
	if mod, ok := v["M"+metric]; ok && mod != "X" {
		return mod
	}
	return sel
}

// macroVector returns the six EQ levels (equivalence classes) of a vector.
func (v cvss4Vector) macroVector() [6]int {
	var eq [6]int
	av, pr, ui := v.m("AV"), v.m("PR"), v.m("UI")
	switch {
	case av == "N" && pr == "N" && ui == "N":
		eq[0] = 0
	case (av == "N" || pr == "N" || ui == "N") && av != "P":
		eq[0] = 1
	default:
		eq[0] = 2
	}
	if !(v.m("AC") == "L" && v.m("AT") == "N") {
		eq[1] = 1
	}
	vc, vi, va := v.m("VC"), v.m("VI"), v.m("VA")
	switch {
	case vc == "H" && vi == "H":
		eq[2] = 0
	case vc == "H" || vi == "H" || va == "H":
		eq[2] = 1
	default:
		eq[2] = 2
	}
	switch {
	case v.m("MSI") == "S" || v.m("MSA") == "S":
		eq[3] = 0
	case v.m("SC") == "H" || v.m("SI") == "H" || v.m("SA") == "H":
		eq[3] = 1
	default:
		eq[3] = 2
	}
	switch v.m("E") {
	case "P":
		eq[4] = 1
	case "U":
		eq[4] = 2
	}
	if !((v.m("CR") == "H" && vc == "H") || (v.m("IR") == "H" && vi == "H") || (v.m("AR") == "H" && va == "H")) {
		eq[5] = 1
	}
	return eq
}

// Severity levels of each metric value within its EQ, used for the distance
// from the MacroVector's highest-severity vector (cvss_score.js).
var cvss4Levels = map[string]map[string]float64{
	"AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
	"PR": {"N": 0.0, "L": 0.1, "H": 0.2},
	"UI": {"N": 0.0, "P": 0.1, "A": 0.2},
	"AC": {"L": 0.0, "H": 0.1},
	"AT": {"N": 0.0, "P": 0.1},
	"VC": {"H": 0.0, "L": 0.1, "N": 0.2},
	"VI": {"H": 0.0, "L": 0.1, "N": 0.2},
	"VA": {"H": 0.0, "L": 0.1, "N": 0.2},
	"SC": {"H": 0.1, "L": 0.2, "N": 0.3},
	"SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
	"SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
	"CR": {"H": 0.0, "M": 0.1, "L": 0.2},
	"IR": {"H": 0.0, "M": 0.1, "L": 0.2},
	"AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}

// cvss4DistanceOrder is the order the reference calculator checks distances in.
var cvss4DistanceOrder = []string{"AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR"}

func cvss4MacroScore(eq [6]int) float64 {
	var b strings.Builder
	for _, d := range eq {
		b.WriteString(strconv.Itoa(d))
	}
	if s, ok := cvss4Lookup[b.String()]; ok {
		return s
	}
	return math.NaN() // no such MacroVector, as undefined in the calculator
}

// CVSS4Score computes the CVSS v4.0 score of a vector: CVSS-B for a Base-only
// vector, CVSS-BT/BE/BTE when Threat or Environmental metrics are present.
// Supplemental metrics are validated but do not change the score. It is a
// port of cvss_score.js in the FIRST reference calculator, including its
// floating-point order of operations, so results match it exactly.
func CVSS4Score(vector string) (float64, bool) {
	v, ok := parseCVSS4(vector)
	if !ok {
		return 0, false
	}
	return v.score(), true
}

func (v cvss4Vector) score() float64 {
	// No impact on either system: the score is 0.
	none := true
	for _, k := range []string{"VC", "VI", "VA", "SC", "SI", "SA"} {
		if v.m(k) != "N" {
			none = false
			break
		}
	}
	if none {
		return 0
	}
	eq := v.macroVector()
	value := cvss4MacroScore(eq)
	if math.IsNaN(value) {
		return 0 // unreachable for a valid vector
	}
	eq1, eq2, eq3, eq4, eq5, eq6 := eq[0], eq[1], eq[2], eq[3], eq[4], eq[5]

	// 1a. Score of the next lower MacroVector for each EQ (NaN if none).
	lowerEQ1 := cvss4MacroScore([6]int{eq1 + 1, eq2, eq3, eq4, eq5, eq6})
	lowerEQ2 := cvss4MacroScore([6]int{eq1, eq2 + 1, eq3, eq4, eq5, eq6})
	var lowerEQ3EQ6 float64
	switch {
	case eq3 == 0 && eq6 == 0:
		// Two ways down (00 -> 01 or 00 -> 10): take the higher score, with
		// the calculator's comparison semantics for missing ones.
		left := cvss4MacroScore([6]int{eq1, eq2, eq3, eq4, eq5, eq6 + 1})
		right := cvss4MacroScore([6]int{eq1, eq2, eq3 + 1, eq4, eq5, eq6})
		if left > right {
			lowerEQ3EQ6 = left
		} else {
			lowerEQ3EQ6 = right
		}
	case eq3 == 1 && eq6 == 0:
		lowerEQ3EQ6 = cvss4MacroScore([6]int{eq1, eq2, eq3, eq4, eq5, eq6 + 1})
	case (eq3 == 0 || eq3 == 1) && eq6 == 1:
		lowerEQ3EQ6 = cvss4MacroScore([6]int{eq1, eq2, eq3 + 1, eq4, eq5, eq6})
	default:
		lowerEQ3EQ6 = cvss4MacroScore([6]int{eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1})
	}
	lowerEQ4 := cvss4MacroScore([6]int{eq1, eq2, eq3, eq4 + 1, eq5, eq6})
	lowerEQ5 := cvss4MacroScore([6]int{eq1, eq2, eq3, eq4, eq5 + 1, eq6})

	// 1b. Severity distance from the first highest-severity vector of the
	// MacroVector that is not less severe than this one. If none qualifies,
	// the last candidate's distances are kept, as in the calculator.
	mc := cvss4MaxComposed
	dist := map[string]float64{}
	found := false
	for _, a := range mc.eq1[eq1] {
		for _, b := range mc.eq2[eq2] {
			for _, c := range mc.eq3[eq3][eq6] {
				for _, d := range mc.eq4[eq4] {
					maxVec := parseMaxVector(a + b + c + d)
					negative := false
					for _, k := range cvss4DistanceOrder {
						lv := cvss4Levels[k]
						dist[k] = lv[v.m(k)] - lv[maxVec[k]]
						if dist[k] < 0 {
							negative = true
						}
					}
					if !negative {
						found = true
					}
					if found {
						break
					}
				}
				if found {
					break
				}
			}
			if found {
				break
			}
		}
		if found {
			break
		}
	}
	distEQ1 := dist["AV"] + dist["PR"] + dist["UI"]
	distEQ2 := dist["AC"] + dist["AT"]
	distEQ3EQ6 := dist["VC"] + dist["VI"] + dist["VA"] + dist["CR"] + dist["IR"] + dist["AR"]
	distEQ4 := dist["SC"] + dist["SI"] + dist["SA"]

	const step = 0.1
	ms := cvss4MaxSeverity
	maxEQ1 := float64(ms.eq1[eq1] * step)
	maxEQ2 := float64(ms.eq2[eq2] * step)
	maxEQ3EQ6 := float64(ms.eq3eq6[eq3][eq6] * step)
	maxEQ4 := float64(ms.eq4[eq4] * step)

	// 1c/1d. Proportion of the distance times the available score drop.
	// The float64 conversions keep each product rounded on its own, so the
	// compiler cannot fuse it into the following addition (as on arm64) and
	// the result stays bit-identical to the JavaScript calculator.
	n := 0
	var nEQ1, nEQ2, nEQ3EQ6, nEQ4, nEQ5 float64
	if d := value - lowerEQ1; !math.IsNaN(d) {
		n++
		nEQ1 = float64(d * float64(distEQ1/maxEQ1))
	}
	if d := value - lowerEQ2; !math.IsNaN(d) {
		n++
		nEQ2 = float64(d * float64(distEQ2/maxEQ2))
	}
	if d := value - lowerEQ3EQ6; !math.IsNaN(d) {
		n++
		nEQ3EQ6 = float64(d * float64(distEQ3EQ6/maxEQ3EQ6))
	}
	if d := value - lowerEQ4; !math.IsNaN(d) {
		n++
		nEQ4 = float64(d * float64(distEQ4/maxEQ4))
	}
	if d := value - lowerEQ5; !math.IsNaN(d) {
		// EQ5 has no depth: its proportion is always 0.
		n++
		nEQ5 = float64(d * 0)
	}

	// 2. Mean of the proportional distances; 3. subtract and round.
	mean := 0.0
	if n > 0 {
		mean = (nEQ1 + nEQ2 + nEQ3EQ6 + nEQ4 + nEQ5) / float64(n)
	}
	value -= mean
	if value < 0 {
		value = 0
	}
	if value > 10 {
		value = 10
	}
	return math.Round(value*10) / 10
}

// parseMaxVector splits a composed "K:V/K:V/" string from cvss4MaxComposed.
func parseMaxVector(s string) map[string]string {
	out := map[string]string{}
	for _, p := range strings.Split(strings.TrimSuffix(s, "/"), "/") {
		k, val, _ := strings.Cut(p, ":")
		out[k] = val
	}
	return out
}
