package osv

import (
	"encoding/json"
	"math"
	"strings"
)

// Rating is a normalised severity.
type Rating struct {
	Level  string  `json:"level"` // critical, high, medium, low, none, unknown
	Score  float64 `json:"score,omitempty"`
	Vector string  `json:"vector,omitempty"`
	Source string  `json:"source"` // cvss_v3, cvss_v4, database, distro_urgency, none
}

func levelForScore(s float64) string {
	switch {
	case s >= 9.0:
		return "critical"
	case s >= 7.0:
		return "high"
	case s >= 4.0:
		return "medium"
	case s > 0:
		return "low"
	}
	return "none"
}

var levelRank = map[string]int{"unknown": 0, "none": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

func LevelRank(l string) int { return levelRank[l] }

// Rate derives a severity from an advisory. CVSS v3 and v4 vectors are scored
// locally; database labels (GitHub "severity", distro urgency) are also
// considered. When sources disagree the higher rating wins, and of two scores
// at the same level the higher score, because under-rating is the more
// dangerous error: upstream records sometimes carry an all-"None" v3 vector
// next to a HIGH vendor rating, and the v3 and v4 scores of one flaw often
// differ. A vector that does not parse is ignored, so the labels decide; when
// a label wins, the first v4 vector is still kept for reference.
func Rate(v *Vulnerability) Rating {
	all := append([]Severity{}, v.Severity...)
	for _, a := range v.Affected {
		all = append(all, a.Severity...)
	}
	best := Rating{Level: "unknown", Source: "none"}
	consider := func(r Rating) {
		if rb, rr := levelRank[best.Level], levelRank[r.Level]; rr > rb || (rr == rb && r.Score > best.Score) {
			best = r
		}
	}
	v4 := ""
	for _, s := range all {
		switch {
		case strings.HasPrefix(s.Type, "CVSS_V3"):
			if score, ok := CVSS3Score(s.Score); ok {
				consider(Rating{Level: levelForScore(score), Score: score, Vector: s.Score, Source: "cvss_v3"})
			}
		case s.Type == "CVSS_V4":
			if score, ok := CVSS4Score(s.Score); ok {
				consider(Rating{Level: levelForScore(score), Score: score, Vector: s.Score, Source: "cvss_v4"})
			}
			if v4 == "" {
				v4 = s.Score
			}
		}
	}
	var db struct {
		Severity string `json:"severity"`
	}
	if len(v.DatabaseSpecific) > 0 && json.Unmarshal(v.DatabaseSpecific, &db) == nil {
		if l := normaliseLabel(db.Severity); l != "" {
			consider(Rating{Level: l, Source: "database"})
		}
	}
	for _, a := range v.Affected {
		var es struct {
			Urgency  string `json:"urgency"`
			Severity string `json:"severity"`
		}
		for _, raw := range []json.RawMessage{a.EcosystemSpecific, a.DatabaseSpecific} {
			if len(raw) > 0 && json.Unmarshal(raw, &es) == nil {
				if l := normaliseLabel(es.Severity); l != "" {
					consider(Rating{Level: l, Source: "database"})
				}
				if l := normaliseLabel(es.Urgency); l != "" {
					consider(Rating{Level: l, Source: "distro_urgency"})
				}
			}
		}
	}
	if best.Vector == "" && v4 != "" {
		best.Vector = v4
	}
	return best
}

func normaliseLabel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low", "negligible", "unimportant":
		return "low"
	}
	return ""
}

// CVSS3Score computes the CVSS v3.0/3.1 base score.
func CVSS3Score(vector string) (float64, bool) {
	parts := strings.Split(vector, "/")
	if len(parts) < 9 || !strings.HasPrefix(parts[0], "CVSS:3") {
		return 0, false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return 0, false
		}
		m[k] = v
	}
	weights := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
		"AC": {"L": 0.77, "H": 0.44},
		"UI": {"N": 0.85, "R": 0.62},
		"C":  {"H": 0.56, "L": 0.22, "N": 0},
		"I":  {"H": 0.56, "L": 0.22, "N": 0},
		"A":  {"H": 0.56, "L": 0.22, "N": 0},
	}
	get := func(k string) (float64, bool) {
		w, ok := weights[k][m[k]]
		return w, ok
	}
	scope := m["S"]
	if scope != "U" && scope != "C" {
		return 0, false
	}
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = map[bool]float64{true: 0.68, false: 0.62}[scope == "C"]
	case "H":
		pr = map[bool]float64{true: 0.50, false: 0.27}[scope == "C"]
	default:
		return 0, false
	}
	av, ok1 := get("AV")
	ac, ok2 := get("AC")
	ui, ok3 := get("UI")
	c, ok4 := get("C")
	i, ok5 := get("I")
	a, ok6 := get("A")
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) {
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	exploit := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, true
	}
	if scope == "U" {
		return roundup(math.Min(impact+exploit, 10)), true
	}
	return roundup(math.Min(1.08*(impact+exploit), 10)), true
}

// roundup is the CVSS 3.1 Roundup function.
func roundup(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}
