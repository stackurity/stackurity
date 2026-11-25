package sitecheck

import (
	"fmt"
	"sort"
	"strings"
)

// Grade sums a report up as a letter from A to F, with the score it comes
// from and every deduction behind it, so the letter can always be explained.
type Grade struct {
	Letter string `json:"letter"`
	// Score starts at 100 and loses points for each problem (never below 0).
	Score int `json:"score"`
	// Deductions are the problems that cost points, most points first.
	Deductions []Deduction `json:"deductions"`
}

// Deduction is one problem and the points it cost.
type Deduction struct {
	What     string `json:"what"`
	Severity string `json:"severity"`
	Points   int    `json:"points"`
}

// Points per problem by severity. Each piece of software counts once, at
// its worst issue, so a library with twenty advisories does not sink the
// grade on its own more than one critical problem does.
var gradePoints = map[string]int{"critical": 30, "high": 15, "medium": 6, "low": 2}

// Missing browser protection headers together cost at most this much.
const headerPointsCap = 8

// grade scores r. A critical problem (or a known-exploited vulnerability)
// keeps the grade at D or below, a high one at C or below, whatever the
// score: a site with an exploitable flaw is never graded B because the rest
// of it is fine.
func grade(r *Report) *Grade {
	g := &Grade{Score: 100, Deductions: []Deduction{}}
	add := func(what, severity string) {
		severity = strings.ToLower(severity)
		p := gradePoints[severity]
		if p == 0 {
			return
		}
		g.Deductions = append(g.Deductions, Deduction{What: what, Severity: severity, Points: p})
	}

	for _, sw := range r.Software {
		name := strings.TrimSpace(sw.Name + " " + sw.Version)
		if len(sw.Issues) > 0 {
			worst := sw.Issues[0] // sorted worst first
			severity := strings.ToLower(worst.Severity)
			if _, ok := gradePoints[severity]; !ok {
				severity = "medium" // an advisory without a rating still counts
			}
			what := fmt.Sprintf("%s has %s", name, pluralise(len(sw.Issues), "known vulnerability", "known vulnerabilities"))
			if kev := countExploited(sw.Issues); kev > 0 {
				severity = "critical"
				what += fmt.Sprintf(", %d exploited in the wild", kev)
			}
			add(what, severity)
		}
		if sw.EndOfLife != nil && sw.EndOfLife.Ended {
			add(name+" no longer gets security fixes (end of life)", "medium")
		}
	}

	for _, f := range r.Findings {
		add(f.Title, f.Severity)
	}

	if r.TLS == nil {
		add("The page is served over plain http, without encryption", "high")
	} else if r.TLS.DaysLeft < 14 {
		add(fmt.Sprintf("The TLS certificate expires in %s", pluralise(max(r.TLS.DaysLeft, 0), "day", "days")), "medium")
	}

	var missing []string
	for _, h := range r.Headers {
		if !h.Present {
			missing = append(missing, h.Name)
		}
	}
	if len(missing) > 0 {
		p := min(len(missing)*gradePoints["low"], headerPointsCap)
		g.Deductions = append(g.Deductions, Deduction{
			What:     "Browser protection headers missing: " + strings.Join(missing, ", "),
			Severity: "low", Points: p,
		})
	}

	worst := 4
	for _, d := range g.Deductions {
		g.Score -= d.Points
		worst = min(worst, rank(d.Severity))
	}
	g.Score = max(g.Score, 0)
	sort.SliceStable(g.Deductions, func(i, j int) bool { return g.Deductions[i].Points > g.Deductions[j].Points })

	switch {
	case g.Score >= 90:
		g.Letter = "A"
	case g.Score >= 80:
		g.Letter = "B"
	case g.Score >= 65:
		g.Letter = "C"
	case g.Score >= 50:
		g.Letter = "D"
	default:
		g.Letter = "F"
	}
	// Letters compare in order: "A" < "B" < ... < "F".
	if worst == 0 && g.Letter < "D" {
		g.Letter = "D"
	}
	if worst == 1 && g.Letter < "C" {
		g.Letter = "C"
	}
	return g
}

func countExploited(is []Issue) int {
	n := 0
	for _, i := range is {
		if i.KnownExploited {
			n++
		}
	}
	return n
}

func pluralise(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
