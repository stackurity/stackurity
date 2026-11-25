package sitecheck

import (
	"encoding/json"
	"strings"
	"testing"
)

func allHeaders(present bool) []HeaderCheck {
	return []HeaderCheck{{Name: "Strict-Transport-Security", Present: present}, {Name: "Content-Security-Policy", Present: present},
		{Name: "X-Content-Type-Options", Present: present}, {Name: "X-Frame-Options", Present: present}, {Name: "Referrer-Policy", Present: present}}
}

func TestGrade(t *testing.T) {
	tls := &TLSInfo{Version: "1.3", DaysLeft: 60}
	for _, tc := range []struct {
		name   string
		r      Report
		letter string
		score  int
	}{
		{"clean https site", Report{TLS: tls, Headers: allHeaders(true)}, "A", 100},
		{"headers missing cost at most 8", Report{TLS: tls, Headers: allHeaders(false)}, "A", 92},
		{"plain http is high: C at best", Report{Headers: allHeaders(true)}, "C", 85},
		{"one medium finding", Report{TLS: tls, Headers: allHeaders(true), Findings: []Finding{{Title: "TLS 1.0 and 1.1 accepted", Severity: "medium"}}}, "A", 94},
		{"known exploited counts as critical: D at best", Report{TLS: tls, Headers: allHeaders(true),
			Software: []Software{{Name: "jQuery", Version: "1.12.4", Issues: []Issue{{ID: "CVE-1", Severity: "medium", KnownExploited: true}, {ID: "CVE-2", Severity: "low"}}}}}, "D", 70},
		{"one entry per library, at its worst issue", Report{TLS: tls, Headers: allHeaders(true),
			Software: []Software{{Name: "Bootstrap", Version: "3.3.7", Issues: []Issue{{ID: "a", Severity: "medium"}, {ID: "b", Severity: "medium"}, {ID: "c", Severity: "low"}}}}}, "A", 94},
		{"end of life is medium", Report{TLS: tls, Headers: allHeaders(true),
			Software: []Software{{Name: "PHP", Version: "7.4.33", EndOfLife: &EOL{Ended: true}}}}, "A", 94},
		{"many problems reach F, never below 0", Report{Headers: allHeaders(false), Findings: []Finding{
			{Title: "a", Severity: "critical"}, {Title: "b", Severity: "critical"}, {Title: "c", Severity: "critical"}, {Title: "d", Severity: "high"}}}, "F", 0},
		{"certificate about to expire", Report{TLS: &TLSInfo{DaysLeft: 3}, Headers: allHeaders(true)}, "A", 94},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := grade(&tc.r)
			if g.Letter != tc.letter || g.Score != tc.score {
				t.Errorf("got %s %d, want %s %d; deductions %+v", g.Letter, g.Score, tc.letter, tc.score, g.Deductions)
			}
			sum := 0
			for i, d := range g.Deductions {
				sum += d.Points
				if i > 0 && d.Points > g.Deductions[i-1].Points {
					t.Errorf("deductions not most points first: %+v", g.Deductions)
				}
			}
			if max(100-sum, 0) != g.Score {
				t.Errorf("deductions add up to %d, score is %d", sum, g.Score)
			}
		})
	}
}

func TestGradeExplainsItself(t *testing.T) {
	g := grade(&Report{TLS: &TLSInfo{DaysLeft: 60}, Headers: allHeaders(true),
		Software: []Software{{Name: "jQuery", Version: "1.12.4", Issues: []Issue{{ID: "CVE-1", Severity: "high", KnownExploited: true}, {ID: "CVE-2", Severity: "medium"}}}}})
	if len(g.Deductions) != 1 || !strings.Contains(g.Deductions[0].What, "jQuery 1.12.4 has 2 known vulnerabilities, 1 exploited in the wild") {
		t.Errorf("deductions: %+v", g.Deductions)
	}
}

// The anonymous teaser never carries the grade: it comes with an account.
func TestTeaserHasNoGrade(t *testing.T) {
	r := &Report{TLS: &TLSInfo{DaysLeft: 60}}
	r.Grade = grade(r)
	b, _ := json.Marshal(r.Teaser())
	if strings.Contains(string(b), "grade") {
		t.Errorf("teaser carries the grade: %s", b)
	}
}
