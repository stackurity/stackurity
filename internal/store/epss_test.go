package store_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

func setEPSS(t *testing.T, s *store.Store, day string, scores map[string]float32) {
	t.Helper()
	date, _ := time.Parse("2006-01-02", day)
	var rows []store.EPSSRow
	for cve, v := range scores {
		rows = append(rows, store.EPSSRow{CVE: cve, Score: v, Percentile: 0.5})
	}
	i := 0
	if _, err := s.ReplaceEPSS(tenant.System(context.Background()), "v2026.06.15", date, func() (*store.EPSSRow, error) {
		if i == len(rows) {
			return nil, nil
		}
		i++
		return &rows[i-1], nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Prioritisation reads each finding's EPSS directly. A finding gets the EPSS
// factor when its score reaches the threshold and keeps it while the score
// moves within the band below, without its row being rewritten; it loses
// it only when the score falls below the band. KEV findings never get it.
func TestPrioritizeEPSSHysteresis(t *testing.T) {
	ctx, s, _ := riskFixture(t)
	p := risk.DefaultPolicy()
	type state struct {
		factors []string
		xmin    string
	}
	read := func(key string) state {
		t.Helper()
		var raw, xmin string
		if err := s.Pool.QueryRow(ctx, `SELECT priority_factors::text, xmin::text FROM findings WHERE key = $1`, key).Scan(&raw, &xmin); err != nil {
			t.Fatal(err)
		}
		return state{factorNames(t, raw), xmin}
	}
	day := func(d string, nofix float32) state {
		t.Helper()
		setEPSS(t, s, d, map[string]float32{"CVE-NOFIX": nofix, "CVE-KEV": 0.9})
		if _, err := s.Prioritize(ctx, p, time.Now()); err != nil {
			t.Fatal(err)
		}
		return read("CVE-NOFIX")
	}
	if st := day("2026-10-01", 0.05); slices.Contains(st.factors, risk.FactorEPSS) {
		t.Fatalf("below the threshold: %v", st.factors)
	}
	crossed := day("2026-10-02", 0.12)
	if !slices.Contains(crossed.factors, risk.FactorEPSS) {
		t.Fatalf("above the threshold: %v", crossed.factors)
	}
	for i, v := range []float32{0.095, 0.11, 0.081} {
		st := day("2026-10-0"+string(rune('3'+i)), v)
		if !slices.Contains(st.factors, risk.FactorEPSS) || st.xmin != crossed.xmin {
			t.Errorf("EPSS %.3f within the band: factors %v, row rewritten %v", v, st.factors, st.xmin != crossed.xmin)
		}
	}
	if st := day("2026-10-06", 0.07); slices.Contains(st.factors, risk.FactorEPSS) {
		t.Errorf("below the band: %v", st.factors)
	}
	if st := read("CVE-KEV"); slices.Contains(st.factors, risk.FactorEPSS) {
		t.Errorf("KEV finding has the EPSS factor: %v", st.factors)
	}

	// The findings list shows the current score and filters on it.
	fs, total, err := s.ListFindings(ctx, store.FindingFilter{EPSSMin: 0.5})
	if err != nil || total != 1 || len(fs) != 1 || fs[0].Key != "CVE-KEV" {
		t.Fatalf("epss >= 0.5: %d %v", total, err)
	}
	f := fs[0]
	if f.EPSS == nil || *f.EPSS != 0.9 || f.EPSSPercentile == nil || *f.EPSSPercentile != 0.5 || f.EPSSModel == nil ||
		*f.EPSSModel != "v2026.06.15" || f.EPSSDate == nil || f.EPSSDate.Format("2006-01-02") != "2026-10-06" {
		t.Errorf("EPSS fields: %v %v %v %v", f.EPSS, f.EPSSPercentile, f.EPSSModel, f.EPSSDate)
	}
	if _, total, _ := s.ListFindings(ctx, store.FindingFilter{EPSSMin: 0.05}); total != 2 {
		t.Errorf("epss >= 0.05: %d findings, want 2", total)
	}
	g, err := s.GetFinding(ctx, f.ID)
	if err != nil || g.EPSS == nil || *g.EPSS != 0.9 {
		t.Errorf("GetFinding EPSS: %+v %v", g, err)
	}
	all, _, _ := s.ListFindings(ctx, store.FindingFilter{})
	for _, f := range all {
		if f.Key == "CVE-PRO" && f.EPSS != nil {
			t.Errorf("a CVE without a score has EPSS %v", *f.EPSS)
		}
	}
}
