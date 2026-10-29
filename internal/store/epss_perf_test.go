package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
)

// TestPrioritizeEPSSPerformance seeds a workspace the size of production
// (seedPerf: STACKURITY_PERF_FINDINGS open findings, e.g. 130000, on 2,000
// hosts, 3,000 distinct CVEs, each advisory with a second CVE as an alias)
// and times the prioritisation pass the dispatcher runs every minute,
// without EPSS data and with a full EPSS file (400,000 CVEs), and the first
// pass after each daily file, with how many findings it rewrote: after the
// first file the findings that crossed the threshold, after days of small
// moves only those that crossed it for real. It also times the findings list
// with the EPSS join and filter. Run it with -v to see the numbers; it fails
// only when EPSS doubles the pass, or a list takes a second or more.
//
//	STACKURITY_PERF_FINDINGS=130000 go test ./internal/store -run TestPrioritizeEPSSPerformance -v
func TestPrioritizeEPSSPerformance(t *testing.T) {
	d := seedPerf(t, perfFindings(t))
	ctx := context.Background()
	p := risk.DefaultPolicy()
	// pass runs the dispatcher's full prioritisation once and says how many
	// findings it wrote.
	pass := func() (time.Duration, int) {
		t.Helper()
		var took time.Duration
		w := d.written(t, func() {
			s := time.Now()
			if _, err := d.st.Prioritize(d.ws, p, time.Now()); err != nil {
				t.Fatal(err)
			}
			took = time.Since(s)
		})
		return took, w
	}
	// steady times passes that change nothing, and the read-and-score part
	// alone (the policy preview reads and scores exactly what a pass does).
	steady := func(label string) (time.Duration, time.Duration) {
		t.Helper()
		var full, read []time.Duration
		for i := 0; i < 5; i++ {
			took, _ := pass()
			full = append(full, took)
			s := time.Now()
			if _, err := d.st.PreviewRiskPolicy(d.ws, p, p, time.Now()); err != nil {
				t.Fatal(err)
			}
			read = append(read, time.Since(s))
		}
		t.Logf("%-52s pass %7.0f ms, of which read and score %6.0f ms", label, ms(median(full)), ms(median(read)))
		return median(full), median(read)
	}
	day := func(date string, shift float64) {
		t.Helper()
		d.loadEPSS(t, date, shift)
		took, written := pass()
		t.Logf("%-52s first pass %7.0f ms, %6d findings written", "EPSS of "+date+fmt.Sprintf(" (shift %+.3f)", shift), ms(took), written)
	}
	var total int
	_ = d.owner.QueryRow(ctx, `SELECT count(*) FROM findings WHERE status = 'open'`).Scan(&total)
	t.Logf("%d open findings", total)

	pass() // the first pass scores the seeded findings
	withoutFull, withoutRead := steady("no EPSS data, steady")
	day("2026-10-28", 0)
	steady("EPSS loaded, steady")
	day("2026-10-29", 0.004)
	day("2026-10-30", -0.004)
	day("2026-10-31", 0.003)
	withFull, withRead := steady("after three days of small moves, steady")
	var counted int
	_ = d.owner.QueryRow(ctx, `SELECT count(*) FROM findings WHERE priority_factors @> '[{"name": "`+risk.FactorEPSS+`"}]'`).Scan(&counted)
	t.Logf("%d findings have the EPSS factor", counted)
	if withRead > 2*withoutRead+100*time.Millisecond || withFull > 2*withoutFull+time.Second {
		t.Errorf("with EPSS: pass %s, read %s; without: pass %s, read %s", withFull, withRead, withoutFull, withoutRead)
	}

	for _, c := range []struct {
		name string
		f    store.FindingFilter
	}{
		{"findings list (first page, EPSS joined)", store.FindingFilter{Page: store.Page{Limit: 50}}},
		{"findings list, epss_min=0.1", store.FindingFilter{EPSSMin: 0.1, Page: store.Page{Limit: 50}}},
		{"findings list, epss_min=0.9", store.FindingFilter{EPSSMin: 0.9, Page: store.Page{Limit: 50}}},
	} {
		var ds []time.Duration
		for i := 0; i < 7; i++ {
			s := time.Now()
			if _, _, err := d.st.ListFindings(d.ws, c.f); err != nil {
				t.Fatal(err)
			}
			ds = append(ds, time.Since(s))
		}
		m := median(ds)
		t.Logf("%-52s %7.1f ms", c.name, ms(m))
		if m >= time.Second {
			t.Errorf("%s: %s", c.name, m)
		}
	}
}
