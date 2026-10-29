package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// aliasFixture stores three advisories and one finding for each, as the
// matcher would: an RHSA fixing three CVEs listed as upstream ids (keyed by
// the lowest), a GHSA whose CVE is an alias, and a GHSA with no CVE.
func aliasFixture(t *testing.T) (context.Context, *store.Store) {
	t.Helper()
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	sys := tenant.System(context.Background())
	mod := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for feed, vs := range map[string][]*osv.Vulnerability{
		"osv:Red Hat": {{ID: "RHSA-2024:0001", Upstream: []string{"CVE-2024-1002", "CVE-2024-1000", "CVE-2024-1001"}, Modified: mod}},
		"osv:PyPI": {
			{ID: "GHSA-alia-sxxx-xxxx", Aliases: []string{"PYSEC-2024-1", "CVE-2024-2000"}, Modified: mod},
			{ID: "GHSA-none-xxxx-xxxx", Aliases: []string{"PYSEC-2024-2"}, Modified: mod},
		},
	} {
		if err := s.EnsureFeed(sys, feed, "vulnerability", time.Hour, 6*time.Hour); err != nil {
			t.Fatal(err)
		}
		if _, err := s.UpsertAdvisories(sys, feed, vs); err != nil {
			t.Fatal(err)
		}
	}
	host := ingestHost(t, s, ctx, "app-1", "pkg:rpm/redhat/openssl@3.0.7-1.el9", "pkg:pypi/django@4.2.0", "pkg:pypi/flask@2.0.0")
	rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: host})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	var in []store.FindingInput
	for _, r := range rows {
		ids = append(ids, r.ID)
		key, src := "", ""
		switch r.Name {
		case "openssl":
			key, src = "CVE-2024-1000", "RHSA-2024:0001"
		case "django":
			key, src = osv.GroupKey("GHSA-alia-sxxx-xxxx", []string{"PYSEC-2024-1", "CVE-2024-2000"}), "GHSA-alia-sxxx-xxxx"
		case "flask":
			key, src = "GHSA-none-xxxx-xxxx", "GHSA-none-xxxx-xxxx"
		}
		in = append(in, store.FindingInput{Kind: "vulnerability", Key: key, InventoryID: r.ID, AssetID: host, ComponentID: r.ComponentID,
			Verification: "confirmed", Severity: "high", Title: key, Sources: []string{src}, Evidence: map[string]any{}})
	}
	if _, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, ids, in); err != nil {
		t.Fatal(err)
	}
	return ctx, s
}

// The advisory's upstream ids are stored, and storing the same record again
// writes nothing.
func TestAdvisoryUpstreamStored(t *testing.T) {
	_, s := aliasFixture(t)
	sys := tenant.System(context.Background())
	var up []string
	if err := s.Pool.QueryRow(sys, `SELECT upstream FROM advisories WHERE id = 'RHSA-2024:0001'`).Scan(&up); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(up, []string{"CVE-2024-1002", "CVE-2024-1000", "CVE-2024-1001"}) {
		t.Errorf("upstream stored as %v", up)
	}
	n, err := s.UpsertAdvisories(sys, "osv:Red Hat", []*osv.Vulnerability{{ID: "RHSA-2024:0001",
		Upstream: []string{"CVE-2024-1002", "CVE-2024-1000", "CVE-2024-1001"}, Modified: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}})
	if err != nil || n != 0 {
		t.Errorf("same record stored again: %d changed, %v", n, err)
	}
	n, err = s.UpsertAdvisories(sys, "osv:Red Hat", []*osv.Vulnerability{{ID: "RHSA-2024:0001",
		Upstream: []string{"CVE-2024-1000", "CVE-2024-1001"}, Modified: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}})
	if err != nil || n != 1 {
		t.Errorf("record with an upstream id fewer: %d changed, %v", n, err)
	}
}

// A finding's EPSS is the highest among all its CVEs: its key and the CVEs
// its advisories list as aliases or upstream ids. The finding stores which
// CVE (epss_cve, NULL for its key) and reads that CVE's score, so a daily
// score change rewrites nothing; it moves to another CVE only when that one
// scores more than a tenth higher, or is on the other side of the threshold.
// The factor's text names no CVE, and the hysteresis applies to the score
// in use.
func TestPrioritizeEPSSThroughAliases(t *testing.T) {
	ctx, s := aliasFixture(t)
	p := risk.DefaultPolicy()
	type state struct {
		epss    *float32
		cve     string
		stored  *string
		factors []string
		detail  string
		xmin    string
	}
	read := func(key string) state {
		t.Helper()
		fs, _, err := s.ListFindings(ctx, store.FindingFilter{Key: key})
		if err != nil || len(fs) != 1 {
			t.Fatalf("finding %s: %d %v", key, len(fs), err)
		}
		f := fs[0]
		st := state{epss: f.EPSS, factors: factorNames(t, string(f.PriorityFactors))}
		if f.EPSSCVE != nil {
			st.cve = *f.EPSSCVE
		}
		var fsx []risk.Factor
		_ = json.Unmarshal(f.PriorityFactors, &fsx)
		for _, x := range fsx {
			if x.Name == risk.FactorEPSS {
				st.detail = x.Detail
			}
		}
		if err := s.Pool.QueryRow(ctx, `SELECT epss_cve, xmin::text FROM findings WHERE id = $1`, f.ID).Scan(&st.stored, &st.xmin); err != nil {
			t.Fatal(err)
		}
		return st
	}
	day := func(d string, scores map[string]float32) state {
		t.Helper()
		setEPSS(t, s, d, scores)
		if _, err := s.Prioritize(ctx, p, time.Now()); err != nil {
			t.Fatal(err)
		}
		return read("CVE-2024-1000")
	}
	rhsa := func(k, a, b float32) map[string]float32 {
		return map[string]float32{"CVE-2024-1000": k, "CVE-2024-1001": a, "CVE-2024-1002": b, "CVE-2024-2000": 0.3}
	}

	// The key's own score is low; another upstream CVE of the RHSA is high.
	rh := day("2026-10-01", rhsa(0.01, 0.5, 0.2))
	if rh.epss == nil || *rh.epss != 0.5 || rh.cve != "CVE-2024-1001" || rh.stored == nil || *rh.stored != "CVE-2024-1001" ||
		!slices.Contains(rh.factors, risk.FactorEPSS) {
		t.Fatalf("RHSA finding: epss %v from %q (stored %v), factors %v", rh.epss, rh.cve, rh.stored, rh.factors)
	}
	if strings.Contains(rh.detail, "CVE-") {
		t.Errorf("the factor's text names a CVE: %q", rh.detail)
	}
	// A GHSA keyed by its CVE alias, and one with no CVE at all.
	if gh := read("CVE-2024-2000"); gh.epss == nil || *gh.epss != 0.3 || gh.cve != "CVE-2024-2000" || gh.stored != nil ||
		!slices.Contains(gh.factors, risk.FactorEPSS) {
		t.Errorf("GHSA with a CVE alias: epss %v from %q (stored %v), factors %v", gh.epss, gh.cve, gh.stored, gh.factors)
	}
	if none := read("GHSA-none-xxxx-xxxx"); none.epss != nil || none.cve != "" || none.stored != nil {
		t.Errorf("GHSA without a CVE: %+v", none)
	}

	// Daily moves: the scores change and another CVE overtakes the one in
	// use by less than a tenth. Nothing is rewritten; the score shown is the
	// day's score of the CVE in use.
	for i, sc := range [][3]float32{{0.01, 0.48, 0.2}, {0.02, 0.5, 0.53}, {0.01, 0.51, 0.55}} {
		st := day(fmt.Sprintf("2026-10-0%d", i+2), rhsa(sc[0], sc[1], sc[2]))
		if st.cve != "CVE-2024-1001" || *st.epss != sc[1] || st.xmin != rh.xmin {
			t.Errorf("day %d: EPSS %v from %q, rewritten %v", i+2, *st.epss, st.cve, st.xmin != rh.xmin)
		}
	}
	// Overtaken by more than a tenth: it moves, and only epss_cve changes.
	moved := day("2026-10-05", rhsa(0.01, 0.4, 0.6))
	if moved.cve != "CVE-2024-1002" || *moved.stored != "CVE-2024-1002" || !slices.Equal(moved.factors, rh.factors) {
		t.Errorf("overtaken: EPSS from %q, factors %v", moved.cve, moved.factors)
	}
	// Within the hysteresis band: the factor is kept with the score in use.
	band := day("2026-10-06", rhsa(0.085, 0.05, 0.02))
	if band.cve != "CVE-2024-1000" || band.stored != nil || !slices.Contains(band.factors, risk.FactorEPSS) {
		t.Errorf("in the band: from %q (stored %v), factors %v", band.cve, band.stored, band.factors)
	}
	if st := day("2026-10-07", rhsa(0.07, 0.05, 0.02)); slices.Contains(st.factors, risk.FactorEPSS) {
		t.Errorf("below the band still counts: %v", st.factors)
	}
	// Never kept across the threshold: the key at 9.5% is within a tenth of
	// another CVE at 10.2%, but that one counts and the key does not.
	if st := day("2026-10-08", rhsa(0.095, 0.102, 0.02)); st.cve != "CVE-2024-1001" || !slices.Contains(st.factors, risk.FactorEPSS) {
		t.Errorf("across the threshold: from %q, factors %v", st.cve, st.factors)
	}
	// Equal scores: the CVE in use is kept.
	if st := day("2026-10-09", rhsa(0.3, 0.3, 0.3)); st.cve != "CVE-2024-1001" {
		t.Errorf("equal scores: moved to %q", st.cve)
	}

	// The filter uses the score in use, in the count and the list.
	setEPSS(t, s, "2026-10-10", rhsa(0.01, 0.2, 0.05))
	if _, err := s.Prioritize(ctx, p, time.Now()); err != nil {
		t.Fatal(err)
	}
	fs, total, err := s.ListFindings(ctx, store.FindingFilter{EPSSMin: 0.25})
	if err != nil || total != 1 || len(fs) != 1 || fs[0].Key != "CVE-2024-2000" {
		t.Errorf("epss_min 0.25: %d findings, %d listed, %v", total, len(fs), err)
	}
	fs, total, err = s.ListFindings(ctx, store.FindingFilter{EPSSMin: 0.15})
	if err != nil || total != 2 || len(fs) != 2 {
		t.Errorf("epss_min 0.15: %d findings, %d listed, %v", total, len(fs), err)
	}
	rhf, _, err := s.ListFindings(ctx, store.FindingFilter{Key: "CVE-2024-1000"})
	if err != nil || len(rhf) != 1 {
		t.Fatalf("RHSA finding: %v", err)
	}
	g, err := s.GetFinding(ctx, rhf[0].ID)
	if err != nil || g.EPSSCVE == nil || *g.EPSSCVE != "CVE-2024-1001" || g.EPSS == nil || *g.EPSS != 0.2 {
		t.Errorf("GetFinding: %v %v", g, err)
	}
	// The policy preview chooses as a pass does.
	pv, err := s.PreviewRiskPolicy(ctx, p, p, time.Now())
	if err != nil || pv.StoredDiffers != 0 {
		t.Errorf("preview: %d stored priorities differ, %v", pv.StoredDiffers, err)
	}
}
