package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// The digest queries read only the public catalogues: KEV additions in a
// date range with their EPSS, and cycles whose security support ends in one.
func TestDigestQueries(t *testing.T) {
	ctx := tenant.System(context.Background())
	s := store.New(testdb.New(t))
	day := func(d string) time.Time {
		v, err := time.Parse(time.DateOnly, d)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	ptr := func(d string) *time.Time { v := day(d); return &v }
	if err := s.ReplaceKnownExploited(ctx, [][]any{
		{"CVE-2026-0001", "Acme", "Gateway", "Acme Gateway RCE", ptr("2026-10-18"), ptr("2026-11-08"), false, "before the week"},
		{"CVE-2026-0002", "Acme", "Gateway", "Acme Gateway SQLi", ptr("2026-10-19"), ptr("2026-11-09"), true, "Acme Gateway contains SQL injection."},
		{"CVE-2026-0003", "Beta", "Server", "Beta Server SSRF", ptr("2026-10-25"), nil, false, ""},
		{"CVE-2026-0004", "Beta", "Server", "after the week", ptr("2026-10-26"), ptr("2026-11-16"), false, ""},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO epss_scores (cve, score, percentile, model_version, score_date)
		VALUES ('CVE-2026-0002', 0.25, 0.97, 'v2025.03.14', '2026-10-28')`); err != nil {
		t.Fatal(err)
	}
	adds, err := s.KEVAddedBetween(ctx, day("2026-10-19"), day("2026-10-25"))
	if err != nil {
		t.Fatal(err)
	}
	if len(adds) != 2 || adds[0].CVE != "CVE-2026-0002" || adds[1].CVE != "CVE-2026-0003" {
		t.Fatalf("additions: %+v", adds)
	}
	a := adds[0]
	if a.ShortDescription != "Acme Gateway contains SQL injection." || !a.Ransomware || a.DueDate == nil || !a.DueDate.Equal(day("2026-11-09")) ||
		a.EPSS == nil || a.EPSS.Score != 0.25 || a.EPSS.Percentile != 0.97 || !a.EPSS.Date.Equal(day("2026-10-28")) {
		t.Errorf("first addition: %+v epss %+v", a, a.EPSS)
	}
	if adds[1].EPSS != nil || adds[1].DueDate != nil {
		t.Errorf("no EPSS or due date: %+v", adds[1])
	}

	if err := s.ReplaceLifecycle(ctx, [][]any{
		{"postgresql", "PostgreSQL", []string{"pkg:generic/postgresql"}, "https://endoflife.date/postgresql"},
		{"some-saas", "Some SaaS", []string{}, "https://endoflife.date/some-saas"},
	}, [][]any{
		{"postgresql", "14", "", ptr("2021-09-30"), false, nil, ptr("2026-12-20"), false, "14.19", nil},
		{"postgresql", "15", "", ptr("2022-10-13"), false, nil, ptr("2027-11-11"), false, "15.14", nil},
		{"some-saas", "1", "", nil, false, nil, ptr("2026-12-21"), false, "", nil},
	}); err != nil {
		t.Fatal(err)
	}
	ends, err := s.LifecycleEndingBetween(ctx, day("2026-12-14"), day("2026-12-27"), true, 10)
	if err != nil || len(ends) != 1 || ends[0].ProductLabel != "PostgreSQL" || ends[0].Cycle != "14" || !ends[0].EOL.Equal(day("2026-12-20")) {
		t.Fatalf("ending with packages: %v %+v", err, ends)
	}
	if all, err := s.LifecycleEndingBetween(ctx, day("2026-12-14"), day("2026-12-27"), false, 10); err != nil || len(all) != 2 {
		t.Fatalf("ending, all products: %v %+v", err, all)
	}
	if one, err := s.LifecycleEndingBetween(ctx, day("2026-12-14"), day("2026-12-27"), false, 1); err != nil || len(one) != 1 {
		t.Fatalf("limit: %v %+v", err, one)
	}
}
