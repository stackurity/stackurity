package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// A CVE's first-seen time is written by the first EPSS file or KEV catalogue
// that has it, and never changed: not by later files, nor by a CVE leaving
// and coming back. Advisory feeds, which follow the workspaces' inventories,
// never write it.
func TestCVEFirstSeen(t *testing.T) {
	ctx := tenant.System(context.Background())
	s := store.New(testdb.New(t))
	kev := func(cves ...string) {
		t.Helper()
		var rows [][]any
		for _, c := range cves {
			rows = append(rows, []any{c, "v", "p", "n", time.Now(), time.Now(), false, "d"})
		}
		if err := s.ReplaceKnownExploited(ctx, rows); err != nil {
			t.Fatal(err)
		}
	}
	at := func(cve string) store.CVEFirstSeen {
		t.Helper()
		got, err := s.CVEsFirstSeen(ctx, []string{cve})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("%s: %d rows", cve, len(got))
		}
		return got[0]
	}

	setEPSS(t, s, "2026-10-30", map[string]float32{"CVE-2024-0001": 0.1, "CVE-2024-0002": 0.2})
	first := at("CVE-2024-0001")
	if first.Source != "epss" || !first.Exact || time.Since(first.At) > time.Minute {
		t.Fatalf("first EPSS file: %+v", first)
	}

	// KEV a moment later: the EPSS time stays; a CVE only KEV has gets KEV's.
	time.Sleep(10 * time.Millisecond)
	kev("CVE-2024-0001", "CVE-2024-0003")
	if got := at("CVE-2024-0001"); !got.At.Equal(first.At) || got.Source != "epss" {
		t.Errorf("KEV rewrote an earlier time: %+v, was %+v", got, first)
	}
	if got := at("CVE-2024-0003"); got.Source != "kev" {
		t.Errorf("KEV-only CVE: %+v", got)
	}

	// The next day's file without CVE-2024-0002, then with it again.
	setEPSS(t, s, "2026-10-31", map[string]float32{"CVE-2024-0001": 0.3})
	two := at("CVE-2024-0002")
	setEPSS(t, s, "2026-11-01", map[string]float32{"CVE-2024-0002": 0.3, "CVE-2024-0004": 0.1})
	if got := at("CVE-2024-0002"); !got.At.Equal(two.At) {
		t.Errorf("a CVE coming back got a new time: %v, was %v", got.At, two.At)
	}

	// An advisory naming a CVE nothing else has does not record it.
	if err := s.EnsureFeed(ctx, "osv:npm", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertAdvisories(ctx, "osv:npm", []*osv.Vulnerability{
		{ID: "GHSA-zzzz", Aliases: []string{"CVE-2024-0099"}, Modified: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.CVEsFirstSeen(ctx, []string{"CVE-2024-0099"}); err != nil || len(got) != 0 {
		t.Errorf("an advisory feed recorded a CVE: %+v, %v", got, err)
	}

	// Newest first, paged with before.
	recent, err := s.RecentCVEs(ctx, time.Time{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 2 || recent[0].CVE != "CVE-2024-0004" {
		t.Fatalf("recent %+v", recent)
	}
	older, err := s.RecentCVEs(ctx, recent[1].At, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range older {
		if !o.At.Before(recent[1].At) {
			t.Errorf("page before %v has %+v", recent[1].At, o)
		}
	}
	if since, err := s.CVETrackingSince(ctx); err != nil || !since.IsZero() {
		t.Errorf("nothing was backfilled, tracking since %v, %v", since, err)
	}
}

// CVEs stored before migration 0068 are marked backfilled: listed by ID
// lookups as "on or before", never in the recent log.
func TestCVEFirstSeenBackfilled(t *testing.T) {
	ctx := tenant.System(context.Background())
	s := store.New(testdb.New(t))
	mark := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	if _, err := s.Pool.Exec(ctx, `INSERT INTO cve_first_seen (cve, first_seen, source, backfilled) VALUES ('CVE-2021-44228', $1, 'kev', true)`, mark); err != nil {
		t.Fatal(err)
	}
	setEPSS(t, s, "2026-11-03", map[string]float32{"CVE-2021-44228": 0.9, "CVE-2026-0001": 0.1})
	got, err := s.CVEsFirstSeen(ctx, []string{"CVE-2021-44228"})
	if err != nil || len(got) != 1 || got[0].Exact || !got[0].At.Equal(mark) {
		t.Fatalf("backfilled row: %+v, %v", got, err)
	}
	recent, err := s.RecentCVEs(ctx, time.Time{}, 10)
	if err != nil || len(recent) != 1 || recent[0].CVE != "CVE-2026-0001" {
		t.Fatalf("recent must hold exact times only: %+v, %v", recent, err)
	}
	if since, err := s.CVETrackingSince(ctx); err != nil || !since.Equal(mark) {
		t.Errorf("tracking since %v, want %v (%v)", since, mark, err)
	}
}
