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

// Replacing the KEV catalogue writes only the advisories whose flag changes.
func TestReplaceKnownExploitedWritesOnlyChangedFlags(t *testing.T) {
	ctx := tenant.System(context.Background())
	s := store.New(testdb.New(t))
	if err := s.EnsureFeed(ctx, "osv:npm", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	vulns := []*osv.Vulnerability{
		{ID: "GHSA-aaaa", Aliases: []string{"CVE-2024-0001"}, Modified: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		{ID: "GHSA-bbbb", Aliases: []string{"CVE-2024-0002"}, Modified: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	if _, err := s.UpsertAdvisories(ctx, "osv:npm", vulns); err != nil {
		t.Fatal(err)
	}
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
	// xmin changes whenever a row is written.
	state := func() map[string][2]string {
		t.Helper()
		rows, err := s.Pool.Query(ctx, `SELECT id, known_exploited::text, xmin::text FROM advisories`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string][2]string{}
		for rows.Next() {
			var id, ke, x string
			if err := rows.Scan(&id, &ke, &x); err != nil {
				t.Fatal(err)
			}
			out[id] = [2]string{ke, x}
		}
		return out
	}

	kev("CVE-2024-0001")
	first := state()
	if first["GHSA-aaaa"][0] != "true" || first["GHSA-bbbb"][0] != "false" {
		t.Fatalf("flags after first catalogue: %v", first)
	}
	kev("CVE-2024-0001")
	if again := state(); again["GHSA-aaaa"] != first["GHSA-aaaa"] || again["GHSA-bbbb"] != first["GHSA-bbbb"] {
		t.Fatalf("an unchanged catalogue rewrote advisories: %v then %v", first, again)
	}
	kev("CVE-2024-0002")
	moved := state()
	if moved["GHSA-aaaa"][0] != "false" || moved["GHSA-bbbb"][0] != "true" {
		t.Fatalf("flags after the catalogue changed: %v", moved)
	}
}
