package store_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stackurity/stackurity/internal/clienterrors"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func billing404(t *testing.T, browser string) clienterrors.Clean {
	t.Helper()
	c, ok := clienterrors.Check(clienterrors.Report{Source: "api", Route: "/settings/billing", Method: "GET", APIRoute: "/api/v1/billing",
		Status: 404, Code: "not_found", Name: "ApiError", Message: "not found", Version: "0.15.0", Browser: browser, PageID: "abcdefgh1234"})
	if !ok {
		t.Fatal("report refused")
	}
	return c
}

// Reports with one fingerprint add up to one row per workspace and day,
// keeping the versions and browsers seen; each workspace sees only its own
// rows, and instance administrators see the total.
func TestClientErrorsAggregateAndIsolate(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	w1, _, err := s.CreateWorkspace(bg, "One", "one", "a@example.com", "A", "pw-a-123456789")
	if err != nil {
		t.Fatal(err)
	}
	w2, _, err := s.CreateWorkspace(bg, "Two", "two", "b@example.com", "B", "pw-b-123456789")
	if err != nil {
		t.Fatal(err)
	}
	chrome, firefox := billing404(t, "Chrome 131"), billing404(t, "Firefox 140")
	if err := s.RecordClientErrors(bg, w1.ID, []clienterrors.Clean{chrome, chrome, firefox}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordClientErrors(bg, w1.ID, []clienterrors.Clean{chrome}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordClientErrors(bg, w2.ID, []clienterrors.Clean{chrome}); err != nil {
		t.Fatal(err)
	}
	// Before sign-in: no workspace.
	if err := s.RecordClientErrors(bg, 0, []clienterrors.Clean{chrome}); err != nil {
		t.Fatal(err)
	}

	count := func(ctx context.Context) (rows int, total int64) {
		t.Helper()
		if err := s.Pool.QueryRow(ctx, `SELECT count(*), COALESCE(sum(count), 0) FROM client_errors`).Scan(&rows, &total); err != nil {
			t.Fatal(err)
		}
		return
	}
	if rows, total := count(tenant.WithWorkspace(bg, w1.ID)); rows != 1 || total != 4 {
		t.Errorf("workspace one sees %d rows, %d reports; want 1 row of 4", rows, total)
	}
	if rows, total := count(tenant.WithWorkspace(bg, w2.ID)); rows != 1 || total != 1 {
		t.Errorf("workspace two sees %d rows, %d reports; want 1 row of 1", rows, total)
	}
	if rows, _ := count(bg); rows != 0 {
		t.Errorf("no scope sees %d rows", rows)
	}
	if rows, total := count(tenant.System(bg)); rows != 3 || total != 6 {
		t.Errorf("system scope sees %d rows, %d reports; want 3 rows of 6", rows, total)
	}
	var versions, browsers []string
	if err := s.Pool.QueryRow(tenant.WithWorkspace(bg, w1.ID), `SELECT versions, browsers FROM client_errors`).Scan(&versions, &browsers); err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || versions[0] != "0.15.0" || len(browsers) != 2 {
		t.Errorf("versions %v browsers %v", versions, browsers)
	}
	// A workspace cannot write another's rows.
	if _, err := s.Pool.Exec(tenant.WithWorkspace(bg, w2.ID), `INSERT INTO client_errors (workspace_id, fingerprint, kind)
		VALUES ($1, $2, 'client')`, w1.ID, chrome.Fingerprint()); err == nil {
		t.Error("workspace two wrote a row for workspace one")
	}
	// Nor read the platform's fingerprint table.
	var n int
	if err := s.Pool.QueryRow(tenant.WithWorkspace(bg, w1.ID), `SELECT count(*) FROM client_error_fingerprints`).Scan(&n); err != nil || n != 0 {
		t.Errorf("a workspace sees %d fingerprints (%v)", n, err)
	}

	sum, err := s.ClientErrorsSummary(bg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.New) != 1 || len(sum.Top) != 1 {
		t.Fatalf("summary: %+v", sum)
	}
	g := sum.Top[0]
	if g.Count != 6 || g.Workspaces != 3 || g.Route != "/settings/billing" || g.APIRoute != "/api/v1/billing" || g.Status != 404 ||
		g.Code != "not_found" || g.Fingerprint != chrome.Fingerprint() {
		t.Errorf("group: %+v", g)
	}
	var sample clienterrors.Clean
	if err := json.Unmarshal(g.Sample, &sample); err != nil || sample.Route != "/settings/billing" {
		t.Errorf("sample %s (%v)", g.Sample, err)
	}
}

// A fingerprint is new when first seen, and again only after 7 days
// without it; old reports are deleted after 90 days.
func TestClientErrorsNewAndRetention(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	sys := tenant.System(bg)
	c := billing404(t, "Chrome 131")
	if err := s.RecordClientErrors(bg, 0, []clienterrors.Clean{c}); err != nil {
		t.Fatal(err)
	}
	newCount := func() int {
		t.Helper()
		now, _ := s.DBNow(sys)
		g, err := s.NewClientErrors(bg, now.Add(-24*60*60*1e9))
		if err != nil {
			t.Fatal(err)
		}
		return len(g)
	}
	if n := newCount(); n != 1 {
		t.Fatalf("%d new after the first report", n)
	}
	// Seen two days ago and since: not new.
	if _, err := s.Pool.Exec(sys, `UPDATE client_error_fingerprints SET new_since = now() - interval '2 days', first_seen = now() - interval '2 days'`); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordClientErrors(bg, 0, []clienterrors.Clean{c}); err != nil {
		t.Fatal(err)
	}
	if n := newCount(); n != 0 {
		t.Errorf("%d new for an error seen all along", n)
	}
	// Not seen for 8 days: new again.
	if _, err := s.Pool.Exec(sys, `UPDATE client_error_fingerprints SET last_seen = now() - interval '8 days', new_since = now() - interval '30 days'`); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordClientErrors(bg, 0, []clienterrors.Clean{c}); err != nil {
		t.Fatal(err)
	}
	if n := newCount(); n != 1 {
		t.Errorf("%d new after 8 days without it", n)
	}

	if _, err := s.Pool.Exec(sys, `UPDATE client_errors SET day = day - 91`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(sys, `UPDATE client_error_fingerprints SET last_seen = now() - interval '91 days'`); err != nil {
		t.Fatal(err)
	}
	if n, err := s.PurgeClientErrors(bg); err != nil || n != 1 {
		t.Errorf("purged %d (%v), want 1", n, err)
	}
	var left int
	if err := s.Pool.QueryRow(sys, `SELECT (SELECT count(*) FROM client_errors) + (SELECT count(*) FROM client_error_fingerprints)`).Scan(&left); err != nil || left != 0 {
		t.Errorf("%d rows left after the purge (%v)", left, err)
	}
}
