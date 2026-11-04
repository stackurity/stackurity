package health

import (
	"context"
	"testing"

	"github.com/stackurity/stackurity/internal/clienterrors"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// A new error people hit opens one platform incident in the operators'
// workspace, which its routes announce once (like any incident): more
// reports of it, and every later sync, change nothing. It resolves by
// itself after 24 hours, and does not come back while the error keeps
// happening; only after 7 days without it is it new again.
func TestNewClientErrorAlertsOnce(t *testing.T) {
	st := store.New(testdb.New(t))
	bg := context.Background()
	sys := tenant.System(bg)
	ops := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	c := &Checker{Store: st, FeedsEnabled: true, ClientErrors: true}
	report, ok := clienterrors.Check(clienterrors.Report{Source: "api", Route: "/settings/billing", Method: "GET",
		APIRoute: "/api/v1/billing", Status: 404, Code: "not_found", Name: "ApiError", Message: "not found"})
	if !ok {
		t.Fatal("report refused")
	}
	exec := func(sql string) {
		t.Helper()
		if _, err := st.Pool.Exec(sys, sql); err != nil {
			t.Fatal(err)
		}
	}
	sync := func() []store.SystemIncident {
		t.Helper()
		incs, err := c.PlatformIncidents(ops)
		if err != nil {
			t.Fatal(err)
		}
		var mine []store.SystemIncident
		for _, in := range incs {
			if in.Detail["problem"] == "client_errors" {
				mine = append(mine, in)
			}
		}
		if err := st.SyncSystemIncidents(ops, mine); err != nil {
			t.Fatal(err)
		}
		return mine
	}
	count := func(status string) int {
		t.Helper()
		var n int
		if err := st.Pool.QueryRow(ops, `SELECT count(*) FROM incidents WHERE kind = 'platform' AND key LIKE 'client_error:%' AND status = $1`,
			status).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	if incs := sync(); len(incs) != 0 {
		t.Fatalf("incidents before any report: %+v", incs)
	}
	if err := st.RecordClientErrors(bg, 0, []clienterrors.Clean{report}); err != nil {
		t.Fatal(err)
	}
	incs := sync()
	if len(incs) != 1 || incs[0].Title != "New error people hit: 404 not_found ApiError on /settings/billing (GET /api/v1/billing)" ||
		incs[0].Priority != "P2" {
		t.Fatalf("new error: %+v", incs)
	}
	for range 3 {
		if err := st.RecordClientErrors(bg, 0, []clienterrors.Clean{report, report}); err != nil {
			t.Fatal(err)
		}
		sync()
	}
	if open, done := count("open"), count("resolved"); open != 1 || done != 0 {
		t.Fatalf("after more reports: %d open, %d resolved; want one open", open, done)
	}

	// A day later it is no longer new: the incident resolves, and more
	// reports do not open another.
	exec(`UPDATE client_error_fingerprints SET new_since = now() - interval '25 hours', first_seen = now() - interval '25 hours'`)
	sync()
	if err := st.RecordClientErrors(bg, 0, []clienterrors.Clean{report}); err != nil {
		t.Fatal(err)
	}
	sync()
	if open, done := count("open"), count("resolved"); open != 0 || done != 1 {
		t.Fatalf("a day later: %d open, %d resolved; want one resolved", open, done)
	}

	// Gone for 8 days, then back: new again, one more incident.
	exec(`UPDATE client_error_fingerprints SET last_seen = now() - interval '8 days'`)
	if err := st.RecordClientErrors(bg, 0, []clienterrors.Clean{report}); err != nil {
		t.Fatal(err)
	}
	sync()
	if open := count("open"); open != 1 {
		t.Fatalf("back after 8 days: %d open", open)
	}

	// Off: nothing is announced.
	off := &Checker{Store: st, FeedsEnabled: true}
	if got, err := off.newClientErrors(ops); err != nil || len(got) != 0 {
		t.Errorf("off: %+v %v", got, err)
	}
}
