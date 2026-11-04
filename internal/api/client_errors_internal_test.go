package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// A panic in a handler and an error Server.fail logs both become kind
// "server" reports under the route pattern, never the path; with reports
// off, nothing is recorded.
func TestServerErrorsRecorded(t *testing.T) {
	st := store.New(testdb.New(t))
	sys := tenant.System(context.Background())
	for _, on := range []bool{false, true} {
		s := &Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "0.15.0", ClientErrors: on}
		r := chi.NewRouter()
		r.Use(s.captureServerErrors, s.recoverer)
		r.Get("/api/v1/assets/{id}/boom", func(w http.ResponseWriter, r *http.Request) { panic("nil map in asset 4711") })
		r.Get("/api/v1/assets/{id}/fail", func(w http.ResponseWriter, r *http.Request) {
			s.fail(w, r, errDB)
		})
		r.Get("/api/v1/assets/{id}/fine", func(w http.ResponseWriter, r *http.Request) { writeError(w, 404, "not_found", "not found") })
		srv := httptest.NewServer(r)
		for _, p := range []string{"/api/v1/assets/4711/boom", "/api/v1/assets/4711/fail", "/api/v1/assets/4711/fine"} {
			resp, err := http.Get(srv.URL + p)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		}
		srv.Close()
		want := 0
		if on {
			want = 2
		}
		var rows []struct {
			Route, Name, Code, Frame string
			Status                   int
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			res, err := st.Pool.Query(sys, `SELECT api_route, name, code, top_frame, status FROM client_errors WHERE kind = 'server' ORDER BY name`)
			if err != nil {
				t.Fatal(err)
			}
			rows = rows[:0]
			for res.Next() {
				var x struct {
					Route, Name, Code, Frame string
					Status                   int
				}
				if err := res.Scan(&x.Route, &x.Name, &x.Code, &x.Frame, &x.Status); err != nil {
					t.Fatal(err)
				}
				rows = append(rows, x)
			}
			res.Close()
			if len(rows) >= want && (want > 0 || time.Now().After(deadline.Add(-4*time.Second))) || time.Now().After(deadline) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if len(rows) != want {
			t.Fatalf("on=%v: %d server reports, want %d: %+v", on, len(rows), want, rows)
		}
		if !on {
			continue
		}
		if rows[0].Name != "error" || rows[0].Route != "/api/v1/assets/{id}/fail" || rows[0].Code != "internal" || rows[0].Status != 500 {
			t.Errorf("fail: %+v", rows[0])
		}
		if rows[1].Name != "panic" || rows[1].Route != "/api/v1/assets/{id}/boom" || rows[1].Frame == "" || rows[1].Status != 500 {
			t.Errorf("panic: %+v", rows[1])
		}
		var msg string
		if err := st.Pool.QueryRow(sys, `SELECT sample->>'message' FROM client_errors WHERE name = 'panic'`).Scan(&msg); err != nil || msg != "nil map in asset 4711" {
			// Four digits are kept; five or more are scrubbed.
			t.Errorf("panic message %q (%v)", msg, err)
		}
	}
}

var errDB = &wrapped{"database is gone: connection refused", nil}
