package api_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/testdb"
)

// While the database is unreachable, credentials cannot be checked. The
// answer is 503, which agents and CI retry and the dashboard shows as an
// outage, never 401, which they treat as revoked credentials (a person would
// be signed out, and an agent would drop its batch).
func TestCredentialsDuringDatabaseOutage(t *testing.T) {
	pool := testdb.New(t)
	down, err := pgxpool.NewWithConfig(context.Background(), pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	down.Close()
	s := &api.Server{Store: store.New(down), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test"}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	for _, tc := range []struct {
		name string
		set  func(*http.Request)
	}{
		{"token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer stk_anything") }},
		{"session", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "stackurity_session", Value: "anything"}) }},
	} {
		for _, path := range []string{"/api/v1/assets", "/api/v1/collections/1/result"} {
			req, _ := http.NewRequest("GET", srv.URL+path, nil)
			tc.set(req)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 503 {
				t.Errorf("%s, %s with the database down: %d; want 503", tc.name, path, resp.StatusCode)
			}
		}
	}

	// With the database up, an unknown token is still a 401.
	up := httptest.NewServer((&api.Server{Store: store.New(pool), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test"}).Handler())
	t.Cleanup(up.Close)
	req, _ := http.NewRequest("GET", up.URL+"/api/v1/assets", nil)
	req.Header.Set("Authorization", "Bearer stk_unknown")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("unknown token: %d, want 401", resp.StatusCode)
	}
}
