package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// A handler that has started a streamed download and then fails aborts it:
// the client must see a broken response, not a complete 200 (security
// review of the evidence pack, 17 Nov 2026).
func TestRecovererPassesAbortOn(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	r := chi.NewRouter()
	r.Use(s.recoverer)
	r.Get("/download", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write([]byte("PK partial"))
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	})
	srv := httptest.NewServer(r)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/download")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Error("the aborted download read as complete")
	}
}
