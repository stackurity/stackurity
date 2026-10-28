package metrics

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProfiles(t *testing.T) {
	mux := http.NewServeMux()
	Profiles(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	get := func(path string) (int, []byte) {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	if code, b := get("/debug/pprof/heap"); code != 200 || !bytes.HasPrefix(b, []byte{0x1f, 0x8b}) {
		t.Errorf("heap: %d, %d bytes; want a gzipped profile", code, len(b))
	}
	if code, b := get("/debug/pprof/heap?gc=1&debug=1"); code != 200 || !bytes.Contains(b, []byte("heap profile:")) {
		t.Errorf("heap?debug=1: %d %.80q", code, b)
	}
	if code, b := get("/debug/pprof/goroutine?debug=2"); code != 200 || !bytes.Contains(b, []byte("goroutine ")) {
		t.Errorf("goroutine?debug=2: %d %.80q", code, b)
	}
	// Only these two: no CPU profile or trace, which would stall the process.
	for _, p := range []string{"/debug/pprof/", "/debug/pprof/profile", "/debug/pprof/trace", "/debug/pprof/cmdline"} {
		if code, _ := get(p); code != 404 {
			t.Errorf("GET %s = %d; want 404", p, code)
		}
	}
}
