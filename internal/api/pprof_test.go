package api_test

import (
	"bytes"
	"io"
	"testing"
)

// Go's heap and goroutine profiles (and the metrics) are served only on the
// private metrics listener (STACKURITY_METRICS_ADDR, internal/metrics), never
// on the API port: a profile shows what the process holds in memory.
func TestNoProfilesOnAPIPort(t *testing.T) {
	e := newEnv(t)
	s := e.anon()
	for _, path := range []string{"/debug/pprof/", "/debug/pprof/heap", "/debug/pprof/goroutine?debug=1", "/debug/pprof/profile", "/metrics"} {
		resp := s.req("GET", path, nil, nil)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		// A profile is gzip (pprof's protobuf) or, with debug=1, text
		// starting with the profile's name.
		if bytes.HasPrefix(b, []byte{0x1f, 0x8b}) || bytes.Contains(b, []byte("goroutine profile:")) ||
			bytes.Contains(b, []byte("heap profile:")) || bytes.Contains(b, []byte("stackurity_")) {
			t.Errorf("GET %s on the API port served profile or metrics data (%d)", path, resp.StatusCode)
		}
	}
}
