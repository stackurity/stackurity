package metrics

import (
	"fmt"
	"net/http"
	"runtime"
	"runtime/pprof"
	"strconv"
)

// Profiles serves the Go heap and goroutine profiles at
// /debug/pprof/heap and /debug/pprof/goroutine, in the format go tool pprof
// reads (?debug=1 or 2 for text). It is mounted only on the private metrics
// listener (STACKURITY_METRICS_ADDR), never on the API port. It uses
// runtime/pprof directly rather than net/http/pprof, whose init registers
// every profile, CPU tracing included, on http.DefaultServeMux.
func Profiles(mux *http.ServeMux) {
	for _, name := range []string{"heap", "goroutine"} {
		mux.HandleFunc("GET /debug/pprof/"+name, func(w http.ResponseWriter, r *http.Request) {
			debug, _ := strconv.Atoi(r.FormValue("debug"))
			if name == "heap" && r.FormValue("gc") != "" {
				runtime.GC() // live objects only, as of now
			}
			p := pprof.Lookup(name)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			if debug > 0 {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			} else {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
			}
			if err := p.WriteTo(w, debug); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		})
	}
}
