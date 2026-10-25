package metrics

import (
	"sort"
	"strconv"
	"sync"
	"time"
)

// Buckets are the latency histogram's upper bounds in seconds.
var Buckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}

// HTTP counts requests by method, route pattern and status class, with a
// latency histogram by method and route pattern. It is safe for concurrent
// use.
type HTTP struct {
	mu       sync.Mutex
	requests map[requestKey]uint64
	latency  map[routeKey]*histogram
}

type routeKey struct{ method, route string }

type requestKey struct {
	routeKey
	class string
}

type histogram struct {
	counts []uint64 // per bucket, not cumulative
	sum    float64
	count  uint64
}

func NewHTTP() *HTTP {
	return &HTTP{requests: map[requestKey]uint64{}, latency: map[routeKey]*histogram{}}
}

// Observe records a finished request. route must be a route pattern (for
// example /api/v1/assets/{id}), never a raw path, to bound cardinality.
func (h *HTTP) Observe(method, route string, status int, d time.Duration) {
	if h == nil {
		return
	}
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
	default:
		method = "OTHER"
	}
	if route == "" {
		route = "unmatched"
	}
	if status == 0 {
		status = 200
	}
	class := strconv.Itoa(status/100) + "xx"
	if status < 100 || status > 599 {
		class = "other"
	}
	rk := routeKey{method, route}
	secs := d.Seconds()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.requests[requestKey{rk, class}]++
	hist := h.latency[rk]
	if hist == nil {
		hist = &histogram{counts: make([]uint64, len(Buckets))}
		h.latency[rk] = hist
	}
	for i, b := range Buckets {
		if secs <= b {
			hist.counts[i]++
			break
		}
	}
	hist.sum += secs
	hist.count++
}

// Write writes the request counter and latency histogram.
func (h *HTTP) Write(w *Writer) {
	h.mu.Lock()
	reqs := make([]requestKey, 0, len(h.requests))
	counts := make(map[requestKey]uint64, len(h.requests))
	for k, v := range h.requests {
		reqs, counts[k] = append(reqs, k), v
	}
	routes := make([]routeKey, 0, len(h.latency))
	hists := make(map[routeKey]histogram, len(h.latency))
	for k, v := range h.latency {
		routes = append(routes, k)
		hists[k] = histogram{counts: append([]uint64(nil), v.counts...), sum: v.sum, count: v.count}
	}
	h.mu.Unlock()

	sort.Slice(reqs, func(i, j int) bool {
		a, b := reqs[i], reqs[j]
		if a.route != b.route {
			return a.route < b.route
		}
		if a.method != b.method {
			return a.method < b.method
		}
		return a.class < b.class
	})
	w.Family("stackurity_http_requests_total", "counter", "HTTP requests served, by method, route pattern and status class.")
	for _, k := range reqs {
		w.Sample("stackurity_http_requests_total", float64(counts[k]), "method", k.method, "route", k.route, "code", k.class)
	}

	sort.Slice(routes, func(i, j int) bool {
		if routes[i].route != routes[j].route {
			return routes[i].route < routes[j].route
		}
		return routes[i].method < routes[j].method
	})
	const name = "stackurity_http_request_duration_seconds"
	w.Family(name, "histogram", "HTTP request latency, by method and route pattern.")
	for _, k := range routes {
		hist := hists[k]
		var cum uint64
		for i, b := range Buckets {
			cum += hist.counts[i]
			w.Sample(name+"_bucket", float64(cum), "method", k.method, "route", k.route, "le", formatValue(b))
		}
		w.Sample(name+"_bucket", float64(hist.count), "method", k.method, "route", k.route, "le", "+Inf")
		w.Sample(name+"_sum", hist.sum, "method", k.method, "route", k.route)
		w.Sample(name+"_count", float64(hist.count), "method", k.method, "route", k.route)
	}
}
