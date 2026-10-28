package worker

import (
	"context"
	"log/slog"
	"runtime/metrics"
	"sort"
	"sync"
	"time"
)

// DefaultHeapWarn is the heap growth during one job or periodic task above
// which the worker logs a warning naming it (Worker.HeapWarn).
const DefaultHeapWarn = 256 << 20

// heapSample is how often the heap is read while work runs.
const heapSample = time.Second

// heapWatch tracks the Go heap while jobs and periodic tasks run, so that
// one which makes it grow a lot names itself in the log. It warns while the
// work is still running, not only when it ends: a process killed for using
// too much memory never logs the end.
type heapWatch struct {
	limit int64
	log   *slog.Logger
	read  func() int64

	mu      sync.Mutex
	running map[*heapRun]struct{}
}

type heapRun struct {
	name   string // "job feed.sync" or "task alerts"
	attrs  []any
	start  int64
	peak   int64
	warned bool
}

func newHeapWatch(limit int64, log *slog.Logger) *heapWatch {
	return &heapWatch{limit: limit, log: log, read: heapBytes, running: map[*heapRun]struct{}{}}
}

// heapBytes is the memory occupied by heap objects, live or not yet swept.
// Reading it does not stop the world.
func heapBytes() int64 {
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return int64(s[0].Value.Uint64())
}

// begin records the start of a run; the returned func ends it. A nil watch
// does nothing.
func (h *heapWatch) begin(name string, attrs ...any) func() {
	if h == nil {
		return func() {}
	}
	now := h.read()
	r := &heapRun{name: name, attrs: attrs, start: now, peak: now}
	h.mu.Lock()
	h.running[r] = struct{}{}
	h.mu.Unlock()
	return func() {
		end := h.read()
		h.mu.Lock()
		delete(h.running, r)
		r.peak = max(r.peak, end)
		grew := r.peak - r.start
		h.mu.Unlock()
		if grew > h.limit {
			h.log.Warn("background work made the heap grow", append([]any{"work", r.name, "heap_start_mib", r.start >> 20,
				"heap_peak_mib", r.peak >> 20, "grew_mib", grew >> 20, "threshold_mib", h.limit >> 20}, r.attrs...)...)
		}
	}
}

// sample updates every running run's peak and warns, once per run, when one
// has grown past the limit.
func (h *heapWatch) sample() {
	now := h.read()
	h.mu.Lock()
	var warn []*heapRun
	var names []string
	for r := range h.running {
		r.peak = max(r.peak, now)
		names = append(names, r.name)
		if !r.warned && now-r.start > h.limit {
			r.warned = true
			warn = append(warn, r)
		}
	}
	h.mu.Unlock()
	sort.Strings(names)
	for _, r := range warn {
		h.log.Warn("heap growing during background work", append([]any{"work", r.name, "heap_start_mib", r.start >> 20,
			"heap_now_mib", now >> 20, "grew_mib", (now - r.start) >> 20, "threshold_mib", h.limit >> 20,
			"running", names}, r.attrs...)...)
	}
}

// run samples until ctx ends.
func (h *heapWatch) run(ctx context.Context) {
	t := time.NewTicker(heapSample)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.sample()
		}
	}
}
