package worker

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// Work that makes the heap grow past the threshold is named while it runs
// (a process killed for its memory never logs the end), once, and again at
// the end with its peak. Work that stays under it logs nothing.
func TestHeapWatchNamesTheWork(t *testing.T) {
	var out syncBuf
	h := newHeapWatch(100<<20, slog.New(slog.NewTextHandler(&out, nil)))
	heap := int64(50 << 20)
	h.read = func() int64 { return heap }

	endQuiet := h.begin("task alerts")
	end := h.begin("job feed.sync", "job", 657)
	heap = 400 << 20
	h.sample()
	h.sample() // warns once per run
	heap = 30 << 20
	end()
	if got := strings.Count(out.String(), "heap growing during background work"); got != 2 {
		// Both runs grew past 100 MiB from their start at 50 MiB.
		t.Fatalf("warnings while running = %d; log:\n%s", got, out.String())
	}
	if !strings.Contains(out.String(), `work="job feed.sync"`) || !strings.Contains(out.String(), "job=657") ||
		!strings.Contains(out.String(), "grew_mib=350") || !strings.Contains(out.String(), `running="[job feed.sync task alerts]"`) {
		t.Errorf("warning does not name the work and its growth:\n%s", out.String())
	}
	if !strings.Contains(out.String(), `msg="background work made the heap grow" work="job feed.sync" heap_start_mib=50 heap_peak_mib=400`) {
		t.Errorf("no end-of-run warning with the peak:\n%s", out.String())
	}

	out = syncBuf{}
	heap = 30 << 20
	endQuiet() // it started at 50 MiB and peaked at 400 MiB
	small := h.begin("task housekeeping")
	heap = 100 << 20
	h.sample()
	small()
	if strings.Contains(out.String(), "housekeeping") {
		t.Errorf("growth of 70 MiB under a 100 MiB threshold was logged:\n%s", out.String())
	}

	var nilWatch *heapWatch
	nilWatch.begin("job x")() // off: no-op
}
