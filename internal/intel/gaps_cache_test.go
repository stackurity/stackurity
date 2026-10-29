package intel

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCoverageGapsCache: the report is reused until the TTL passes, errors
// are not cached, concurrent callers share one build, and a caller whose
// context ends while another builds gives up.
func TestCoverageGapsCache(t *testing.T) {
	var builds atomic.Int64
	fail := false
	clock := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	build := func(ctx context.Context) (*GapReport, error) {
		n := builds.Add(1)
		if fail {
			return nil, errors.New("db down")
		}
		return &GapReport{Assets: n}, nil
	}
	get := cacheGapReport(build, 5*time.Minute, func() time.Time { return clock })
	ctx := context.Background()

	r1, err := get(ctx)
	if err != nil || r1.Assets != 1 {
		t.Fatalf("first: %+v %v", r1, err)
	}
	clock = clock.Add(4 * time.Minute)
	if r, _ := get(ctx); r != r1 || builds.Load() != 1 {
		t.Fatalf("within TTL: rebuilt (%d builds)", builds.Load())
	}
	clock = clock.Add(2 * time.Minute)
	fail = true
	if _, err := get(ctx); err == nil {
		t.Fatal("expired cache with a failing build: want the error")
	}
	fail = false
	r3, err := get(ctx)
	if err != nil || r3.Assets != 3 {
		t.Fatalf("after an error: %+v %v (errors must not be cached)", r3, err)
	}

	// Concurrent callers on an expired cache share one build.
	clock = clock.Add(time.Hour)
	release := make(chan struct{})
	started := make(chan struct{})
	slow := cacheGapReport(func(ctx context.Context) (*GapReport, error) {
		builds.Add(1)
		close(started)
		<-release
		return &GapReport{}, nil
	}, time.Minute, func() time.Time { return clock })
	before := builds.Load()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = slow(ctx) }()
	<-started
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := slow(cctx); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled waiter: %v", err)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = slow(ctx) }()
	}
	close(release)
	wg.Wait()
	if n := builds.Load() - before; n != 1 {
		t.Errorf("concurrent callers: %d builds, want 1", n)
	}
}
