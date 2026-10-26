package main

import (
	"testing"
	"time"
)

func TestParseTimings(t *testing.T) {
	got, err := parseTimings("")
	if err != nil || got != defaultTimings() {
		t.Fatalf("empty = %+v, %v; want the defaults", got, err)
	}
	got, err = parseTimings("job-lock=3s, alerts=500ms")
	if err != nil || got.JobLock != 3*time.Second || got.Alerts != 500*time.Millisecond || got.Tick != 15*time.Second {
		t.Fatalf("got %+v, %v", got, err)
	}
	for _, bad := range []string{"lock=3s", "job-lock=soon", "tick=0s", "poll=-1s"} {
		if _, err := parseTimings(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

// Agents spread their check-again polls: up to a third of the interval on top.
func TestJitter(t *testing.T) {
	for i := 0; i < 100; i++ {
		if d := jitter(45 * time.Second); d < 45*time.Second || d > 60*time.Second {
			t.Fatalf("jitter(45s) = %v", d)
		}
	}
	if jitter(0) != 0 {
		t.Error("jitter(0)")
	}
}
