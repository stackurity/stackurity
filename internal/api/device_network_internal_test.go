package api

import (
	"testing"
	"time"
)

func TestSameNetwork(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"198.51.100.7", "198.51.100.200", true},
		{"198.51.100.7", "198.51.101.7", false},
		{"2001:db8:1:2::1", "2001:db8:1:ffff::9", true},
		{"2001:db8:1::1", "2001:db8:2::1", false},
		{"198.51.100.7", "2001:db8::1", false},
		{"::ffff:198.51.100.7", "198.51.100.9", true},
		{"", "", true},
		{"unknown", "198.51.100.7", false},
	} {
		if got := sameNetwork(c.a, c.b); got != c.want {
			t.Errorf("sameNetwork(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestDeviceMissDelay(t *testing.T) {
	for misses, want := range map[int]time.Duration{0: 0, 999: 0, 1000: time.Second, 1199: time.Second, 1200: 2 * time.Second, 5000: 5 * time.Second} {
		if got := deviceMissDelay(misses); got != want {
			t.Errorf("deviceMissDelay(%d) = %v, want %v", misses, got, want)
		}
	}
}
