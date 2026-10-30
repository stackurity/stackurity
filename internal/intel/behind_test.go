package intel

import (
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

func TestReleasesBehind(t *testing.T) {
	for _, c := range []struct {
		installed, latest string
		n                 int
		ok                bool
	}{
		{"6.5.3", "6.5.14", 11, true},
		{"6.5", "6.5.14", 14, true},
		{"6.5.14", "6.5.14", 0, true},
		{"6.5.14", "6.5", -14, true}, // lifecycle data behind the site: not behind
		{"6.9-RC1", "6.9.11", 0, false},
		{"6.7-alpha-58576-src", "6.7.4", 0, false},
		{"6.6-beta2", "6.6.3", 0, false},
		{"6.4.3", "6.5.14", 0, false}, // another line
		{"6.5.03", "6.5.14", 0, false},
		{"6.5.3", "", 0, false},
	} {
		n, ok := releasesBehind(c.installed, c.latest)
		if n != c.n || ok != c.ok {
			t.Errorf("%s against %s = %d %v, want %d %v", c.installed, c.latest, n, ok, c.n, c.ok)
		}
	}
}

// Only products whose point releases are security releases are reported
// as behind.
func TestBehindOnlyListedProducts(t *testing.T) {
	r := store.EvalRow{Version: "1.24.0", Confidence: "confirmed"}
	if f := behindFinding(r, &store.LifecycleCycle{Product: "nginx", Cycle: "1.24", Latest: "1.24.5"}); f != nil {
		t.Errorf("nginx: %+v", f)
	}
	r.Version = "6.5.3"
	if f := behindFinding(r, &store.LifecycleCycle{Product: "wordpress", ProductLabel: "WordPress", Cycle: "6.5", Latest: "6.5.14"}); f == nil ||
		f.Severity != "high" || f.FixedVersion != "6.5.14" {
		t.Errorf("wordpress: %+v", f)
	}
}
