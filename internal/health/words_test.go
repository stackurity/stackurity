package health

import (
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

func TestProductionPart(t *testing.T) {
	for _, c := range []struct {
		count, severe int64
		want          string
	}{
		{0, 0, ""},
		{1, 0, ""},
		{1, 1, " (production)"},
		{3, 2, ", 2 of them production"},
	} {
		if got := production(&store.HealthGroup{Count: c.count, Severe: c.severe}); got != c.want {
			t.Errorf("%d/%d: %q", c.count, c.severe, got)
		}
	}
}
