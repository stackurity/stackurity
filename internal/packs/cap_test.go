package packs

import (
	"io"
	"strings"
	"testing"
)

// TestCappedHoldsUnderIOCopy: the cap holds however the output is written,
// including through io.Copy, which prefers a destination's ReadFrom.
func TestCappedHoldsUnderIOCopy(t *testing.T) {
	c := &capped{max: 1 << 10}
	_, _ = io.Copy(c, strings.NewReader(strings.Repeat("x", 1<<20)))
	if len(c.Bytes()) > 1<<10 || !c.over {
		t.Errorf("kept %d bytes, over=%v", len(c.Bytes()), c.over)
	}
}
