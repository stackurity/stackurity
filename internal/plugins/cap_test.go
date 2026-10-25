package plugins

import (
	"io"
	"strings"
	"testing"
)

// TestCappedHoldsUnderIOCopy: os/exec copies output with io.Copy, which
// uses a destination's ReadFrom when it has one. The cap must hold there.
func TestCappedHoldsUnderIOCopy(t *testing.T) {
	c := &capped{max: 1 << 10}
	_, _ = io.Copy(c, strings.NewReader(strings.Repeat("x", 1<<20)))
	if len(c.Bytes()) > 1<<10 || !c.over {
		t.Errorf("kept %d bytes, over=%v", len(c.Bytes()), c.over)
	}
}
