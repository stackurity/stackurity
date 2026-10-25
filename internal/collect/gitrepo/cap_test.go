package gitrepo

import (
	"io"
	"strings"
	"testing"
)

// TestCapBufferHoldsUnderIOCopy: os/exec copies git's stderr with io.Copy,
// which uses a destination's ReadFrom when it has one.
func TestCapBufferHoldsUnderIOCopy(t *testing.T) {
	c := &capBuffer{max: 1 << 10}
	if _, err := io.Copy(c, strings.NewReader(strings.Repeat("remote: x\n", 1<<20))); err != nil {
		t.Fatal(err)
	}
	if n := len(c.String()); n > 1<<10 {
		t.Errorf("kept %d bytes", n)
	}
}
