package linux

import (
	"io"
	"strings"
	"testing"
)

// TestLimitedBufferHoldsUnderIOCopy: os/exec copies a binary's output with
// io.Copy, which uses a destination's ReadFrom when it has one.
func TestLimitedBufferHoldsUnderIOCopy(t *testing.T) {
	b := &limitedBuffer{max: 64 << 10}
	if _, err := io.Copy(b, strings.NewReader(strings.Repeat("v", 8<<20))); err != nil {
		t.Fatal(err)
	}
	if n := len(b.Bytes()); n > 64<<10 {
		t.Errorf("kept %d bytes", n)
	}
}
