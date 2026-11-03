package main

import (
	"strings"
	"testing"
)

func TestPumpLines(t *testing.T) {
	long := strings.Repeat("x", maxLogLine+50)
	var got []string
	pumpLines(strings.NewReader("first\r\n\nsecond\n"+long+"\nlast without newline"), func(l string) { got = append(got, l) })
	if len(got) != 4 || got[0] != "first" || got[1] != "second" || got[3] != "last without newline" {
		t.Fatalf("lines %q", got)
	}
	if len(got[2]) != maxLogLine+len(" [cut]") || !strings.HasSuffix(got[2], " [cut]") {
		t.Errorf("long line not cut: %d characters", len(got[2]))
	}
}
