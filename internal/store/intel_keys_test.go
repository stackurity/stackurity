package store

import (
	"slices"
	"testing"
)

// A threat notice links to the findings of all its CVEs at once.
func TestSplitKeys(t *testing.T) {
	for in, want := range map[string][]string{
		"":               nil,
		"CVE-1":          {"CVE-1"},
		"CVE-1, CVE-2,,": {"CVE-1", "CVE-2"},
		" , ":            nil,
	} {
		if got := splitKeys(in); !slices.Equal(got, want) {
			t.Errorf("splitKeys(%q) = %q, want %q", in, got, want)
		}
	}
}
