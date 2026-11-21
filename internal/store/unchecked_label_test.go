package store

import "testing"

// A generic component (a Flutter engine build) is not labelled "other
// packages", which read as if it depended on something else.
func TestUncheckedLabelGeneric(t *testing.T) {
	for subject, want := range map[string]string{
		"generic|ecosystem":   GenericUnsupportedLabel,
		"generic|other":       GenericUnsupportedLabel,
		"cocoapods|ecosystem": "CocoaPods packages",
		"generic|cms":         "WordPress core",
	} {
		if got := uncheckedLabel(UncheckedUnsupported, subject, ""); got != want {
			t.Errorf("uncheckedLabel(%q) = %q, want %q", subject, got, want)
		}
	}
}
