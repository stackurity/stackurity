package version

import "testing"

func TestCompareMaven(t *testing.T) {
	// Each version is older than the next (from Maven's ComparableVersion tests).
	ordered := []string{
		"1-alpha2", "1-alpha123", "1-beta-2", "1-beta123", "1-m2", "1-m11", "1-rc", "1-cr2", "1-rc123",
		"1-SNAPSHOT", "1", "1-sp", "1-sp2", "1-sp123", "1-abc", "1-def", "1-1-snapshot", "1-1", "1-2", "1-123",
		"1.2.3", "1.2.4-alpha1", "1.2.4", "1.10", "2.0.0-M1", "2.0.0-RC1", "2.0.0", "2.0.1", "10.0",
	}
	for i := 0; i+1 < len(ordered); i++ {
		a, b := ordered[i], ordered[i+1]
		if c, _ := CompareMaven(a, b); c >= 0 {
			t.Errorf("%s should be older than %s (got %d)", a, b, c)
		}
		if c, _ := CompareMaven(b, a); c <= 0 {
			t.Errorf("%s should be newer than %s (got %d)", b, a, c)
		}
	}
	for _, eq := range [][2]string{{"1", "1.0"}, {"1", "1.0.0"}, {"1.0", "1-ga"}, {"1", "1-final"}, {"1-rc1", "1-cr1"}, {"1.0.0", "1.0.0-release"}} {
		if c, _ := CompareMaven(eq[0], eq[1]); c != 0 {
			t.Errorf("%s and %s should be equal (got %d)", eq[0], eq[1], c)
		}
	}
	if ForPurlType("maven") != Maven {
		t.Error("maven purls do not use the Maven comparator")
	}
}
