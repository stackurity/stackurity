package oraclebuild

import "testing"

func TestChannel(t *testing.T) {
	for v, want := range map[string]string{
		"2:2.34-60.0.3.ksplice1.el9": "ksplice",
		"2.34-60.0.3.ksplice1.el9":   "ksplice",
		"10:3.5.8-2.0.1.el9_8_fips":  "fips",
		"10:3.6.16-8.el8_9.1_FIPS":   "fips",
		"0:2.34-60.0.3.el9":          "",
		"1:3.0.7-24.el9":             "",
		"0:ksplice-tools-1.0-1.el9":  "", // the name or version, not the release
		"1.2.3":                      "",
		"0:1.0.0fips-1.el9":          "", // "fips" in the version, not the release
	} {
		if got := Channel(v); got != want {
			t.Errorf("Channel(%q) = %q, want %q", v, got, want)
		}
	}
}
