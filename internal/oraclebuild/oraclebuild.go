// Package oraclebuild reads which build of an Oracle Linux package a version
// is. It is shared, on purpose, by the matcher (internal/osv) and the
// independent second check (internal/secondcheck): it is a reading of
// Oracle's naming, not matching logic, and one definition keeps the two
// from drifting apart.
package oraclebuild

import "strings"

// Channel names the build an installed Oracle Linux package version is, from
// its release (the part after the last "-", epoch and version aside):
// "ksplice" for a Ksplice userspace build (2:2.34-60.0.3.ksplice1.el9),
// "fips" for a FIPS build (10:3.5.8-2.0.1.el9_8_fips), "" for a regular
// build or a version without a release. Such builds carry their own epoch
// and have their own advisories.
func Channel(version string) string {
	i := strings.LastIndexByte(version, '-')
	if i < 0 {
		return ""
	}
	rel := strings.ToLower(version[i+1:])
	switch {
	case strings.Contains(rel, "ksplice"):
		return "ksplice"
	case strings.Contains(rel, "fips"):
		return "fips"
	}
	return ""
}
