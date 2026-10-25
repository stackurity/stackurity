package version

import "strings"

type nugetVersion struct {
	nums [4]string
	pre  []string
}

// parseNuGet accepts NuGet versions: SemVer 2.0 with up to four numeric
// parts ("1.2.3.4"), prerelease labels compared case-insensitively, and
// build metadata, which is ignored.
func parseNuGet(s string) (nugetVersion, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nugetVersion{}, false
	}
	v := nugetVersion{nums: [4]string{"0", "0", "0", "0"}}
	for i, p := range parts {
		if !isDigits(p) {
			return nugetVersion{}, false
		}
		v.nums[i] = p
	}
	if hasPre {
		if pre == "" {
			return nugetVersion{}, false
		}
		v.pre = strings.Split(strings.ToLower(pre), ".")
	}
	return v, true
}

// CompareNuGet orders versions as NuGet does. SemVer would reject the
// fourth numeric part, and the generic comparator would put 1.0.0-beta
// after 1.0.0.
func CompareNuGet(a, b string) (int, error) {
	if err := tooLong(NuGet, a, b); err != nil {
		return 0, err
	}
	x, ok := parseNuGet(a)
	if !ok {
		return 0, &ParseError{NuGet, a}
	}
	y, ok := parseNuGet(b)
	if !ok {
		return 0, &ParseError{NuGet, b}
	}
	for i := range x.nums {
		if c := cmpNum(x.nums[i], y.nums[i]); c != 0 {
			return c, nil
		}
	}
	// Same prerelease rules as SemVer, on the lower-cased labels.
	return compareSemver(semver{"0", "0", "0", x.pre}, semver{"0", "0", "0", y.pre}), nil
}

// NuGetPrerelease reports whether v has a prerelease label.
func NuGetPrerelease(v string) bool {
	n, ok := parseNuGet(v)
	return ok && len(n.pre) > 0
}
