package version

import "strings"

type semver struct {
	major, minor, patch string
	pre                 []string
}

// ParseSemver accepts strict SemVer 2.0 plus a leading "v" and missing
// minor/patch ("1", "1.2"), which appear in real lockfiles and advisories.
func ParseSemver(s string) (semver, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "=")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i] // build metadata does not affect precedence
	}
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return semver{}, false
	}
	for _, p := range parts {
		if !isDigits(p) {
			return semver{}, false
		}
	}
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	v := semver{major: parts[0], minor: parts[1], patch: parts[2]}
	if hasPre {
		if pre == "" {
			return semver{}, false
		}
		v.pre = strings.Split(pre, ".")
	}
	return v, true
}

func CompareSemver(a, b string) (int, error) {
	va, ok := ParseSemver(a)
	if !ok {
		return 0, &ParseError{SemVer, a}
	}
	vb, ok := ParseSemver(b)
	if !ok {
		return 0, &ParseError{SemVer, b}
	}
	return compareSemver(va, vb), nil
}

func compareSemver(a, b semver) int {
	if c := cmpNum(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpNum(a.minor, b.minor); c != 0 {
		return c
	}
	if c := cmpNum(a.patch, b.patch); c != 0 {
		return c
	}
	// A version without prerelease has higher precedence.
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		dx, dy := isDigits(x), isDigits(y)
		var c int
		switch {
		case dx && dy:
			c = cmpNum(x, y)
		case dx:
			c = -1
		case dy:
			c = 1
		default:
			c = sign(strings.Compare(x, y))
		}
		if c != 0 {
			return c
		}
	}
	return sign(len(a.pre) - len(b.pre))
}

// SemverPrerelease reports whether v has a prerelease tag.
func SemverPrerelease(v string) bool {
	s, ok := ParseSemver(v)
	return ok && len(s.pre) > 0
}

// UpdateType classifies the change from installed to target as "major",
// "minor", "patch" or "" when target is not newer.
func UpdateType(installed, target string) string {
	a, ok1 := ParseSemver(installed)
	b, ok2 := ParseSemver(target)
	if !ok1 || !ok2 || compareSemver(a, b) >= 0 {
		return ""
	}
	switch {
	case cmpNum(a.major, b.major) != 0:
		return "major"
	case cmpNum(a.minor, b.minor) != 0:
		return "minor"
	}
	return "patch"
}
