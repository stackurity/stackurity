package secondcheck

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The comparators here are written independently of internal/version, on
// purpose, and read less: plain dotted numbers for language ecosystems,
// dpkg and rpm rules for distro packages, and the common Alpine forms.
// Anything else is "could not check", never a guess.

type family string

const (
	famDotted family = "dotted numbers"
	famDpkg   family = "dpkg"
	famRPM    family = "rpm"
	famAPK    family = "apk"
)

type comparator func(a, b string) (int, error)

func comparatorFor(f family) comparator {
	switch f {
	case famDpkg:
		return dpkgCompare
	case famRPM:
		return rpmCompare
	case famAPK:
		return apkCompare
	}
	return dottedCompare
}

var dottedRE = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+)*$`)

// dottedCompare compares plain dotted numbers ("1.2.10" > "1.2.9"); missing
// parts count as 0. Pre-releases, build metadata and words are refused.
func dottedCompare(a, b string) (int, error) {
	pa, err := dottedParts(a)
	if err != nil {
		return 0, err
	}
	pb, err := dottedParts(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y uint64
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

func dottedParts(v string) ([]uint64, error) {
	if !dottedRE.MatchString(v) || len(v) > 128 {
		return nil, fmt.Errorf("%q is not plain dotted numbers", v)
	}
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	out := make([]uint64, len(parts))
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%q has a part too large to compare", v)
		}
		out[i] = n
	}
	return out, nil
}

// --- dpkg (Debian Policy 5.6.12)

var dpkgRE = regexp.MustCompile(`^([0-9]+:)?[0-9][A-Za-z0-9.+~:-]*$`)

func dpkgCompare(a, b string) (int, error) {
	ea, ua, ra, err := dpkgSplit(a)
	if err != nil {
		return 0, err
	}
	eb, ub, rb, err := dpkgSplit(b)
	if err != nil {
		return 0, err
	}
	if ea != eb {
		if ea < eb {
			return -1, nil
		}
		return 1, nil
	}
	if c := dpkgPart(ua, ub); c != 0 {
		return c, nil
	}
	return dpkgPart(ra, rb), nil
}

func dpkgSplit(v string) (epoch uint64, upstream, revision string, err error) {
	if len(v) > 256 || !dpkgRE.MatchString(v) {
		return 0, "", "", fmt.Errorf("%q is not a Debian version", v)
	}
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if epoch, err = strconv.ParseUint(v[:i], 10, 32); err != nil {
			return 0, "", "", fmt.Errorf("%q has an unreadable epoch", v)
		}
		v = v[i+1:]
	}
	upstream = v
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		upstream, revision = v[:i], v[i+1:]
	}
	return epoch, upstream, revision, nil
}

// dpkgOrder ranks one non-digit character: "~" before the end of the
// string, the end before letters, letters before other characters.
func dpkgOrder(c byte, end bool) int {
	switch {
	case end:
		return 0
	case c == '~':
		return -1
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		return int(c)
	}
	return int(c) + 256
}

func dpkgPart(a, b string) int {
	for a != "" || b != "" {
		// Non-digit prefixes, character by character.
		for (a != "" && !isDigit(a[0])) || (b != "" && !isDigit(b[0])) {
			ca, cb := dpkgOrder(first(a), a == "" || isDigit(a[0])), dpkgOrder(first(b), b == "" || isDigit(b[0]))
			if ca != cb {
				return sign(ca - cb)
			}
			if a != "" && !isDigit(a[0]) {
				a = a[1:]
			}
			if b != "" && !isDigit(b[0]) {
				b = b[1:]
			}
		}
		// Digit runs, numerically.
		var na, nb string
		na, a = digitRun(a)
		nb, b = digitRun(b)
		if c := numCompare(na, nb); c != 0 {
			return c
		}
	}
	return 0
}

// --- rpm (rpmvercmp, with epoch and release)

var rpmRE = regexp.MustCompile(`^([0-9]+:)?[A-Za-z0-9._+~^-]+$`)

func rpmCompare(a, b string) (int, error) {
	ea, va, ra, err := rpmSplit(a)
	if err != nil {
		return 0, err
	}
	eb, vb, rb, err := rpmSplit(b)
	if err != nil {
		return 0, err
	}
	if ea != eb {
		if ea < eb {
			return -1, nil
		}
		return 1, nil
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c, nil
	}
	if ra == "" || rb == "" {
		return 0, nil // a version without release matches any release
	}
	return rpmvercmp(ra, rb), nil
}

func rpmSplit(v string) (epoch uint64, ver, rel string, err error) {
	if len(v) > 256 || !rpmRE.MatchString(v) {
		return 0, "", "", fmt.Errorf("%q is not an RPM version", v)
	}
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if epoch, err = strconv.ParseUint(v[:i], 10, 32); err != nil {
			return 0, "", "", fmt.Errorf("%q has an unreadable epoch", v)
		}
		v = v[i+1:]
	}
	ver = v
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		ver, rel = v[:i], v[i+1:]
	}
	return epoch, ver, rel, nil
}

func isAlnum(c byte) bool { return isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	for a != "" || b != "" {
		for a != "" && !isAlnum(a[0]) && a[0] != '~' && a[0] != '^' {
			a = a[1:]
		}
		for b != "" && !isAlnum(b[0]) && b[0] != '~' && b[0] != '^' {
			b = b[1:]
		}
		// Tilde sorts before everything, even the end.
		if first(a) == '~' || first(b) == '~' {
			if first(a) != '~' {
				return 1
			}
			if first(b) != '~' {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		// Caret sorts after the end, before anything else.
		if first(a) == '^' || first(b) == '^' {
			if a == "" {
				return -1
			}
			if b == "" {
				return 1
			}
			if first(a) != '^' {
				return 1
			}
			if first(b) != '^' {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if a == "" || b == "" {
			break
		}
		var sa, sb string
		numeric := isDigit(a[0])
		if numeric {
			sa, a = digitRun(a)
			sb, b = digitRun(b)
		} else {
			sa, a = alphaRun(a)
			sb, b = alphaRun(b)
		}
		if sb == "" {
			// Different kinds of segment: a number is newer than letters.
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			if c := numCompare(sa, sb); c != 0 {
				return c
			}
		} else if sa != sb {
			if sa < sb {
				return -1
			}
			return 1
		}
	}
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return -1
	}
	return 1
}

// --- apk: the common forms only (1.2.3, 1.2.3a, with -rN)

var apkRE = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)*)([a-z]?)(?:-r([0-9]+))?$`)

func apkCompare(a, b string) (int, error) {
	ma, mb := apkRE.FindStringSubmatch(a), apkRE.FindStringSubmatch(b)
	if ma == nil || len(a) > 128 {
		return 0, fmt.Errorf("%q is outside the Alpine version forms the second check reads", a)
	}
	if mb == nil || len(b) > 128 {
		return 0, fmt.Errorf("%q is outside the Alpine version forms the second check reads", b)
	}
	if c, err := dottedCompare(ma[1], mb[1]); err != nil || c != 0 {
		return c, err
	}
	if ma[2] != mb[2] {
		if ma[2] < mb[2] {
			return -1, nil
		}
		return 1, nil
	}
	return numCompare(orZero(ma[3]), orZero(mb[3])), nil
}

// --- helpers

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func first(s string) byte {
	if s == "" {
		return 0
	}
	return s[0]
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

func digitRun(s string) (run, rest string) {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

func alphaRun(s string) (run, rest string) {
	i := 0
	for i < len(s) && ((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z')) {
		i++
	}
	return s[:i], s[i:]
}

// numCompare compares two digit strings of any length numerically.
func numCompare(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return sign(strings.Compare(a, b))
}
