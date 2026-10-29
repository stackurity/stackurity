// Package version compares versions using each ecosystem's own rules.
// Comparing distro package versions as semver gives wrong answers (epochs,
// backport revisions, tildes), so every ecosystem gets its own comparator.
package version

import (
	"fmt"
	"strings"
)

// Comparator returns <0, 0 or >0. An error means a version could not be
// parsed under this ecosystem's rules.
type Comparator func(a, b string) (int, error)

type Ecosystem string

const (
	SemVer   Ecosystem = "semver"   // npm, and the fallback for GitHub-style tags
	Composer Ecosystem = "composer" // Packagist
	Debian   Ecosystem = "debian"   // dpkg: Debian, Ubuntu
	RPM      Ecosystem = "rpm"      // Rocky, Alma, RHEL, Fedora, SUSE
	APK      Ecosystem = "apk"      // Alpine, Wolfi
	PEP440   Ecosystem = "pep440"   // PyPI
	RubyGems Ecosystem = "rubygems" // RubyGems
	Maven    Ecosystem = "maven"    // Maven Central and Gradle
	NuGet    Ecosystem = "nuget"    // NuGet
	Generic  Ecosystem = "generic"
)

func For(e Ecosystem) Comparator {
	switch e {
	case SemVer:
		return CompareSemver
	case Composer:
		return CompareComposer
	case Debian:
		return CompareDebian
	case RPM:
		return CompareRPM
	case APK:
		return CompareAPK
	case PEP440:
		return ComparePEP440
	case RubyGems:
		return CompareRubyGems
	case Maven:
		return CompareMaven
	case NuGet:
		return CompareNuGet
	}
	return CompareGeneric
}

// ForPurlType maps a purl type to its comparator family.
func ForPurlType(t string) Ecosystem {
	switch t {
	case "npm", "cargo", "golang", "pub", "swift", "hex":
		return SemVer
	case "pypi":
		return PEP440
	case "gem":
		return RubyGems
	case "maven":
		return Maven
	case "nuget":
		return NuGet
	case "composer":
		return Composer
	case "deb":
		return Debian
	case "rpm":
		return RPM
	case "apk":
		return APK
	}
	return Generic
}

// --- generic: dotted numeric with alphanumeric tie-break

// CompareGeneric splits on non-alphanumerics and compares numeric parts
// numerically and others lexically. It never errors.
func CompareGeneric(a, b string) (int, error) {
	if err := tooLong(Generic, a, b); err != nil {
		return 0, err
	}
	pa, pb := splitAlnum(a), splitAlnum(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y string
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if c := cmpPart(x, y); c != 0 {
			return c, nil
		}
	}
	return 0, nil
}

func splitAlnum(s string) []string {
	var out []string
	cur := strings.Builder{}
	kind := 0 // 1 digit, 2 letter
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range strings.ToLower(s) {
		k := 0
		switch {
		case r >= '0' && r <= '9':
			k = 1
		case r >= 'a' && r <= 'z':
			k = 2
		}
		if k == 0 {
			flush()
			kind = 0
			continue
		}
		if k != kind {
			flush()
		}
		kind = k
		cur.WriteRune(r)
	}
	flush()
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// cmpNum compares two digit strings of any length numerically.
func cmpNum(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func cmpPart(x, y string) int {
	switch {
	case x == y:
		return 0
	case x == "":
		if isDigits(y) && strings.Trim(y, "0") == "" {
			return 0
		}
		return -1
	case y == "":
		if isDigits(x) && strings.Trim(x, "0") == "" {
			return 0
		}
		return 1
	}
	dx, dy := isDigits(x), isDigits(y)
	switch {
	case dx && dy:
		return cmpNum(x, y)
	case dx: // numbers sort after letters ("1.0.a" < "1.0.1")
		return 1
	case dy:
		return -1
	}
	return strings.Compare(x, y)
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

// MaxLength bounds the versions compared. Real versions are far shorter,
// but a collector may submit any string up to the batch field limit, and
// comparing such strings against every advisory range and release would let
// one batch keep the shared evaluator busy for hours. Longer versions fail
// to parse, which records the component as not evaluated.
const MaxLength = 256

func tooLong(e Ecosystem, a, b string) error {
	for _, v := range []string{a, b} {
		if len(v) > MaxLength {
			return &ParseError{Ecosystem: e, Version: v[:32] + "…"}
		}
	}
	return nil
}

type ParseError struct {
	Ecosystem Ecosystem
	Version   string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("cannot parse %q as a %s version", e.Version, e.Ecosystem)
}
