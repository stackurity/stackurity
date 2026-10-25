package version

import (
	"regexp"
	"strings"
)

// PEP 440 (Python) version ordering:
// epoch, release, then dev < pre (a < b < rc) < final < post.
var pep440RE = regexp.MustCompile(`^v?(?:(\d+)!)?(\d+(?:\.\d+)*)` +
	`(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?` +
	`(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d*)))?` +
	`(?:[-_.]?(dev)[-_.]?(\d*))?` +
	`(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)

type pep440 struct {
	epoch   string
	release []string
	preRank int // 0 none, -3 a, -2 b, -1 rc
	pre     string
	post    string // "" when absent
	dev     string // "" when absent
	hasDev  bool
	hasPost bool
}

func parsePEP440(v string) (pep440, bool) {
	m := pep440RE.FindStringSubmatch(strings.ToLower(strings.TrimSpace(v)))
	if m == nil {
		return pep440{}, false
	}
	p := pep440{epoch: m[1], release: strings.Split(m[2], ".")}
	if p.epoch == "" {
		p.epoch = "0"
	}
	switch m[3] {
	case "a", "alpha":
		p.preRank = -3
	case "b", "beta":
		p.preRank = -2
	case "c", "rc", "pre", "preview":
		p.preRank = -1
	}
	p.pre = orZero(m[4])
	if m[5] != "" {
		p.hasPost, p.post = true, m[5]
	} else if m[6] != "" {
		p.hasPost, p.post = true, orZero(m[7])
	}
	if m[8] != "" {
		p.hasDev, p.dev = true, orZero(m[9])
	}
	return p, true
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

func ComparePEP440(a, b string) (int, error) {
	x, ok := parsePEP440(a)
	if !ok {
		return 0, &ParseError{"pep440", a}
	}
	y, ok := parsePEP440(b)
	if !ok {
		return 0, &ParseError{"pep440", b}
	}
	if c := cmpNum(x.epoch, y.epoch); c != 0 {
		return c, nil
	}
	for i := 0; i < len(x.release) || i < len(y.release); i++ {
		p, q := "0", "0"
		if i < len(x.release) {
			p = x.release[i]
		}
		if i < len(y.release) {
			q = y.release[i]
		}
		if c := cmpNum(p, q); c != 0 {
			return c, nil
		}
	}
	// A dev release of the final version sorts before its pre-releases.
	rank := func(v pep440) int {
		switch {
		case v.preRank != 0:
			return v.preRank
		case v.hasDev && !v.hasPost:
			return -4
		}
		return 0
	}
	if c := sign(rank(x) - rank(y)); c != 0 {
		return c, nil
	}
	if x.preRank != 0 {
		if c := cmpNum(x.pre, y.pre); c != 0 {
			return c, nil
		}
	}
	if x.hasPost != y.hasPost {
		if x.hasPost {
			return 1, nil
		}
		return -1, nil
	}
	if c := cmpNum(x.post, y.post); x.hasPost && c != 0 {
		return c, nil
	}
	if x.hasDev != y.hasDev {
		if x.hasDev {
			return -1, nil
		}
		return 1, nil
	}
	return cmpNum(x.dev, y.dev), nil
}

// CompareRubyGems follows Gem::Version: segments split on dots and on
// letter/digit boundaries; any segment with letters makes a prerelease,
// which sorts before the release.
func CompareRubyGems(a, b string) (int, error) {
	seg := func(v string) []string {
		var out []string
		for _, part := range strings.Split(strings.TrimSpace(strings.ReplaceAll(v, "-", ".pre.")), ".") {
			out = append(out, splitAlnum(part)...)
		}
		// Canonical form, as Gem::Version: trailing zeros are dropped from
		// the release part and from the prerelease part separately, so
		// "1.0.0.pre" becomes [1 pre] and "1.0" equals "1".
		k := len(out)
		for i, p := range out {
			if !isDigits(p) {
				k = i
				break
			}
		}
		trim := func(s []string, keep int) []string {
			for len(s) > keep && s[len(s)-1] == "0" {
				s = s[:len(s)-1]
			}
			return s
		}
		rel := trim(append([]string{}, out[:k]...), 1)
		return append(rel, trim(out[k:], 0)...)
	}
	x, y := seg(a), seg(b)
	if len(x) == 0 || len(y) == 0 {
		return 0, &ParseError{"rubygems", a + " / " + b}
	}
	for i := 0; i < len(x) || i < len(y); i++ {
		var p, q string
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		if p == q {
			continue
		}
		pd, qd := isDigits(p), isDigits(q)
		switch {
		case p == "": // b continues: a prerelease tail sorts before
			if qd {
				return -1, nil
			}
			return 1, nil
		case q == "":
			if pd {
				return 1, nil
			}
			return -1, nil
		case pd && qd:
			return cmpNum(p, q), nil
		case pd: // letters (prerelease) sort before numbers
			return 1, nil
		case qd:
			return -1, nil
		}
		return sign(strings.Compare(p, q)), nil
	}
	return 0, nil
}
