package version

import (
	"math/big"
	"strings"
)

// CompareMaven orders versions the way Maven's ComparableVersion does, which
// is what OSV's Maven ranges assume. Qualifiers rank
// alpha < beta < milestone < rc < snapshot < (release) < sp, so 1.0-rc1 is
// older than 1.0 and 1.0-sp1 newer. Any other string is a valid Maven
// version, except an empty one and an unresolved property reference such as
// "${log4j.version}", which a build left unexpanded: those are errors.
func CompareMaven(a, b string) (int, error) {
	for _, v := range []string{a, b} {
		if strings.TrimSpace(v) == "" || strings.Contains(v, "${") {
			return 0, &ParseError{Maven, v}
		}
	}
	return compareMavenItems(parseMaven(a), parseMaven(b)), nil
}

// mavenItem is a number, a qualifier string, or a nested list (after "-").
type mavenItem struct {
	kind int // 0 number, 1 string, 2 list
	num  *big.Int
	str  string
	list []mavenItem
}

var mavenAliases = map[string]string{"ga": "", "final": "", "release": "", "cr": "rc"}

// Qualifier order; unknown qualifiers sort after all of these, alphabetically.
var mavenQualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

func qualifierRank(s string) (int, bool) {
	for i, q := range mavenQualifiers {
		if q == s {
			return i, true
		}
	}
	return len(mavenQualifiers), false
}

func parseMaven(v string) []mavenItem {
	v = strings.ToLower(strings.TrimSpace(v))
	root := []mavenItem{}
	stack := [][]mavenItem{}
	cur := &root
	var tok strings.Builder
	isDigit := false
	flush := func(followedByDigit bool) {
		s := tok.String()
		tok.Reset()
		if s == "" {
			*cur = append(*cur, mavenItem{kind: 0, num: big.NewInt(0)})
			return
		}
		if isDigit {
			n := new(big.Int)
			n.SetString(s, 10)
			*cur = append(*cur, mavenItem{kind: 0, num: n})
			return
		}
		if followedByDigit && len(s) == 1 {
			switch s {
			case "a":
				s = "alpha"
			case "b":
				s = "beta"
			case "m":
				s = "milestone"
			}
		}
		if alias, ok := mavenAliases[s]; ok {
			s = alias
		}
		*cur = append(*cur, mavenItem{kind: 1, str: s})
	}
	startList := func() {
		stack = append(stack, *cur)
		sub := []mavenItem{}
		cur = &sub
	}
	runes := []rune(v)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case c == '.':
			flush(false)
			isDigit = false
		case c == '-':
			flush(false)
			isDigit = false
			startList() // closed at the end
		case c >= '0' && c <= '9':
			if !isDigit && tok.Len() > 0 {
				flush(true)
				startList()
			}
			isDigit = true
			tok.WriteRune(c)
		default:
			if isDigit && tok.Len() > 0 {
				flush(false)
				startList()
			}
			isDigit = false
			tok.WriteRune(c)
		}
	}
	if tok.Len() > 0 {
		flush(false)
	}
	// Close nested lists from the innermost outwards.
	for len(stack) > 0 {
		parent := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		parent = append(parent, mavenItem{kind: 2, list: normalizeMaven(*cur)})
		cur = &parent
	}
	return normalizeMaven(*cur)
}

// normalizeMaven drops trailing "null" items (zeros, release qualifiers,
// empty lists), so 1.0.0 == 1 and 1-ga == 1.
func normalizeMaven(items []mavenItem) []mavenItem {
	for len(items) > 0 && isNullMaven(items[len(items)-1]) {
		items = items[:len(items)-1]
	}
	return items
}

func isNullMaven(it mavenItem) bool {
	switch it.kind {
	case 0:
		return it.num.Sign() == 0
	case 1:
		return it.str == ""
	}
	return len(it.list) == 0
}

func compareMavenItems(a, b []mavenItem) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y *mavenItem
		if i < len(a) {
			x = &a[i]
		}
		if i < len(b) {
			y = &b[i]
		}
		if c := compareMavenItem(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// compareMavenItem compares two items; nil stands for a missing item, which
// compares like a release (0, "" or an empty list).
func compareMavenItem(x, y *mavenItem) int {
	if x == nil && y == nil {
		return 0
	}
	if x == nil {
		return -compareMavenItem(y, nil)
	}
	switch x.kind {
	case 0:
		if y == nil {
			return x.num.Sign()
		}
		switch y.kind {
		case 0:
			return x.num.Cmp(y.num)
		default:
			return 1 // a number is newer than a qualifier or a sub-list
		}
	case 1:
		if y == nil {
			return compareQualifier(x.str, "")
		}
		switch y.kind {
		case 0, 2:
			return -1
		default:
			return compareQualifier(x.str, y.str)
		}
	default:
		if y == nil {
			if len(x.list) == 0 {
				return 0
			}
			return compareMavenItem(&x.list[0], nil)
		}
		switch y.kind {
		case 0:
			return -1
		case 1:
			return 1
		default:
			return compareMavenItems(x.list, y.list)
		}
	}
}

func compareQualifier(a, b string) int {
	ra, ka := qualifierRank(a)
	rb, kb := qualifierRank(b)
	if ra != rb {
		if ra < rb {
			return -1
		}
		return 1
	}
	if !ka && !kb {
		return strings.Compare(a, b)
	}
	return 0
}

// MavenPrerelease reports whether v carries a qualifier that ranks below a
// release (alpha, beta, milestone, rc/cr, snapshot, including the a1, b1 and
// m1 short forms), anywhere in the version.
func MavenPrerelease(v string) bool {
	release, _ := qualifierRank("")
	var walk func(items []mavenItem) bool
	walk = func(items []mavenItem) bool {
		for _, it := range items {
			switch it.kind {
			case 1:
				if r, known := qualifierRank(it.str); known && r < release {
					return true
				}
			case 2:
				if walk(it.list) {
					return true
				}
			}
		}
		return false
	}
	return walk(parseMaven(v))
}
