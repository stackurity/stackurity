package version

import (
	"strings"
)

// --- Debian (dpkg) version comparison, per deb-version(7).

func splitDebian(v string) (epoch, upstream, revision string, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", "", "", false
	}
	if e, rest, found := strings.Cut(v, ":"); found {
		if !isDigits(e) {
			return "", "", "", false
		}
		epoch, v = e, rest
	} else {
		epoch = "0"
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		upstream, revision = v[:i], v[i+1:]
	} else {
		upstream, revision = v, "0"
	}
	if upstream == "" || upstream[0] < '0' || upstream[0] > '9' {
		// Policy says upstream should start with a digit; dpkg tolerates
		// otherwise, so we do too, but an empty upstream is invalid.
		if upstream == "" {
			return "", "", "", false
		}
	}
	return epoch, upstream, revision, true
}

// debOrder is the dpkg character weight: ~ sorts before everything, even the
// end of the string; letters sort before non-letters.
func debOrder(c byte, present bool) int {
	switch {
	case !present:
		return 0
	case c == '~':
		return -1
	case c >= '0' && c <= '9':
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	}
	return int(c) + 256
}

func debCompareString(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// non-digit prefix
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			var ca, cb byte
			pa, pb := i < len(a) && !isDigit(a[i]), j < len(b) && !isDigit(b[j])
			if pa {
				ca = a[i]
			}
			if pb {
				cb = b[j]
			}
			oa, ob := debOrder(ca, pa), debOrder(cb, pb)
			if oa != ob {
				return sign(oa - ob)
			}
			if pa {
				i++
			}
			if pb {
				j++
			}
		}
		// digit run
		si := i
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		sj := j
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if c := cmpNum(a[si:i], b[sj:j]); c != 0 {
			return c
		}
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func CompareDebian(a, b string) (int, error) {
	ea, ua, ra, ok := splitDebian(a)
	if !ok {
		return 0, &ParseError{Debian, a}
	}
	eb, ub, rb, ok := splitDebian(b)
	if !ok {
		return 0, &ParseError{Debian, b}
	}
	if c := cmpNum(ea, eb); c != 0 {
		return c, nil
	}
	if c := debCompareString(ua, ub); c != 0 {
		return c, nil
	}
	return debCompareString(ra, rb), nil
}

// --- RPM: epoch:version-release with rpmvercmp.

func splitRPM(v string) (epoch, ver, rel string) {
	epoch = "0"
	if e, rest, ok := strings.Cut(v, ":"); ok && isDigits(e) {
		epoch, v = e, rest
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func isAlnum(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// rpmvercmp follows rpm's lib/rpmvercmp.c, including tilde and caret.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		// tilde: sorts before anything, including end of string
		if (i < len(a) && a[i] == '~') || (j < len(b) && b[j] == '~') {
			if i >= len(a) || a[i] != '~' {
				return 1
			}
			if j >= len(b) || b[j] != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		// caret: sorts after end of string but before anything else
		if (i < len(a) && a[i] == '^') || (j < len(b) && b[j] == '^') {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if a[i] != '^' {
				return 1
			}
			if b[j] != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		numeric := isDigit(a[i])
		if numeric {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlnum(a[i]) && !isDigit(a[i]) {
				i++
			}
			for j < len(b) && isAlnum(b[j]) && !isDigit(b[j]) {
				j++
			}
		}
		x, y := a[si:i], b[sj:j]
		if y == "" {
			// segment types differ: numeric is newer than alpha
			if numeric {
				return 1
			}
			return -1
		}
		var c int
		if numeric {
			c = cmpNum(x, y)
		} else {
			c = sign(strings.Compare(x, y))
		}
		if c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	}
	return 1
}

func CompareRPM(a, b string) (int, error) {
	if strings.TrimSpace(a) == "" {
		return 0, &ParseError{RPM, a}
	}
	if strings.TrimSpace(b) == "" {
		return 0, &ParseError{RPM, b}
	}
	ea, va, ra := splitRPM(a)
	eb, vb, rb := splitRPM(b)
	if c := cmpNum(ea, eb); c != 0 {
		return c, nil
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c, nil
	}
	if ra == "" || rb == "" {
		return 0, nil // a bare version matches any release
	}
	return rpmvercmp(ra, rb), nil
}

// --- Alpine apk: digits, letter, suffixes, -rN.

var apkSuffixRank = map[string]int{
	"alpha": -4, "beta": -3, "pre": -2, "rc": -1, // before release
	"cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5, // after release
}

type apkVersion struct {
	nums     []string
	letter   byte
	suffixes [][2]string // name, number
	rel      string
}

func parseAPK(v string) (apkVersion, bool) {
	var out apkVersion
	v = strings.TrimSpace(v)
	if base, rel, ok := strings.Cut(v, "-r"); ok {
		if !isDigits(rel) {
			return out, false
		}
		v, out.rel = base, rel
	} else {
		out.rel = "0"
	}
	main, suf, _ := strings.Cut(v, "_")
	if main == "" {
		return out, false
	}
	if c := main[len(main)-1]; c >= 'a' && c <= 'z' {
		out.letter = c
		main = main[:len(main)-1]
	}
	for _, p := range strings.Split(main, ".") {
		if !isDigits(p) {
			return out, false
		}
		out.nums = append(out.nums, p)
	}
	if suf != "" {
		for _, s := range strings.Split(suf, "_") {
			k := 0
			for k < len(s) && !isDigit(s[k]) {
				k++
			}
			name, num := s[:k], s[k:]
			if _, ok := apkSuffixRank[name]; !ok {
				return out, false
			}
			if num == "" {
				num = "0"
			}
			out.suffixes = append(out.suffixes, [2]string{name, num})
		}
	}
	return out, true
}

func CompareAPK(a, b string) (int, error) {
	va, ok := parseAPK(a)
	if !ok {
		return CompareGeneric(a, b) // apk tolerates odd versions; degrade gracefully
	}
	vb, ok := parseAPK(b)
	if !ok {
		return CompareGeneric(a, b)
	}
	for i := 0; i < len(va.nums) || i < len(vb.nums); i++ {
		x, y := "0", "0"
		if i < len(va.nums) {
			x = va.nums[i]
		}
		if i < len(vb.nums) {
			y = vb.nums[i]
		}
		// apk compares the first component numerically and later ones as
		// fractions only when they start with 0; numeric is right in practice.
		if c := cmpNum(x, y); c != 0 {
			return c, nil
		}
	}
	if va.letter != vb.letter {
		return sign(int(va.letter) - int(vb.letter)), nil
	}
	for i := 0; i < len(va.suffixes) || i < len(vb.suffixes); i++ {
		ra, rb := 0, 0
		na, nb := "0", "0"
		if i < len(va.suffixes) {
			ra, na = apkSuffixRank[va.suffixes[i][0]], va.suffixes[i][1]
		}
		if i < len(vb.suffixes) {
			rb, nb = apkSuffixRank[vb.suffixes[i][0]], vb.suffixes[i][1]
		}
		if ra != rb {
			return sign(ra - rb), nil
		}
		if c := cmpNum(na, nb); c != 0 {
			return c, nil
		}
	}
	return cmpNum(va.rel, vb.rel), nil
}

// --- Composer (Packagist)

var composerStability = map[string]int{"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "": 4, "stable": 4, "patch": 5, "pl": 5, "p": 5}

type composerVersion struct {
	nums      []string
	stability int
	stabNum   string
}

func parseComposer(v string) (composerVersion, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "v")
	if strings.HasPrefix(v, "dev-") || v == "" {
		return composerVersion{}, false
	}
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	// Split numeric head from stability tail: 1.2.3-beta2, 1.2.3beta2, 1.2.3.RC1
	end := 0
	for end < len(v) && (isDigit(v[end]) || v[end] == '.') {
		end++
	}
	head := strings.Trim(v[:end], ".")
	tail := strings.TrimLeft(v[end:], "-_.")
	if head == "" {
		return composerVersion{}, false
	}
	var out composerVersion
	for _, p := range strings.Split(head, ".") {
		if !isDigits(p) {
			return composerVersion{}, false
		}
		out.nums = append(out.nums, p)
	}
	k := 0
	for k < len(tail) && !isDigit(tail[k]) && tail[k] != '.' {
		k++
	}
	name := tail[:k]
	rank, ok := composerStability[name]
	if !ok {
		return composerVersion{}, false
	}
	out.stability = rank
	out.stabNum = strings.Trim(tail[k:], ".-")
	if out.stabNum == "" {
		out.stabNum = "0"
	}
	if !isDigits(strings.ReplaceAll(out.stabNum, ".", "")) {
		return composerVersion{}, false
	}
	return out, true
}

func CompareComposer(a, b string) (int, error) {
	va, ok := parseComposer(a)
	if !ok {
		return 0, &ParseError{Composer, a}
	}
	vb, ok := parseComposer(b)
	if !ok {
		return 0, &ParseError{Composer, b}
	}
	for i := 0; i < 4; i++ {
		x, y := "0", "0"
		if i < len(va.nums) {
			x = va.nums[i]
		}
		if i < len(vb.nums) {
			y = vb.nums[i]
		}
		if c := cmpNum(x, y); c != 0 {
			return c, nil
		}
	}
	if va.stability != vb.stability {
		return sign(va.stability - vb.stability), nil
	}
	return CompareGeneric(va.stabNum, vb.stabNum)
}
