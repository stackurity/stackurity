package version

import (
	"fmt"
	"strings"
)

// ChangeType classifies an upgrade. For distro packages a change that keeps
// the upstream version and only moves the distro revision (a backported
// security fix) is "distro" — the least disruptive kind.
func ChangeType(purlType, from, to string) (string, error) {
	cmp := For(ForPurlType(purlType))
	c, err := cmp(from, to)
	if err != nil {
		return "", err
	}
	if c >= 0 {
		return "", fmt.Errorf("%s is not newer than %s", to, from)
	}
	switch purlType {
	case "deb", "rpm", "apk":
		uf, ut := upstream(purlType, from), upstream(purlType, to)
		if uf == ut {
			return "distro", nil
		}
		return semverish(uf, ut), nil
	}
	return semverish(from, to), nil
}

// upstream strips epoch and distro revision.
func upstream(purlType, v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:]
	}
	switch purlType {
	case "deb", "rpm":
		if i := strings.LastIndexByte(v, '-'); i > 0 {
			v = v[:i]
		}
	case "apk":
		if i := strings.LastIndex(v, "-r"); i > 0 {
			v = v[:i]
		}
	}
	return v
}

// semverish classifies by the first differing dotted numeric component.
func semverish(from, to string) string {
	if t := UpdateType(from, to); t != "" {
		return t
	}
	f := strings.FieldsFunc(strings.TrimPrefix(from, "v"), func(r rune) bool { return r == '.' || r == '-' || r == '+' || r == '~' })
	t := strings.FieldsFunc(strings.TrimPrefix(to, "v"), func(r rune) bool { return r == '.' || r == '-' || r == '+' || r == '~' })
	for i := 0; i < len(f) && i < len(t); i++ {
		if f[i] != t[i] {
			switch i {
			case 0:
				return "major"
			case 1:
				return "minor"
			}
			return "patch"
		}
	}
	return "patch"
}

// Prerelease reports whether v is a pre-release under the ecosystem's own
// rules (what its package manager skips unless asked). Distro and generic
// versions have no such notion and are never pre-releases.
func Prerelease(e Ecosystem, v string) bool {
	switch e {
	case SemVer:
		return SemverPrerelease(v)
	case PEP440:
		pre, _ := PEP440Prerelease(v)
		return pre
	case Maven:
		return MavenPrerelease(v)
	case NuGet:
		return NuGetPrerelease(v)
	case RubyGems:
		// Gem::Version: any letter makes a prerelease.
		return strings.IndexFunc(v, func(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }) >= 0
	case Composer:
		return ComposerPrerelease(v)
	}
	return false
}

// ComposerPrerelease reports whether v is a dev, alpha, beta or RC version.
func ComposerPrerelease(v string) bool {
	l := strings.ToLower(v)
	if strings.HasPrefix(l, "dev-") || strings.HasSuffix(l, "-dev") {
		return true
	}
	for _, s := range []string{"alpha", "beta", "rc", "-a", "-b"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// MajorLine returns the version's major release line (the leading number,
// with a non-zero PEP 440 epoch kept), or "" when it has none. Versions in
// the same line are what a "same major" upgrade may move between.
func MajorLine(e Ecosystem, v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	prefix := ""
	if e == PEP440 {
		if ep, rest, ok := strings.Cut(v, "!"); ok {
			if strings.TrimLeft(ep, "0") != "" {
				prefix = ep + "!"
			}
			v = rest
		}
	}
	end := 0
	for end < len(v) && v[end] >= '0' && v[end] <= '9' {
		end++
	}
	if end == 0 {
		return ""
	}
	n := strings.TrimLeft(v[:end], "0")
	if n == "" {
		n = "0"
	}
	return prefix + n
}
