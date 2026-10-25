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
