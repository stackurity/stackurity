package secondcheck

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// purl is a package URL read by the second check's own parser: type,
// namespace, name, version and qualifiers, percent-decoded. It reads what
// collectors send; anything it cannot read is "could not check".
type purl struct {
	typ, namespace, name, version string
	qualifiers                    map[string]string
}

func parsePurl(s string) (purl, error) {
	var p purl
	rest, ok := strings.CutPrefix(s, "pkg:")
	if !ok || len(s) > 2048 {
		return p, fmt.Errorf("not a package URL")
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, query, _ := strings.Cut(rest, "?")
	p.qualifiers = map[string]string{}
	if query != "" {
		for _, kv := range strings.Split(query, "&") {
			k, v, _ := strings.Cut(kv, "=")
			dv, err := url.PathUnescape(v)
			if err != nil {
				return p, fmt.Errorf("unreadable qualifier %q", k)
			}
			p.qualifiers[strings.ToLower(k)] = dv
		}
	}
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		v, err := url.PathUnescape(rest[i+1:])
		if err != nil {
			return p, fmt.Errorf("unreadable version")
		}
		p.version, rest = v, rest[:i]
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 {
		return p, fmt.Errorf("no package name")
	}
	p.typ = strings.ToLower(parts[0])
	for i := range parts[1:] {
		d, err := url.PathUnescape(parts[1+i])
		if err != nil {
			return p, fmt.Errorf("unreadable name")
		}
		parts[1+i] = d
	}
	p.name = parts[len(parts)-1]
	p.namespace = strings.Join(parts[1:len(parts)-1], "/")
	return p, nil
}

// target is what the second check derives from the observed inventory row:
// the ecosystem rules that apply, the names an advisory may use for the
// package, the release for distro packages and the version to compare.
type target struct {
	ecosystem string // npm, PyPI, Debian, Ubuntu, Alpine, Rocky Linux, ...
	release   string // distro release from the distro qualifier
	names     map[string]bool
	version   string
	family    family
	fips      bool
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

func normaliseName(eco, n string) string {
	switch eco {
	case "PyPI":
		return strings.ToLower(pypiSep.ReplaceAllString(n, "-"))
	case "Packagist", "NuGet":
		return strings.ToLower(n)
	}
	return n
}

// deriveTarget reads the raw observation. An error says why the second
// check cannot decide this package.
func deriveTarget(rawPurl, invVersion string, ev map[string]string) (target, error) {
	p, err := parsePurl(rawPurl)
	if err != nil {
		return target{}, fmt.Errorf("the package URL could not be read by the second check: %v", err)
	}
	t := target{names: map[string]bool{}, version: invVersion, family: famDotted}
	if t.version == "" {
		t.version = p.version
	}
	join := func() string {
		if p.namespace == "" {
			return p.name
		}
		return p.namespace + "/" + p.name
	}
	add := func(n string) {
		n = strings.TrimSpace(n)
		if i := strings.IndexByte(n, ' '); i > 0 {
			n = n[:i] // "openssl (3.0.11)"
		}
		if n != "" {
			t.names[normaliseName(t.ecosystem, n)] = true
		}
	}
	switch p.typ {
	case "npm":
		t.ecosystem = "npm"
		add(join())
	case "composer":
		t.ecosystem = "Packagist"
		add(join())
	case "pypi":
		t.ecosystem = "PyPI"
		add(p.name)
	case "golang":
		t.ecosystem = "Go"
		add(join())
		if join() == "stdlib" {
			t.version = strings.TrimPrefix(t.version, "go")
		}
	case "cargo":
		t.ecosystem = "crates.io"
		add(p.name)
	case "gem":
		t.ecosystem = "RubyGems"
		add(p.name)
	case "maven":
		t.ecosystem = "Maven"
		add(p.namespace + ":" + p.name)
	case "nuget":
		t.ecosystem = "NuGet"
		add(p.name)
	case "pub":
		t.ecosystem = "Pub"
		add(p.name)
	case "deb":
		t.family = famDpkg
		distro := p.qualifiers["distro"]
		switch strings.ToLower(p.namespace) {
		case "debian":
			t.ecosystem, t.release = "Debian", strings.TrimPrefix(distro, "debian-")
		case "ubuntu":
			t.ecosystem, t.release = "Ubuntu", strings.TrimPrefix(distro, "ubuntu-")
		default:
			return t, fmt.Errorf("deb packages from %q have no advisory source", p.namespace)
		}
		if t.release == "" || t.release == distro {
			return t, fmt.Errorf("the distro release is unknown")
		}
		t.fips = strings.Contains(strings.ToLower(t.version), "fips")
		add(p.name)
		add(p.qualifiers["upstream"])
		add(ev["source_package"])
	case "apk":
		t.family = famAPK
		distro := p.qualifiers["distro"]
		t.ecosystem, t.release = "Alpine", strings.TrimPrefix(distro, "alpine-")
		if strings.ToLower(p.namespace) != "alpine" || t.release == "" || t.release == distro {
			return t, fmt.Errorf("the Alpine release is unknown")
		}
		add(p.name)
		add(p.qualifiers["upstream"])
		add(ev["source_package"])
	case "rpm":
		t.family = famRPM
		distro := p.qualifiers["distro"]
		id, rel := "", ""
		for _, d := range []string{"almalinux", "rocky", "rhel", "amzn", "opensuse-leap", "sles_sap", "sles", "sled"} {
			if r, ok := strings.CutPrefix(distro, d+"-"); ok {
				id, rel = d, r
				break
			}
		}
		switch id {
		case "rocky":
			t.ecosystem = "Rocky Linux"
		case "almalinux":
			t.ecosystem = "AlmaLinux"
		case "rhel":
			t.ecosystem = "Red Hat"
		case "amzn":
			t.ecosystem = "Amazon Linux"
		case "":
			return t, fmt.Errorf("the rpm distribution %q has no advisory source", distro)
		default:
			return t, fmt.Errorf("SUSE and openSUSE product channels are not re-derived by the second check")
		}
		t.release = rel
		add(p.name)
		srpm := ev["source_rpm"]
		if srpm == "" {
			srpm = p.qualifiers["upstream"]
		}
		add(srpmName(srpm))
		if evr := ev["evr"]; evr != "" {
			t.version = evr
		} else if e := p.qualifiers["epoch"]; e != "" && e != "0" && !strings.Contains(t.version, ":") {
			t.version = e + ":" + t.version
		}
	default:
		return t, fmt.Errorf("no advisory source for %s packages", p.typ)
	}
	if t.version == "" {
		return t, fmt.Errorf("no installed version was reported")
	}
	return t, nil
}

// srpmName reads the package name from "name-version-release.src.rpm".
func srpmName(s string) string {
	base, ok := strings.CutSuffix(s, ".src.rpm")
	if !ok {
		return ""
	}
	parts := strings.Split(base, "-")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[:len(parts)-2], "-")
}

// recordApplies says whether an advisory record's ecosystem describes the
// observed release. paid is set for subscription-only channels (Ubuntu Pro).
func (t target) recordApplies(eco string) (applies, paid bool) {
	base, rest, _ := strings.Cut(eco, ":")
	major, _, _ := strings.Cut(t.release, ".")
	switch t.ecosystem {
	case "Packagist":
		return base == "Packagist", false
	case "Debian":
		return eco == "Debian:"+major, false
	case "Ubuntu":
		if base != "Ubuntu" {
			return false, false
		}
		parts := strings.Split(rest, ":")
		has := func(s string) bool {
			for _, p := range parts {
				if p == s {
					return true
				}
			}
			return false
		}
		fipsChannel := strings.Contains(rest, "FIPS")
		return has(t.release) && fipsChannel == t.fips, has("Pro")
	case "Alpine":
		mm := t.release
		if p := strings.SplitN(t.release, ".", 3); len(p) >= 2 {
			mm = p[0] + "." + p[1]
		}
		return eco == "Alpine:v"+mm, false
	case "Rocky Linux", "AlmaLinux":
		return eco == t.ecosystem+":"+major, false
	case "Amazon Linux":
		return eco == "Amazon Linux:"+t.release, false
	case "Red Hat":
		stream, ok := strings.CutPrefix(eco, "Red Hat:enterprise_linux:")
		if !ok {
			return false, false
		}
		stream, _, _ = strings.Cut(stream, "::")
		mm := t.release
		if p := strings.SplitN(t.release, ".", 3); len(p) >= 2 {
			mm = p[0] + "." + p[1]
		}
		return stream == major || stream == mm, false
	}
	return eco == t.ecosystem, false
}
