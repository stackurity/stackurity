package secondcheck

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/stackurity/stackurity/internal/oraclebuild"
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
	// oracleBuild is the build channel of an Oracle Linux package, read
	// from its release: "ksplice" (2:2.34-60.0.3.ksplice1.el9), "fips"
	// (10:3.5.8-2.0.1.el9_8_fips) or "" for a regular build.
	oracleBuild string
	// kernel: a Debian or Ubuntu package built from a kernel source.
	// kernelSource: the source package it was derived from is known (from
	// the upstream qualifier or the source_package evidence), so a record
	// for another kernel source is a real mismatch; without it the kernel
	// source stream cannot be told from the binary name alone.
	kernel, kernelSource bool
	// line: a side-by-side program's installed release line ("3.11"), and
	// lineOf reads a version's; fixes on other lines are not this line's.
	line   string
	lineOf func(string) string
}

// Debian and Ubuntu kernels, read by the second check's own rules.
//
// A running kernel is several binary packages (linux-image-*, linux-modules-*,
// linux-modules-extra-*, linux-image-unsigned-*, ...) whose names carry the
// kernel ABI and flavour (linux-image-5.15.0-1050-aws). Their version is the
// kernel source's version (5.15.0-1050.55, 5.15.0-91.101~20.04.1 for a
// backported stream), so it compares directly with the advisory's. Advisories
// name the kernel source: linux, or a stream such as linux-aws,
// linux-aws-5.15, linux-hwe-5.15, linux-gcp, linux-azure, linux-oracle,
// linux-lowlatency. The signed image comes from a wrapper source
// (linux-signed, linux-signed-aws-5.15, linux-signed-hwe-6.5) whose advisories
// are published under the kernel source it wraps, and Debian names its signed
// wrappers per architecture (linux-signed-amd64).
//
// Metapackages (linux-image-generic-hwe-22.04, from linux-meta-hwe-6.5) are
// not mapped: they carry no kernel code and their versions use another
// scheme (6.5.0.35.35~22.04.1, not 6.5.0-35.35~22.04.1), so comparing them
// with the kernel's records would give wrong answers.
var kernelABI = regexp.MustCompile(`\d+\.\d+\.\d+-\d+`)

var debianArch = map[string]bool{"amd64": true, "arm64": true, "i386": true, "armhf": true, "armel": true, "ppc64el": true,
	"s390x": true, "mips64el": true, "riscv64": true}

// kernelSourceName maps a source package to the kernel source its
// advisories use: linux-signed-aws-5.15 -> linux-aws-5.15, linux-signed ->
// linux, and for Debian linux-signed-amd64 -> linux,
// linux-signed-5.10-amd64 -> linux-5.10. ok is false for a name that is not
// a kernel source (linux-firmware, linux-base, a linux-meta-* metapackage
// source).
func kernelSourceName(ecosystem, src string) (string, bool) {
	if (src != "linux" && !strings.HasPrefix(src, "linux-")) || strings.HasPrefix(src, "linux-meta") {
		return "", false
	}
	parts := strings.Split(src, "-")
	out := []string{parts[0]}
	for _, p := range parts[1:] {
		if p == "signed" {
			continue
		}
		out = append(out, p)
	}
	if ecosystem == "Debian" && len(out) > 1 && debianArch[out[len(out)-1]] && strings.Contains(src, "-signed") {
		out = out[:len(out)-1]
	}
	name := strings.Join(out, "-")
	// Packages that share the linux- prefix but are not built from a kernel
	// source (linux-base, linux-firmware) keep their own name.
	switch {
	case name == "linux-base", name == "linux-sysctl-defaults", strings.HasPrefix(name, "linux-firmware"):
		return "", false
	}
	return name, true
}

// isKernelBinary reports a Debian or Ubuntu binary package tied to one kernel
// version: its name carries the kernel ABI (5.15.0-91).
func isKernelBinary(name string) bool {
	return strings.HasPrefix(name, "linux-") && kernelABI.MatchString(name)
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

func normaliseName(eco, n string) string {
	switch eco {
	case "PyPI":
		return strings.ToLower(pypiSep.ReplaceAllString(n, "-"))
	case "Packagist", "NuGet", "SwiftURL":
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
	case "swift":
		// OSV's SwiftURL names a package by its repository URL; a registry
		// identity (scope/name, no host) has no advisories.
		if host, _, _ := strings.Cut(p.namespace, "/"); !strings.Contains(host, ".") {
			return t, fmt.Errorf("a Swift package without a repository URL has no advisory source")
		}
		t.ecosystem = "SwiftURL"
		add(p.namespace + "/" + p.name)
	case "hex":
		if p.namespace != "" {
			return t, fmt.Errorf("packages from a private Hex organisation or repository have no advisory source")
		}
		t.ecosystem = "Hex"
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
		t.kernel = isKernelBinary(p.name)
		for _, src := range []string{p.qualifiers["upstream"], ev["source_package"]} {
			if i := strings.IndexByte(src, ' '); i > 0 {
				src = src[:i]
			}
			if k, ok := kernelSourceName(t.ecosystem, src); ok {
				add(k)
				t.kernel, t.kernelSource = true, true
			}
		}
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
		for _, d := range []string{"almalinux", "rocky", "rhel", "amzn", "ol", "opensuse-leap", "sles_sap", "sles", "sled"} {
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
		case "ol":
			t.ecosystem = "Oracle Linux"
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
		if t.ecosystem == "Oracle Linux" {
			// Shared with the matcher on purpose: it reads Oracle's naming
			// of builds, not matching rules.
			t.oracleBuild = oraclebuild.Channel(t.version)
		}
	case "generic":
		if ev["registry_view"] != "" && ev["kind"] == "" {
			// An installed Windows program (an Add/Remove Programs entry).
			eco, id, v, line, lineOf, err := windowsProgram(p.name, t.version, ev)
			if err != nil {
				return t, err
			}
			t.ecosystem, t.version, t.line, t.lineOf = eco, v, line, lineOf
			add(id)
			break
		}
		if strings.ToLower(p.name) != "windows" || ev["kind"] != "operating-system" {
			return t, fmt.Errorf("no advisory source for %s packages", p.typ)
		}
		line, err := windowsLine(t.version, ev)
		if err != nil {
			return t, err
		}
		t.ecosystem = "Windows:" + line
		add("windows")
	default:
		return t, fmt.Errorf("no advisory source for %s packages", p.typ)
	}
	if t.version == "" {
		return t, fmt.Errorf("no installed version was reported")
	}
	return t, nil
}

// windowsServerLines and windowsClientLines are the second check's own
// reading of a Windows build (10.0.<build>.<revision>) as the update line
// Microsoft's Security Update Guide publishes fixed builds for.
var (
	windowsServerLines = map[string]string{"14393": "Server 2016", "17763": "Server 2019", "20348": "Server 2022",
		"25398": "Server 23H2", "26100": "Server 2025"}
	windowsClientLines = map[string]string{"10240": "10 1507", "14393": "10 1607", "17763": "10 1809", "19044": "10 21H2",
		"19045": "10 22H2", "22621": "11 22H2", "22631": "11 23H2", "26100": "11 24H2", "26200": "11 25H2", "26300": "11 26H2",
		"28000": "11 26H1"}
)

// windowsLine reads the update line of a Windows host from its version and
// product name. Server is told from client by the product name (or, without
// one, a Server edition); Windows Server 2019 and the 1809 semi-annual
// channel release share build 17763, and only the former has a year.
func windowsLine(v string, ev map[string]string) (string, error) {
	parts := strings.Split(v, ".")
	if len(parts) != 4 || parts[0] != "10" || parts[1] != "0" {
		return "", fmt.Errorf("Windows version %q is not 10.0.<build>.<revision>", v)
	}
	name, edition := ev["product_name"], strings.ToLower(ev["edition_id"])
	if strings.Contains(name, "Azure Edition") || strings.HasPrefix(edition, "serverturbine") {
		return "", fmt.Errorf("Azure Edition hosts run hotpatch builds, which the second check does not re-derive")
	}
	switch {
	case strings.HasPrefix(name, "Windows Server") || (name == "" && strings.HasPrefix(edition, "server")):
		line, ok := windowsServerLines[parts[2]]
		if !ok || (parts[2] == "17763" && !strings.Contains(name, "2019")) {
			return "", fmt.Errorf("Windows Server build %s is not an update line the second check knows", parts[2])
		}
		return line, nil
	case strings.HasPrefix(name, "Windows 1"):
		if line, ok := windowsClientLines[parts[2]]; ok {
			return line, nil
		}
	}
	return "", fmt.Errorf("Windows build %s (%q) is not an update line the second check knows", parts[2], name)
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
	case "Oracle Linux":
		// Regular records apply to every build (as in Oracle's OVAL); a
		// Ksplice or FIPS channel only to that kind of build.
		if eco == "Oracle Linux:"+major {
			return true, false
		}
		return t.oracleBuild != "" && eco == "Oracle Linux:"+major+":"+t.oracleBuild, false
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
