// Package lifecycle decides which endoflife.date product, and which release
// line of it, a component is. It needs no database: the server feeds it the
// catalogue it stores, and the standalone scanner (pkg/engine) the catalogue
// it downloaded, so both reach the same answer for the same component.
package lifecycle

import (
	"regexp"
	"strings"

	"github.com/stackurity/stackurity/internal/intel/eoloverlay"
)

// OSProducts maps os-release IDs to endoflife.date product names.
var OSProducts = map[string]string{
	"debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine-linux", "rocky": "rocky-linux",
	"almalinux": "almalinux", "rhel": "rhel", "centos": "centos", "amzn": "amazon-linux",
	"fedora": "fedora", "opensuse-leap": "opensuse", "sles": "sles", "ol": "oracle-linux",
	// Not an os-release ID: the macOS agent reports the OS as
	// pkg:generic/macos (internal/collect/darwin).
	"macos": "macos",
}

// versionedPackages match distro packages that carry the upstream release
// in their name, which endoflife.date's package identifiers do not cover
// (its dotnet identifiers name pkg:rpm/redhat/dotnet-sdk-X.Y, a namespace
// the agent never reports). One package per installation is matched (PHP's
// -common is always installed, as is dotnet-runtime-X.Y under the SDK and
// ASP.NET Core runtime) so each runtime yields one finding, not one per
// module.
var versionedPackages = []struct {
	re      *regexp.Regexp // the first group is the release
	product string
}{
	{regexp.MustCompile(`^pkg:deb/[^/]+/php(\d+\.\d+)-common$`), "php"},
	{regexp.MustCompile(`^pkg:deb/[^/]+/ruby(\d+\.\d+)$`), "ruby"},
	// Ubuntu's and Microsoft's deb packages, RHEL's and Microsoft's rpm
	// packages: dotnet-runtime-8.0 is .NET 8 (endoflife.date cycle "8").
	{regexp.MustCompile(`^pkg:(?:deb|rpm)/[^/]+/dotnet-runtime-(\d+\.\d+)$`), "dotnet"},
}

// VersionedPackagesPattern is every versioned-package expression as one
// alternation, for a database regular-expression match (Postgres ~ reads the
// same \d, [^/] and (?:...) syntax).
func VersionedPackagesPattern() string {
	res := make([]string, len(versionedPackages))
	for i, p := range versionedPackages {
		res[i] = p.re.String()
	}
	return strings.Join(res, "|")
}

// VersionedDebProduct returns the endoflife.date product and release cycle
// named by a versioned distro package, e.g. php7.4-common -> php 7.4,
// dotnet-runtime-8.0 -> dotnet 8.0.
func VersionedDebProduct(purlKey string) (product, cycle string, ok bool) {
	for _, p := range versionedPackages {
		if m := p.re.FindStringSubmatch(purlKey); m != nil {
			return p.product, m[1], true
		}
	}
	return "", "", false
}

// Resolver maps components to endoflife.date products: endoflife.date's
// identifiers, the lifecycle overlay (eoloverlay), runtimes and operating
// systems by name, and versioned distro package names.
type Resolver struct {
	ByPurl  map[string]string // endoflife.date purl (lower case, no version) -> product
	Names   map[string]bool   // every endoflife.date product
	Overlay *eoloverlay.Overlay
}

// Match is a component's product and the version its release line is read
// from (the installed version, or the line a package name carries).
type Match struct {
	Product      string
	CycleVersion string
	Rule         string // endoflife.date, namespace_family, overlay, name, package_name
}

// Resolve maps one component. purlKey is its versionless purl; kind is the
// evidence kind (operating-system, runtime, ...) for generic purls.
func (lr *Resolver) Resolve(purlType, purlKey, version, kind string) (Match, bool) {
	ov := lr.Overlay
	if ov == nil {
		ov = eoloverlay.Default()
	}
	if purlType == "generic" && kind == "operating-system" {
		p := OSProducts[strings.TrimPrefix(purlKey, "pkg:generic/")]
		return Match{p, version, "name"}, p != ""
	}
	if m, ok := ov.Product(purlKey, func(k string) string { return lr.ByPurl[k] }); ok && lr.Names[m.Product] {
		cv := version
		if m.Cycle != "" {
			cv = m.Cycle
		}
		return Match{m.Product, cv, m.Rule}, true
	}
	// pkg:generic/<name> where <name> is an endoflife.date product
	// (e.g. amazon-eks, aws-lambda, nginx).
	if name := strings.TrimPrefix(purlKey, "pkg:generic/"); purlType == "generic" && lr.Names[name] {
		return Match{name, version, "name"}, true
	}
	if purlType == "deb" || purlType == "rpm" {
		if p, cycle, ok := VersionedDebProduct(purlKey); ok && lr.Names[p] {
			return Match{p, cycle, "package_name"}, true
		}
	}
	return Match{}, false
}

// CycleIndex finds the release cycle for a version among cycle names: exact,
// then the longest dotted prefix ("3.19.1" -> "3.19" -> "3"). -1 when none.
func CycleIndex(cycles []string, v string) int {
	v = strings.TrimPrefix(v, "v")
	// A Debian or RPM epoch ("5:27.3.1-1~ubuntu.24.04~noble", Docker; "1:10.11.6",
	// MariaDB) is not part of the upstream release.
	if e, rest, ok := strings.Cut(v, ":"); ok && e != "" && strings.Trim(e, "0123456789") == "" {
		v = rest
	}
	if i := strings.IndexAny(v, "-+~_ "); i > 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	for n := len(parts); n >= 1; n-- {
		cand := strings.Join(parts[:n], ".")
		for i := range cycles {
			if cycles[i] == cand {
				return i
			}
		}
	}
	return -1
}
