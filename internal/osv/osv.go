// Package osv parses OSV advisories, maps package URLs to OSV ecosystems and
// decides whether a version is affected.
// Schema: https://ossf.github.io/osv-schema/
package osv

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/version"
)

type Vulnerability struct {
	ID               string          `json:"id"`
	Modified         time.Time       `json:"modified"`
	Published        time.Time       `json:"published"`
	Withdrawn        *time.Time      `json:"withdrawn,omitempty"`
	Aliases          []string        `json:"aliases"`
	Upstream         []string        `json:"upstream"`
	Related          []string        `json:"related"`
	Summary          string          `json:"summary"`
	Details          string          `json:"details"`
	Severity         []Severity      `json:"severity"`
	Affected         []Affected      `json:"affected"`
	References       []Reference     `json:"references"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl"`
}

type Affected struct {
	Package           Package         `json:"package"`
	Severity          []Severity      `json:"severity"`
	Ranges            []Range         `json:"ranges"`
	Versions          []string        `json:"versions"`
	EcosystemSpecific json.RawMessage `json:"ecosystem_specific"`
	DatabaseSpecific  json.RawMessage `json:"database_specific"`
}

type Range struct {
	Type   string  `json:"type"` // SEMVER, ECOSYSTEM, GIT
	Events []Event `json:"events"`
}

type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Target is where an installed component lives in OSV terms.
type Target struct {
	Ecosystem string // e.g. "npm", "Packagist", "Debian:12", "Alpine:v3.19"
	Name      string // OSV package name (source package for distros)
	Version   string
	Compare   version.Ecosystem
}

// TargetFor maps a purl (with version and qualifiers) to an OSV target. ok is
// false when the ecosystem is not supported yet; callers record that as
// coverage rather than treating the component as clean.
func TargetFor(purl, ver string, evidence map[string]string) (Target, bool) {
	p, err := packageurl.FromString(purl)
	if err != nil {
		return Target{}, false
	}
	q := p.Qualifiers.Map()
	if ver == "" {
		ver = p.Version
	}
	t := Target{Version: ver, Compare: version.ForPurlType(p.Type)}
	source := q["upstream"]
	if source == "" && evidence != nil {
		source = evidence["source_package"]
	}
	// Strip any "(version)" an upstream qualifier may carry.
	if i := strings.IndexByte(source, ' '); i > 0 {
		source = source[:i]
	}
	switch p.Type {
	case "npm":
		t.Ecosystem, t.Name = "npm", joinNS(p.Namespace, p.Name)
	case "composer":
		t.Ecosystem, t.Name = "Packagist", joinNS(p.Namespace, p.Name)
	case "pypi":
		t.Ecosystem, t.Name = "PyPI", p.Name
	case "golang":
		t.Ecosystem, t.Name = "Go", joinNS(p.Namespace, p.Name)
	case "cargo":
		t.Ecosystem, t.Name = "crates.io", p.Name
	case "gem":
		t.Ecosystem, t.Name = "RubyGems", p.Name
	case "maven":
		t.Ecosystem, t.Name = "Maven", p.Namespace+":"+p.Name
	case "nuget":
		t.Ecosystem, t.Name = "NuGet", p.Name
	case "pub":
		t.Ecosystem, t.Name = "Pub", p.Name
	case "deb":
		distro := q["distro"] // e.g. debian-12, ubuntu-22.04
		name := p.Name
		if source != "" {
			name = source
		}
		switch strings.ToLower(p.Namespace) {
		case "debian":
			rel := strings.TrimPrefix(distro, "debian-")
			if rel == "" || rel == distro {
				return Target{}, false
			}
			t.Ecosystem, t.Name = "Debian:"+majorOf(rel), name
		case "ubuntu":
			rel := strings.TrimPrefix(distro, "ubuntu-")
			if rel == "" || rel == distro {
				return Target{}, false
			}
			t.Ecosystem, t.Name = "Ubuntu:"+rel, name // ":LTS" suffix handled by MatchEcosystem
		default:
			return Target{}, false
		}
	case "apk":
		distro := q["distro"] // alpine-3.19.1
		rel := strings.TrimPrefix(distro, "alpine-")
		if strings.ToLower(p.Namespace) != "alpine" || rel == "" || rel == distro {
			return Target{}, false
		}
		name := p.Name
		if source != "" {
			name = source
		}
		t.Ecosystem, t.Name = "Alpine:v"+majorMinor(rel), name
	case "rpm":
		// distro is "<os-release ID>-<VERSION_ID>": rocky-9.3, rhel-9.4,
		// sles-15.5, opensuse-leap-15.5, amzn-2023. The agent uses the ID as
		// namespace; Syft uses vendor names (redhat, amazon), so the
		// qualifier decides.
		id, rel := rpmDistro(q["distro"])
		if id == "" {
			return Target{}, false
		}
		// Red Hat, Alma and Amazon advisories name binary packages; Rocky
		// and SUSE advisories name the source package (RLSA records list
		// "openssl", never "openssl-libs").
		name := p.Name
		srpm := ""
		if evidence != nil {
			srpm = evidence["source_rpm"]
		}
		if srpm == "" {
			srpm = q["upstream"] // Syft: the source rpm file name
		}
		switch id {
		case "rocky":
			t.Ecosystem = "Rocky Linux:" + majorOf(rel)
			if src := sourceRPMName(srpm); src != "" {
				name = src
			}
		case "almalinux":
			t.Ecosystem = "AlmaLinux:" + majorOf(rel)
		case "rhel":
			t.Ecosystem = "Red Hat:enterprise_linux:" + majorOf(rel)
		case "amzn":
			if rel != "2" && rel != "2023" {
				return Target{}, false // Amazon Linux 1 and unknown releases
			}
			t.Ecosystem = "Amazon Linux:" + rel
		case "sles", "sles_sap", "sled":
			sp := suseServicePack(rel)
			if sp == "" {
				return Target{}, false
			}
			t.Ecosystem = "SUSE:" + sp
			if src := sourceRPMName(srpm); src != "" {
				name = src
			}
		case "opensuse-leap":
			t.Ecosystem = "openSUSE:Leap " + rel
			if src := sourceRPMName(srpm); src != "" {
				name = src
			}
		}
		t.Name = name
		if evr := evidence["evr"]; evr != "" {
			t.Version = evr
		} else if e := q["epoch"]; e != "" && e != "0" && !strings.Contains(t.Version, ":") {
			t.Version = e + ":" + t.Version
		}
	default:
		return Target{}, false
	}
	return t, t.Name != "" && t.Version != ""
}

func joinNS(ns, name string) string {
	if ns == "" {
		return name
	}
	return ns + "/" + name
}

func majorOf(v string) string {
	m, _, _ := strings.Cut(v, ".")
	return m
}

// rpmDistros are the os-release IDs with an advisory source, longest first
// so "sles_sap" is not read as "sles". CentOS, Oracle Linux and Fedora have
// none yet.
var rpmDistros = []string{"opensuse-leap", "almalinux", "sles_sap", "rocky", "rhel", "amzn", "sles", "sled"}

// rpmDistro splits a distro qualifier ("rhel-9.4") into a supported ID and
// its release.
func rpmDistro(distro string) (id, rel string) {
	for _, d := range rpmDistros {
		if r, ok := strings.CutPrefix(distro, d+"-"); ok && r != "" {
			return d, r
		}
	}
	return "", ""
}

// suseServicePack turns a SLES VERSION_ID into the product suffix SUSE
// advisories use: "15.5" -> "15 SP5", "15" -> "15".
func suseServicePack(rel string) string {
	major, sp, ok := strings.Cut(rel, ".")
	if major == "" || !isDigits(major) {
		return ""
	}
	if !ok || sp == "0" {
		return major
	}
	if !isDigits(sp) {
		return ""
	}
	return major + " SP" + sp
}

// sourceRPMName extracts the package name from a SOURCERPM value such as
// "openssl-3-3.0.8-150500.5.3.1.src.rpm" (name-version-release.src.rpm).
func sourceRPMName(srpm string) string {
	s := strings.TrimSuffix(strings.TrimSuffix(srpm, ".src.rpm"), ".nosrc.rpm")
	if s == srpm {
		return ""
	}
	for i := 0; i < 2; i++ {
		j := strings.LastIndexByte(s, '-')
		if j <= 0 {
			return ""
		}
		s = s[:j]
	}
	return s
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func majorMinor(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return v
}

// BaseEcosystem returns the OSV bulk-download folder for an ecosystem
// string ("Debian:12" -> "Debian").
func BaseEcosystem(eco string) string {
	b, _, _ := strings.Cut(eco, ":")
	return b
}

// MatchEcosystem reports whether an advisory's ecosystem string applies to
// the target's. Ubuntu advisories carry suffixes such as ":LTS", and Ubuntu
// Pro (ESM) advisories use "Ubuntu:Pro:<release>"; both match the release.
// Red Hat advisories name a repository after the release
// ("Red Hat:enterprise_linux:9::appstream"); minor-release streams
// (rhel_eus, rhel_aus) are separate products and do not match. A SUSE
// target "SUSE:15 SP5" matches every product of that service pack
// ("SUSE:Linux Enterprise Module for Basesystem 15 SP5") and its extended
// support channels ("... 15 SP5-LTSS"). Use Subscription to tell
// subscription-only fixes apart.
func MatchEcosystem(advisory, target string) bool {
	if advisory == target {
		return true
	}
	switch {
	case strings.HasPrefix(target, "Ubuntu:") && strings.HasPrefix(advisory, "Ubuntu:"):
		rel := strings.TrimPrefix(target, "Ubuntu:")
		for _, part := range strings.Split(strings.TrimPrefix(advisory, "Ubuntu:"), ":") {
			if part == rel {
				return true
			}
		}
	case strings.HasPrefix(target, "Red Hat:"):
		return strings.HasPrefix(advisory, target+"::")
	case strings.HasPrefix(target, "SUSE:") && strings.HasPrefix(advisory, "SUSE:"):
		_, ok := suseChannel(advisory, strings.TrimPrefix(target, "SUSE:"))
		return ok
	}
	return false
}

// suseChannel matches a SUSE product ecosystem against a service pack
// ("15 SP5") and returns the extended support suffix ("LTSS"), if any.
func suseChannel(advisory, sp string) (suffix string, ok bool) {
	product := strings.TrimPrefix(advisory, "SUSE:")
	if i := strings.LastIndex(product, " "+sp); i >= 0 {
		rest := product[i+len(sp)+1:]
		if rest == "" {
			return "", true
		}
		if s, found := strings.CutPrefix(rest, "-"); found && s != "" && !strings.ContainsAny(s, " ") {
			return s, true
		}
	}
	return "", false
}

// IsPro reports whether an ecosystem is a subscription channel whose fixes
// need a paid subscription (Ubuntu Pro, SUSE LTSS).
func IsPro(ecosystem string) bool { return Subscription(ecosystem) != "" }

// Subscription names the paid channel an advisory ecosystem belongs to, or
// "" for a release's free updates.
func Subscription(ecosystem string) string {
	switch {
	case strings.HasPrefix(ecosystem, "Ubuntu:Pro:"):
		return "Ubuntu Pro"
	case strings.HasPrefix(ecosystem, "SUSE:"):
		if m := suseExtended.FindStringSubmatch(ecosystem); m != nil {
			return "SUSE " + m[1]
		}
	}
	return ""
}

// suseExtended matches extended support channels such as
// "SUSE:Linux Enterprise Server 15 SP5-LTSS".
var suseExtended = regexp.MustCompile(` \d+(?: SP\d+)?-([A-Za-z0-9-]+)$`)

// Match is the result of checking one Affected entry.
type Match struct {
	Affected     bool
	FixedVersion string // lowest fix above the installed version, if known
	Range        string // human-readable description of the matched range
	Exact        bool   // matched through the explicit versions list
}

// Check evaluates whether target.Version falls in a's ranges or versions.
func Check(a Affected, t Target) (Match, error) {
	cmp := version.For(t.Compare)
	var firstErr error
	for _, v := range a.Versions {
		if v == t.Version {
			m := Match{Affected: true, Exact: true, Range: "listed version " + v}
			m.FixedVersion = lowestFixAbove(a, t.Version, cmp)
			return m, nil
		}
	}
	for _, r := range a.Ranges {
		if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
			continue // GIT ranges need commit data we do not have
		}
		c := cmp
		if r.Type == "SEMVER" {
			c = version.CompareSemver
		}
		hit, desc, err := inRange(r.Events, t.Version, c)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if hit {
			return Match{Affected: true, Range: desc, FixedVersion: lowestFixAbove(a, t.Version, cmp)}, nil
		}
	}
	return Match{}, firstErr
}

// inRange implements the OSV evaluation algorithm: sort events, then walk
// them tracking whether the version is inside an introduced..fixed span.
func inRange(events []Event, v string, cmp version.Comparator) (bool, string, error) {
	type ev struct {
		kind, ver string
	}
	var list []ev
	for _, e := range events {
		switch {
		case e.Introduced != "":
			list = append(list, ev{"introduced", e.Introduced})
		case e.Fixed != "":
			list = append(list, ev{"fixed", e.Fixed})
		case e.LastAffected != "":
			list = append(list, ev{"last_affected", e.LastAffected})
		case e.Limit != "":
			list = append(list, ev{"limit", e.Limit})
		}
	}
	var sortErr error
	cmpEv := func(a, b string) int {
		if a == b {
			return 0
		}
		if a == "0" {
			return -1
		}
		if b == "0" {
			return 1
		}
		c, err := cmp(a, b)
		if err != nil && sortErr == nil {
			sortErr = err
		}
		return c
	}
	sort.SliceStable(list, func(i, j int) bool { return cmpEv(list[i].ver, list[j].ver) < 0 })
	if sortErr != nil {
		return false, "", sortErr
	}
	affected := false
	start := ""
	for _, e := range list {
		var c int
		if e.ver == "0" {
			c = 1 // every version is >= "0"
		} else {
			var err error
			if c, err = cmp(v, e.ver); err != nil {
				return false, "", err
			}
		}
		switch e.kind {
		case "introduced":
			if c >= 0 {
				affected, start = true, e.ver
			}
		case "fixed", "limit":
			if c >= 0 {
				affected = false
			} else if affected {
				return true, describe(start, "<", e.ver), nil
			}
		case "last_affected":
			if c > 0 {
				affected = false
			} else if affected {
				return true, describe(start, "<=", e.ver), nil
			}
		}
	}
	if affected {
		return true, describe(start, "", ""), nil
	}
	return false, "", nil
}

func describe(from, op, to string) string {
	s := ">= " + from
	if from == "0" {
		s = "all versions"
	}
	if op != "" {
		if from == "0" {
			return op + " " + to
		}
		s += ", " + op + " " + to
	}
	return s
}

func lowestFixAbove(a Affected, installed string, cmp version.Comparator) string {
	best := ""
	for _, r := range a.Ranges {
		for _, e := range r.Events {
			if e.Fixed == "" {
				continue
			}
			if c, err := cmp(e.Fixed, installed); err != nil || c <= 0 {
				continue
			}
			if best == "" {
				best = e.Fixed
			} else if c, err := cmp(e.Fixed, best); err == nil && c < 0 {
				best = e.Fixed
			}
		}
	}
	return best
}

// GroupKey picks a stable identity for deduplicating equivalent advisories:
// the lowest CVE among id, aliases and upstream ids, else the id itself.
// Distro records such as DEBIAN-CVE-2024-1234 carry the CVE in "upstream".
func GroupKey(id string, aliases []string, upstream ...string) string {
	best := ""
	ids := append(append([]string{id}, aliases...), upstream...)
	for _, a := range ids {
		if strings.HasPrefix(a, "CVE-") && (best == "" || a < best) {
			best = a
		}
	}
	if best != "" {
		return best
	}
	return id
}
