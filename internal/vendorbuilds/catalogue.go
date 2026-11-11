// Package vendorbuilds is Stackurity's curated catalogue of vendor builds of
// Linux packages: products a vendor ships from its own APT or RPM repository
// (nginx.org, NodeSource, PGDG, Ondřej Surý's PHP packages, MongoDB, Redis,
// MariaDB, MySQL, Elastic, HashiCorp) that are matched against the upstream
// product's NVD records.
//
// The distribution's advisories describe the distribution's own builds, so
// a vendor's build is not matched against them (internal/intel recognises
// one by its package name or version form). Vendor repositories ship the
// upstream release itself (nginx 1.26.2-1~jammy is nginx 1.26.2), so its
// upstream version can be matched against NVD's ranges for the product.
// Only the packages listed here are: a package of the product's own
// version (nginx, php8.3-common), never a separately versioned one built
// alongside it (php8.3-redis, a PECL extension, has its own version).
//
// The data is a versioned JSON document (catalogue.json, embedded in the
// binary). Every pattern is a regular expression anchored at both ends and
// matched without regard to case.
package vendorbuilds

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/stackurity/stackurity/internal/winprograms"
)

//go:embed catalogue.json
var embedded []byte

// Schema is the document version this code reads.
const Schema = 1

// Ecosystem is the base ecosystem vendor build advisories are stored under;
// a product's own ecosystem is Ecosystem + ":" + its id.
const Ecosystem = "Vendor builds"

// defaultVersion reads the upstream version of most vendor builds: an
// optional epoch, the upstream release, and the packaging revision
// ("6:7.4.1-1rl1~jammy1" is 7.4.1). A pre-release ("2.0.0~rc1-1") or an
// edition marker ("1.20.1+ent-1") does not match.
const defaultVersion = `^(?:\d+:)?(\d+(?:\.\d+)+)(?:-.*)?$`

// Document is the catalogue file.
type Document struct {
	Schema      int       `json:"schema"`
	Version     string    `json:"version"`
	Description string    `json:"description,omitempty"`
	Products    []Product `json:"products"`
}

// Product is one catalogued product.
type Product struct {
	// ID names the product's advisories (package name) and is lower case
	// letters, digits and hyphens.
	ID    string `json:"id"`
	Label string `json:"label"`
	// Packages match "<purl type>/<package name>" ("deb/nginx",
	// "rpm/php-common"). When several of a product's packages are installed
	// at one version on a host, its findings are reported once, on the
	// package of the earliest pattern that matches.
	Packages []string `json:"packages"`
	// Version reads the upstream version from the installed package
	// version, in its first group; defaultVersion when empty.
	Version string `json:"version,omitempty"`
	// SideBySide is "major" or "major.minor" for a product whose release
	// lines install side by side (postgresql-15 and postgresql-16, php8.2
	// and php8.3): each line is updated on its own.
	SideBySide string `json:"side_by_side,omitempty"`
	// CPEs are the NVD products read, as in the Windows program catalogue
	// ("cpe:2.3:a:<vendor>:<product>", optionally with further fields that
	// must match, such as a sw_edition).
	CPEs []string `json:"cpes"`
	// CoverageNote is shown on every evaluated row of the product: what the
	// source is known not to cover.
	CoverageNote string `json:"coverage_note,omitempty"`
	// Update says how the product is usually updated, for the action plan.
	Update   string   `json:"update,omitempty"`
	Sources  []string `json:"sources"`
	Verified string   `json:"verified"`
	Note     string   `json:"note,omitempty"`

	packages []*regexp.Regexp
	version  *regexp.Regexp
}

var (
	idPattern  = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	dottedNums = regexp.MustCompile(`^\d+(?:\.\d+)*$`)
	cpePattern = regexp.MustCompile(`^cpe:2\.3:a:[^:*]+:[^:*]+(?::\*:\*(?::[^:]+){0,6})?$`)
)

// Catalogue is a parsed, validated document.
type Catalogue struct {
	doc  Document
	byID map[string]*Product
}

func compileAnchored(what, p string) (*regexp.Regexp, error) {
	if !strings.HasPrefix(p, "^") || !strings.HasSuffix(p, "$") {
		return nil, fmt.Errorf("%s pattern %q must be anchored with ^ and $", what, p)
	}
	re, err := regexp.Compile("(?i)" + p)
	if err != nil {
		return nil, fmt.Errorf("%s pattern %q: %w", what, p, err)
	}
	return re, nil
}

// Parse reads and validates a catalogue document.
func Parse(b []byte) (*Catalogue, error) {
	var d Document
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("vendor build catalogue: %w", err)
	}
	if d.Schema != Schema {
		return nil, fmt.Errorf("vendor build catalogue: schema %d, this version reads %d", d.Schema, Schema)
	}
	if d.Version == "" {
		return nil, errors.New("vendor build catalogue: no version")
	}
	c := &Catalogue{doc: d, byID: map[string]*Product{}}
	cpes := map[string]string{}
	for i := range c.doc.Products {
		p := &c.doc.Products[i]
		fail := func(err error) error { return fmt.Errorf("vendor build catalogue: %s: %w", p.ID, err) }
		if !idPattern.MatchString(p.ID) {
			return nil, fmt.Errorf("vendor build catalogue: product %d: id %q is not lower-case words joined by hyphens", i, p.ID)
		}
		if c.byID[p.ID] != nil {
			return nil, fmt.Errorf("vendor build catalogue: %s is listed twice", p.ID)
		}
		if p.Label == "" || len(p.Packages) == 0 || len(p.CPEs) == 0 || len(p.Sources) == 0 {
			return nil, fail(errors.New("needs a label, packages, CPEs and sources"))
		}
		if _, err := time.Parse("2006-01-02", p.Verified); err != nil {
			return nil, fail(fmt.Errorf("verified %q is not a date", p.Verified))
		}
		for _, s := range p.Packages {
			re, err := compileAnchored("package", s)
			if err != nil {
				return nil, fail(err)
			}
			if !strings.HasPrefix(s, "^deb/") && !strings.HasPrefix(s, "^rpm/") {
				return nil, fail(fmt.Errorf("package pattern %q must start with ^deb/ or ^rpm/", s))
			}
			p.packages = append(p.packages, re)
		}
		vp := p.Version
		if vp == "" {
			vp = defaultVersion
		}
		re, err := compileAnchored("version", vp)
		if err != nil {
			return nil, fail(err)
		}
		if re.NumSubexp() < 1 {
			return nil, fail(fmt.Errorf("version pattern %q has no group for the upstream version", vp))
		}
		p.version = re
		if p.SideBySide != "" && p.SideBySide != "major" && p.SideBySide != "major.minor" {
			return nil, fail(fmt.Errorf("side_by_side %q is not major or major.minor", p.SideBySide))
		}
		for _, cpe := range p.CPEs {
			if !cpePattern.MatchString(cpe) {
				return nil, fail(fmt.Errorf("CPE %q is not cpe:2.3:a:<vendor>:<product>[:*:*:<more fields>]", cpe))
			}
			if prev, dup := cpes[cpe]; dup {
				return nil, fail(fmt.Errorf("CPE %s is also the source of %s", cpe, prev))
			}
			cpes[cpe] = p.ID
		}
		c.byID[p.ID] = p
	}
	// A package belongs to one product at most.
	for _, p := range c.doc.Products {
		for _, q := range c.doc.Products {
			if p.ID >= q.ID {
				continue
			}
			for _, s := range p.Packages {
				for _, t := range q.Packages {
					if s == t {
						return nil, fmt.Errorf("vendor build catalogue: package pattern %s is listed for %s and %s", s, p.ID, q.ID)
					}
				}
			}
		}
	}
	return c, nil
}

var (
	defaultOnce sync.Once
	defaultCat  *Catalogue
)

// Default returns the catalogue embedded in the binary.
func Default() *Catalogue {
	defaultOnce.Do(func() {
		c, err := Parse(embedded)
		if err != nil {
			panic(err)
		}
		defaultCat = c
	})
	return defaultCat
}

// Version is the document's version.
func (c *Catalogue) Version() string { return c.doc.Version }

// Products lists the catalogued products in document order.
func (c *Catalogue) Products() []*Product {
	out := make([]*Product, len(c.doc.Products))
	for i := range c.doc.Products {
		out[i] = &c.doc.Products[i]
	}
	return out
}

// Product returns the product with an id, or nil.
func (c *Catalogue) Product(id string) *Product { return c.byID[id] }

// Identify returns the product a package of a purl type ("deb", "rpm") and
// name belongs to, and the rank of the pattern it matched (lower is where
// findings are reported), or nil.
func (c *Catalogue) Identify(purlType, name string) (*Product, int) {
	key := strings.ToLower(purlType) + "/" + name
	for i := range c.doc.Products {
		p := &c.doc.Products[i]
		for rank, re := range p.packages {
			if re.MatchString(key) {
				return p, rank
			}
		}
	}
	return nil, 0
}

// NamePattern is one regular expression (POSIX, for a database query)
// matching the name of every package the catalogue lists, whatever its
// type; Identify decides.
func (c *Catalogue) NamePattern() string {
	var alts []string
	for _, p := range c.doc.Products {
		for _, s := range p.Packages {
			s = strings.TrimSuffix(strings.TrimPrefix(s, "^"), "$")
			_, name, _ := strings.Cut(s, "/")
			alts = append(alts, "(?:"+name+")")
		}
	}
	return "^(?:" + strings.Join(alts, "|") + ")$"
}

// UpstreamVersion reads the upstream version from an installed package
// version ("1:11.4.3+maria~ubu2404" is 11.4.3).
func (p *Product) UpstreamVersion(installed string) (string, error) {
	v := strings.TrimSpace(installed)
	if v == "" {
		return "", fmt.Errorf("no version was recorded for %s", p.Label)
	}
	m := p.version.FindStringSubmatch(v)
	if m == nil || !dottedNums.MatchString(m[1]) {
		return "", fmt.Errorf("the version %q of %s is not in the form the vendor build catalogue reads (a pre-release or another edition)", v, p.Label)
	}
	return m[1], nil
}

// Ecosystem is the product's own ecosystem string.
func (p *Product) Ecosystem() string { return Ecosystem + ":" + p.ID }

// AdvisoryName is the package name the product's advisories are stored under.
func (p *Product) AdvisoryName() string { return p.ID }

// DisplayLabel is the product's name for people.
func (p *Product) DisplayLabel() string { return p.Label }

// AdvisoryPrefix starts the id of every advisory read for the product. It
// differs from the Windows programs' ("NVD-<id>-"), as advisory ids are
// unique across feeds.
func (p *Product) AdvisoryPrefix() string { return "NVD-vendor-" + p.ID + "-" }

// CPEList is the CPE products read from NVD.
func (p *Product) CPEList() []string { return p.CPEs }

// OwnsCPE reports whether a CPE match string names one of the product's
// CPE products, in an edition it reads, for Linux or any platform.
func (p *Product) OwnsCPE(criteria string) bool {
	return winprograms.CPEsOwn(p.CPEs, criteria, func(ts string) bool { return strings.Contains(ts, "linux") })
}

// linuxVendors are the operating system CPE vendors of Linux distributions
// whose product names do not say "linux" (fedoraproject:fedora).
var linuxVendors = map[string]bool{"fedoraproject": true, "redhat": true, "centos": true, "rockylinux": true, "almalinux": true,
	"opensuse": true, "suse": true, "debian": true, "canonical": true, "amazon": true, "oracle": true}

// PlatformAllows reports whether a platform CPE of an AND configuration
// ("X running on Y") allows a Linux host: Linux, a Linux distribution, or
// any operating system ("*").
func (p *Product) PlatformAllows(criteria string) bool {
	f := winprograms.SplitCPE(criteria)
	if len(f) < 5 || f[2] != "o" {
		return false
	}
	vendor, product := strings.ToLower(f[3]), strings.ToLower(f[4])
	switch {
	case vendor == "*":
		return true
	case strings.Contains(product, "linux"):
		return true
	case linuxVendors[vendor] && !strings.Contains(product, "windows"):
		return true
	}
	return false
}

// SourceVersion reads one of NVD's versions; only dotted numbers are read.
func (p *Product) SourceVersion(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if !dottedNums.MatchString(v) {
		return "", false
	}
	return v, true
}

// Line is the release line an upstream version is on, for a product whose
// lines install side by side ("16" for PostgreSQL 16.4, "8.3" for PHP
// 8.3.13); "" for other products.
func (p *Product) Line(version string) string {
	parts := strings.Split(version, ".")
	switch {
	case p.SideBySide == "major":
		return parts[0]
	case p.SideBySide == "major.minor" && len(parts) >= 2:
		return parts[0] + "." + parts[1]
	}
	return ""
}
