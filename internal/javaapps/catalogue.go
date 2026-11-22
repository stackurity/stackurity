// Package javaapps is Stackurity's curated catalogue of Java web
// applications deployed in a servlet container (Tomcat, Jetty) whose release
// the host agent reads from the application's own files (Apache Roller's
// roller-version.properties), matched against the product's NVD records.
//
// Such an application is not a package any vulnerability source lists by
// name: OSV has no record for Apache Roller as a Maven package, only a Git
// range and NVD's CPE. The agent reports it as pkg:generic/<id> with
// evidence kind "java-webapp" (internal/collect/apps), and the products
// listed here are matched by that release against NVD's ranges for their
// CPE products, as the vendor build and Windows program catalogues are.
// The libraries bundled in WEB-INF/lib are Maven packages, read by the Java
// stack pack and matched against OSV; they are not listed here.
//
// The data is a versioned JSON document (catalogue.json, embedded in the
// binary).
package javaapps

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

// Ecosystem is the base ecosystem Java web application advisories are
// stored under; a product's own ecosystem is Ecosystem + ":" + its id.
const Ecosystem = "Java web applications"

// Kind is the evidence kind of a Java web application the agent identified
// by its own files (internal/collect/apps).
const Kind = "java-webapp"

// Document is the catalogue file.
type Document struct {
	Schema      int       `json:"schema"`
	Version     string    `json:"version"`
	Description string    `json:"description,omitempty"`
	Products    []Product `json:"products"`
}

// Product is one catalogued application.
type Product struct {
	// ID is the purl name the agent reports (pkg:generic/<id>) and names
	// the product's advisories; lower-case words joined by hyphens.
	ID    string `json:"id"`
	Label string `json:"label"`
	// CPEs are the NVD products read ("cpe:2.3:a:<vendor>:<product>"), as
	// in the Windows program catalogue.
	CPEs []string `json:"cpes"`
	// CoverageNote is shown on every evaluated row of the product: what the
	// source is known not to cover.
	CoverageNote string `json:"coverage_note,omitempty"`
	// Update says how the application is updated, for the action plan.
	Update   string   `json:"update,omitempty"`
	Sources  []string `json:"sources"`
	Verified string   `json:"verified"`
	Note     string   `json:"note,omitempty"`
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

// Parse reads and validates a catalogue document.
func Parse(b []byte) (*Catalogue, error) {
	var d Document
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("Java web application catalogue: %w", err)
	}
	if d.Schema != Schema {
		return nil, fmt.Errorf("Java web application catalogue: schema %d, this version reads %d", d.Schema, Schema)
	}
	if d.Version == "" {
		return nil, errors.New("Java web application catalogue: no version")
	}
	c := &Catalogue{doc: d, byID: map[string]*Product{}}
	cpes := map[string]string{}
	for i := range c.doc.Products {
		p := &c.doc.Products[i]
		fail := func(err error) error { return fmt.Errorf("Java web application catalogue: %s: %w", p.ID, err) }
		if !idPattern.MatchString(p.ID) {
			return nil, fmt.Errorf("Java web application catalogue: product %d: id %q is not lower-case words joined by hyphens", i, p.ID)
		}
		if c.byID[p.ID] != nil {
			return nil, fmt.Errorf("Java web application catalogue: %s is listed twice", p.ID)
		}
		if p.Label == "" || len(p.CPEs) == 0 || len(p.Sources) == 0 {
			return nil, fail(errors.New("needs a label, CPEs and sources"))
		}
		if _, err := time.Parse("2006-01-02", p.Verified); err != nil {
			return nil, fail(fmt.Errorf("verified %q is not a date", p.Verified))
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

// Identify returns the product a versionless purl ("pkg:generic/apache-roller")
// names, or nil.
func (c *Catalogue) Identify(purlKey string) *Product {
	id, ok := strings.CutPrefix(purlKey, "pkg:generic/")
	if !ok {
		return nil
	}
	return c.byID[id]
}

// PurlKey is the versionless purl the agent reports the product as.
func (p *Product) PurlKey() string { return "pkg:generic/" + p.ID }

// Release reads the installed release: dotted numbers only, so a
// development build ("6.1.6-SNAPSHOT") is not matched.
func (p *Product) Release(installed string) (string, error) {
	v := strings.TrimSpace(installed)
	if v == "" {
		return "", fmt.Errorf("no version was recorded for %s", p.Label)
	}
	if !dottedNums.MatchString(v) {
		return "", fmt.Errorf("the version %q of %s is not a release (a development or pre-release build)", v, p.Label)
	}
	return v, nil
}

// Ecosystem is the product's own ecosystem string.
func (p *Product) Ecosystem() string { return Ecosystem + ":" + p.ID }

// AdvisoryName is the package name the product's advisories are stored under.
func (p *Product) AdvisoryName() string { return p.ID }

// DisplayLabel is the product's name for people.
func (p *Product) DisplayLabel() string { return p.Label }

// AdvisoryPrefix starts the id of every advisory read for the product,
// unlike the other NVD catalogues' ("NVD-<id>-", "NVD-vendor-<id>-"), as
// advisory ids are unique across feeds.
func (p *Product) AdvisoryPrefix() string { return "NVD-java-" + p.ID + "-" }

// CPEList is the CPE products read from NVD.
func (p *Product) CPEList() []string { return p.CPEs }

// OwnsCPE reports whether a CPE match string names one of the product's CPE
// products with no target software ("*" or "-"): a Java web application is
// one build for every platform.
func (p *Product) OwnsCPE(criteria string) bool {
	return winprograms.CPEsOwn(p.CPEs, criteria, func(string) bool { return false })
}

// PlatformAllows reports whether a platform CPE of an AND configuration
// ("X running on Y") allows the hosts the application is deployed on: any
// operating system, as the application runs on the JVM wherever its
// servlet container does.
func (p *Product) PlatformAllows(criteria string) bool {
	f := winprograms.SplitCPE(criteria)
	return len(f) >= 5 && f[2] == "o"
}

// SourceVersion reads one of NVD's versions; only dotted numbers are read.
func (p *Product) SourceVersion(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if !dottedNums.MatchString(v) {
		return "", false
	}
	return v, true
}
