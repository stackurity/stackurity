// Package eoloverlay is Stackurity's own lifecycle mapping data, applied on
// top of endoflife.date: package URLs endoflife.date does not list for a
// product it tracks (MongoDB's mongodb-org-server, Docker's docker-ce,
// Electron on npm), release lines read from package names (postgresql-16,
// temurin-21-jdk), packages only a vendor's own repository ships, and
// products no lifecycle source tracks at all.
//
// The data is a versioned JSON document (lifecycle_overlay.json, embedded
// in the binary). Parse reads any copy of it, so the same document can later
// be fetched as a feed and replace the embedded one without code changes.
//
// Rules, in order of precedence, for a component's versionless purl:
//
//  1. An overlay entry marked "override" that matches.
//  2. endoflife.date's own purl identifiers (exact match).
//  3. endoflife.date's identifier for the same package name in another
//     namespace of a namespace family (pkg:rpm/rocky/nginx uses
//     pkg:rpm/redhat/nginx), when the overlay declares that family.
//  4. Other overlay entries.
//
// So the overlay never replaces a mapping endoflife.date provides unless an
// entry says so explicitly.
package eoloverlay

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed lifecycle_overlay.json
var embedded []byte

// Schema is the document version this code reads.
const Schema = 1

// Document is the overlay as stored.
type Document struct {
	Schema      int    `json:"schema"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	// Families are namespaces whose packages share names: a purl in one may
	// use endoflife.date's identifier from another.
	Families []Family `json:"namespace_families"`
	Products []Entry  `json:"products"`
	// Untracked are products recognised by purl that no lifecycle source
	// tracks; they are counted in the coverage-gap report.
	Untracked []Untracked `json:"untracked"`
}

type Family struct {
	Type       string   `json:"type"`
	Namespaces []string `json:"namespaces"`
	Why        string   `json:"why"`
}

// Entry maps purl patterns to one endoflife.date product.
//
// A pattern is "pkg:<type>/<namespace>/<name>" or "pkg:<type>/<name>". The
// namespace may be "*" (any non-empty namespace). The name may contain
// "{cycle}", which matches a dotted number and names the release line
// (pkg:deb/*/postgresql-{cycle}); otherwise the line is read from the
// installed version.
type Entry struct {
	Product string   `json:"product"`
	Purls   []string `json:"purls"`
	// CycleAliases rewrites a release line read from a name
	// ("1.8.0" -> "8").
	CycleAliases map[string]string `json:"cycle_aliases,omitempty"`
	// VendorOnly names the repository that ships these packages when no
	// distribution ships a package of that name: every match is a vendor
	// build, never a distribution's own package.
	VendorOnly string `json:"vendor_only,omitempty"`
	// VendorBuilds recognise a vendor's build of a package name the
	// distribution also ships, by its version.
	VendorBuilds []VendorBuild `json:"vendor_builds,omitempty"`
	// Override lets this entry replace endoflife.date's own mapping.
	Override bool     `json:"override,omitempty"`
	Sources  []string `json:"sources"`
	Verified string   `json:"verified"`
	Note     string   `json:"note,omitempty"`
}

type VendorBuild struct {
	Repository string `json:"repository"`
	Version    string `json:"version"` // regular expression on the installed version
}

type Untracked struct {
	Label   string   `json:"label"`
	Purls   []string `json:"purls"`
	Why     string   `json:"why"`
	Sources []string `json:"sources"`
	Checked string   `json:"checked"`
}

// Overlay is a parsed, validated document.
type Overlay struct {
	doc      Document
	rules    map[string][]*rule // by purl type
	untrack  map[string][]*rule
	families map[string]map[string][]string // type -> namespace -> the others
}

type rule struct {
	typ, ns, name string         // lower case; ns "*" is any non-empty namespace
	nameRe        *regexp.Regexp // when the name has {cycle}
	entry         *Entry
	vendor        []*regexp.Regexp
	label         string // untracked
}

const cyclePart = `(\d+(?:\.\d+)*)`

// Parse reads and validates an overlay document.
func Parse(b []byte) (*Overlay, error) {
	var d Document
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("lifecycle overlay: %w", err)
	}
	if d.Schema != Schema {
		return nil, fmt.Errorf("lifecycle overlay: schema %d, this version reads %d", d.Schema, Schema)
	}
	if d.Version == "" {
		return nil, errors.New("lifecycle overlay: no version")
	}
	o := &Overlay{doc: d, rules: map[string][]*rule{}, untrack: map[string][]*rule{}, families: map[string]map[string][]string{}}
	for _, f := range d.Families {
		if f.Type == "" || len(f.Namespaces) < 2 {
			return nil, fmt.Errorf("lifecycle overlay: family %q needs a type and two or more namespaces", f.Type)
		}
		m := o.families[f.Type]
		if m == nil {
			m = map[string][]string{}
			o.families[f.Type] = m
		}
		for _, ns := range f.Namespaces {
			if _, dup := m[ns]; dup {
				return nil, fmt.Errorf("lifecycle overlay: namespace %s/%s is in two families", f.Type, ns)
			}
			for _, other := range f.Namespaces {
				if other != ns {
					m[ns] = append(m[ns], other)
				}
			}
		}
	}
	seen := map[string]string{}
	for i := range o.doc.Products {
		e := &o.doc.Products[i]
		if e.Product == "" || len(e.Purls) == 0 {
			return nil, fmt.Errorf("lifecycle overlay: product %d needs a product and purls", i)
		}
		if len(e.Sources) == 0 {
			return nil, fmt.Errorf("lifecycle overlay: %s: no sources", e.Product)
		}
		if _, err := time.Parse("2006-01-02", e.Verified); err != nil {
			return nil, fmt.Errorf("lifecycle overlay: %s: verified %q is not a date", e.Product, e.Verified)
		}
		var vendor []*regexp.Regexp
		for _, vb := range e.VendorBuilds {
			re, err := regexp.Compile(vb.Version)
			if err != nil || vb.Repository == "" {
				return nil, fmt.Errorf("lifecycle overlay: %s: vendor build %q: needs a repository and a valid pattern", e.Product, vb.Version)
			}
			vendor = append(vendor, re)
		}
		for _, p := range e.Purls {
			r, err := parsePattern(p)
			if err != nil {
				return nil, fmt.Errorf("lifecycle overlay: %s: %w", e.Product, err)
			}
			if prev, dup := seen[strings.ToLower(p)]; dup {
				return nil, fmt.Errorf("lifecycle overlay: %s is mapped to both %s and %s", p, prev, e.Product)
			}
			seen[strings.ToLower(p)] = e.Product
			r.entry, r.vendor = e, vendor
			o.rules[r.typ] = append(o.rules[r.typ], r)
		}
	}
	for i := range o.doc.Untracked {
		u := &o.doc.Untracked[i]
		if u.Label == "" || len(u.Purls) == 0 || u.Why == "" || len(u.Sources) == 0 {
			return nil, fmt.Errorf("lifecycle overlay: untracked %d needs a label, purls, why and sources", i)
		}
		for _, p := range u.Purls {
			r, err := parsePattern(p)
			if err != nil {
				return nil, fmt.Errorf("lifecycle overlay: %s: %w", u.Label, err)
			}
			if r.nameRe != nil {
				return nil, fmt.Errorf("lifecycle overlay: %s: untracked purls cannot name a release line", u.Label)
			}
			if prev, dup := seen[strings.ToLower(p)]; dup {
				return nil, fmt.Errorf("lifecycle overlay: %s is mapped to both %s and untracked %s", p, prev, u.Label)
			}
			seen[strings.ToLower(p)] = u.Label
			r.label = u.Label
			o.untrack[r.typ] = append(o.untrack[r.typ], r)
		}
	}
	return o, nil
}

func parsePattern(p string) (*rule, error) {
	typ, ns, name, ok := SplitKey(p)
	if !ok || name == "" {
		return nil, fmt.Errorf("purl pattern %q: want pkg:<type>/[<namespace>/]<name>", p)
	}
	if strings.ContainsAny(p, "@?#") {
		return nil, fmt.Errorf("purl pattern %q: no version, qualifiers or subpath", p)
	}
	r := &rule{typ: typ, ns: ns, name: name}
	if n := strings.Count(name, "{cycle}"); n > 1 {
		return nil, fmt.Errorf("purl pattern %q: at most one {cycle}", p)
	} else if n == 1 {
		before, after, _ := strings.Cut(name, "{cycle}")
		r.nameRe = regexp.MustCompile("^" + regexp.QuoteMeta(before) + cyclePart + regexp.QuoteMeta(after) + "$")
	}
	return r, nil
}

// SplitKey splits a versionless purl ("pkg:deb/ubuntu/nginx") into lower-case
// type, namespace and name. The namespace is everything between the type and
// the last slash (Go and Maven namespaces may hold slashes or dots).
func SplitKey(key string) (typ, ns, name string, ok bool) {
	rest, ok := strings.CutPrefix(strings.ToLower(key), "pkg:")
	if !ok {
		return "", "", "", false
	}
	typ, rest, ok = strings.Cut(rest, "/")
	if !ok || typ == "" {
		return "", "", "", false
	}
	if i := strings.LastIndexByte(rest, '/'); i >= 0 {
		return typ, rest[:i], rest[i+1:], true
	}
	return typ, "", rest, true
}

func (r *rule) match(ns, name string) (cycle string, ok bool) {
	switch {
	case r.ns == "*" && ns == "":
		return "", false
	case r.ns != "*" && r.ns != ns:
		return "", false
	}
	if r.nameRe == nil {
		return "", r.name == name
	}
	m := r.nameRe.FindStringSubmatch(name)
	if m == nil {
		return "", false
	}
	return m[1], true
}

var (
	defaultOnce sync.Once
	defaultOv   *Overlay
)

// Default is the overlay embedded in this binary. Tests make sure it parses.
func Default() *Overlay {
	defaultOnce.Do(func() {
		o, err := Parse(embedded)
		if err != nil {
			panic(err)
		}
		defaultOv = o
	})
	return defaultOv
}

// Version is the document's version, recorded with the mappings it produced.
func (o *Overlay) Version() string { return o.doc.Version }

// Document returns the parsed document (for listing and tests).
func (o *Overlay) Document() Document { return o.doc }

// Match is how a component was mapped to a lifecycle product.
type Match struct {
	Product string
	// Cycle is the release line read from the package name, or "" to read it
	// from the installed version.
	Cycle string
	// Rule is endoflife.date, namespace_family or overlay.
	Rule string
}

// Product maps a versionless purl to an endoflife.date product. edl looks up
// endoflife.date's own identifiers (nil when there are none).
func (o *Overlay) Product(key string, edl func(key string) string) (Match, bool) {
	typ, ns, name, ok := SplitKey(key)
	if !ok {
		return Match{}, false
	}
	find := func(override bool) (Match, bool) {
		for _, r := range o.rules[typ] {
			if r.entry.Override != override {
				continue
			}
			if cycle, ok := r.match(ns, name); ok {
				if a, ok := r.entry.CycleAliases[cycle]; ok {
					cycle = a
				}
				return Match{Product: r.entry.Product, Cycle: cycle, Rule: "overlay"}, true
			}
		}
		return Match{}, false
	}
	if m, ok := find(true); ok {
		return m, true
	}
	if edl != nil {
		if p := edl(strings.ToLower(key)); p != "" {
			return Match{Product: p, Rule: "endoflife.date"}, true
		}
		for _, other := range o.families[typ][ns] {
			if p := edl("pkg:" + typ + "/" + other + "/" + name); p != "" {
				return Match{Product: p, Rule: "namespace_family"}, true
			}
		}
	}
	return find(false)
}

// VendorBuild reports whether a package was built by a vendor's own
// repository rather than the distribution, from the overlay's vendor-only
// package names and vendor version patterns. repository names it.
func (o *Overlay) VendorBuild(key, version string) (repository string, ok bool) {
	typ, ns, name, ok := SplitKey(key)
	if !ok {
		return "", false
	}
	for _, r := range o.rules[typ] {
		if _, ok := r.match(ns, name); !ok {
			continue
		}
		if r.entry.VendorOnly != "" {
			return r.entry.VendorOnly, true
		}
		for i, re := range r.vendor {
			if re.MatchString(version) {
				return r.entry.VendorBuilds[i].Repository, true
			}
		}
	}
	return "", false
}

// Untracked returns the label of a product no lifecycle source tracks.
func (o *Overlay) Untracked(key string) (label string, ok bool) {
	typ, ns, name, ok := SplitKey(key)
	if !ok {
		return "", false
	}
	for _, r := range o.untrack[typ] {
		if _, ok := r.match(ns, name); ok {
			return r.label, true
		}
	}
	return "", false
}

// LikePatterns are SQL LIKE patterns (backslash escapes) covering every purl
// the overlay names, mapped or untracked. A {cycle} or "*" becomes "%", so a
// pattern can match more than the rule: callers confirm each candidate with
// Product or Untracked.
func (o *Overlay) LikePatterns() []string {
	var out []string
	for _, rs := range []map[string][]*rule{o.rules, o.untrack} {
		types := make([]string, 0, len(rs))
		for t := range rs {
			types = append(types, t)
		}
		sort.Strings(types)
		for _, t := range types {
			for _, r := range rs[t] {
				p := "pkg:" + r.typ + "/"
				if r.ns != "" {
					p += r.ns + "/"
				}
				p += r.name
				p = strings.NewReplacer(`\`, `\\`, "_", `\_`, "%", `\%`).Replace(p)
				out = append(out, strings.NewReplacer("{cycle}", "%", "*", "%").Replace(p))
			}
		}
	}
	return out
}

// FamilyKeys expands endoflife.date purls into the same package in the other
// namespaces of their family (pkg:rpm/redhat/nginx -> pkg:rpm/rocky/nginx, ...).
func (o *Overlay) FamilyKeys(keys []string) []string {
	var out []string
	for _, k := range keys {
		typ, ns, name, ok := SplitKey(k)
		if !ok {
			continue
		}
		for _, other := range o.families[typ][ns] {
			out = append(out, "pkg:"+typ+"/"+other+"/"+name)
		}
	}
	return out
}
