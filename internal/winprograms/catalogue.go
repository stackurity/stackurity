// Package winprograms is Stackurity's curated catalogue of Windows programs:
// which installed programs (Add/Remove Programs entries, read from the
// registry by the Windows agent) are matched against vulnerability data, how
// their version strings are read, and where their advisories come from.
//
// Matching a program by its display name alone is unreliable ("Google Chrome
// Helper", "Java Auto Updater", "Microsoft Edge Update" are not the browser
// or runtime), and so is NVD's CPE dictionary searched by publisher and name.
// So only programs in this catalogue are matched. Every entry was checked:
// its name patterns against real registry entries, its version rule against
// the vendor's version strings, and its source against the advisories it
// returns. Programs not in the catalogue are reported as coverage gaps with
// that reason, never as clean.
//
// The data is a versioned JSON document (catalogue.json, embedded in the
// binary). Every pattern is a regular expression anchored at both ends and
// matched without regard to case.
package winprograms

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed catalogue.json
var embedded []byte

// Schema is the document version this code reads.
const Schema = 1

// Ecosystem is the base ecosystem advisories for catalogued programs are
// stored under; an entry's own ecosystem is Ecosystem + ":" + its id.
const Ecosystem = "Windows programs"

// Document is the catalogue as stored.
type Document struct {
	Schema      int       `json:"schema"`
	Version     string    `json:"version"`
	Description string    `json:"description,omitempty"`
	Programs    []Program `json:"programs"`
}

// Program is one catalogued program.
type Program struct {
	// ID names the program's advisories (package name) and is lower case
	// letters, digits and hyphens.
	ID    string `json:"id"`
	Label string `json:"label"`
	// Names match the registry DisplayName.
	Names []string `json:"names"`
	// Exclude are DisplayNames that are never this program, although a
	// name pattern matches them.
	Exclude []string `json:"exclude,omitempty"`
	// Publishers match the registry Publisher. A program whose publisher is
	// another is not this one; one with no publisher recorded is matched,
	// but needs validation.
	Publishers []string `json:"publishers"`
	// VersionMatch, when set, limits the entry to registry versions it
	// matches: Adobe Acrobat's Continuous track (24.003.20180) and Classic
	// track (24.001.30264) carry the same names but get different fixes.
	VersionMatch string `json:"version_match,omitempty"`
	// Version reads the installed version; required with a Source.
	Version VersionRule `json:"version,omitempty"`
	// Source is where advisories come from; nil when the program is
	// recognised but not matched (Unmatched says why).
	Source    *Source `json:"source,omitempty"`
	Unmatched string  `json:"unmatched,omitempty"`
	// SideBySide is "major" or "major.minor" for a program whose release
	// lines install side by side (.NET 8 and 9, Python 3.12 and 3.13): each
	// line is updated on its own, so the action plan has one update per line.
	SideBySide string `json:"side_by_side,omitempty"`
	// ExtendedParity is "even" or "odd" for a program whose extended-support
	// line has majors of that parity only (Edge's Extended Stable is even):
	// only such majors are taken as succeeding one another when the
	// Security Update Guide lists them next to a higher major.
	ExtendedParity string `json:"extended_parity,omitempty"`
	// CoverageNote is shown on every evaluated row of the program: what its
	// source is known not to cover (NVD's backlog for the product).
	CoverageNote string `json:"coverage_note,omitempty"`
	// Update says how the program is usually updated, for the action plan.
	Update   string   `json:"update,omitempty"`
	Sources  []string `json:"sources"`
	Verified string   `json:"verified"`
	Note     string   `json:"note,omitempty"`

	names, exclude, publishers []*regexp.Regexp
	versionMatch               *regexp.Regexp
	version                    *versionRule
}

// VersionRule reads a version: Pattern is matched against the field named by
// From ("display_version", the default, or "display_name"), and Format, with
// $1, $2... for its groups, gives the version compared. The result must be
// dotted numbers ("130.0.6723.92", "1.8.0.401").
type VersionRule struct {
	From    string `json:"from,omitempty"`
	Pattern string `json:"pattern"`
	Format  string `json:"format"`
}

// Source types.
const (
	// SourceNVD: NVD's CVE records whose configurations name the program's
	// CPE products, with the version ranges NVD's analysts recorded.
	SourceNVD = "nvd_cpe"
	// SourceMSRC: Microsoft's Security Update Guide (the documents the
	// Windows updates feed reads), which lists the build of Microsoft Edge
	// that fixes each CVE, including the Chromium CVEs Edge takes in.
	SourceMSRC = "msrc"
	// SourceMozilla: Mozilla's security advisories (MFSA), which list the
	// release of each product that fixes each CVE.
	SourceMozilla = "mfsa"
)

// msrcPrograms are the programs the Windows updates feed reads fixes for
// (internal/intel msrcProgram).
var msrcPrograms = map[string]bool{"microsoft-edge": true, "dotnet-runtime": true, "aspnetcore-runtime": true}

// Source is a program's advisory source.
type Source struct {
	// Type is SourceNVD or SourceMSRC.
	Type string `json:"type"`
	// CPEs are "cpe:2.3:a:<vendor>:<product>", optionally followed by
	// further CPE fields that must match: NVD marks Firefox ESR as
	// sw_edition "esr" of the firefox product
	// ("cpe:2.3:a:mozilla:firefox:*:*:*:*:esr"). Without a sw_edition, only
	// configurations for any ("*") or no ("-") edition are read, never a
	// named one, so a range meant for another edition is never applied.
	CPEs []string `json:"cpes,omitempty"`
	// Products are the MFSA product names read ("Firefox ESR").
	Products []string `json:"products,omitempty"`
	// PerLine reads an MFSA source's fixes per major version (Firefox ESR
	// 115.16.1 and 128.3.1 each fix their own line), as the Security Update
	// Guide's always are; without it the program has one rolling line
	// (Firefox's rapid release) and every earlier version is affected.
	PerLine bool `json:"per_line,omitempty"`
	// Version reads NVD's version strings when they are not already dotted
	// numbers in the same form as the installed version; it is matched
	// against "<version>" or, when the CPE has an update field,
	// "<version>:<update>".
	Version *VersionRule `json:"version,omitempty"`
}

type versionRule struct {
	fromName bool
	re       *regexp.Regexp
	format   string
}

var (
	idPattern   = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	dottedNums  = regexp.MustCompile(`^\d+(?:\.\d+)*$`)
	cpePattern  = regexp.MustCompile(`^cpe:2\.3:a:[^:*]+:[^:*]+(?::\*:\*(?::[^:]+){0,6})?$`)
	groupRefRe  = regexp.MustCompile(`\$(\d+)`)
	defaultOnce sync.Once
	defaultCat  *Catalogue
)

// Catalogue is a parsed, validated document.
type Catalogue struct {
	doc  Document
	byID map[string]*Program
}

func compileAnchored(what, p string) (*regexp.Regexp, error) {
	if !strings.HasPrefix(p, "^") || !strings.HasSuffix(p, "$") {
		return nil, fmt.Errorf("%s %q must be anchored with ^ and $", what, p)
	}
	re, err := regexp.Compile("(?i)" + p)
	if err != nil {
		return nil, fmt.Errorf("%s %q: %w", what, p, err)
	}
	return re, nil
}

func compileRule(r VersionRule, allowName bool) (*versionRule, error) {
	vr := &versionRule{format: r.Format}
	switch r.From {
	case "", "display_version":
	case "display_name":
		if !allowName {
			return nil, fmt.Errorf("version rule: from %q is not allowed here", r.From)
		}
		vr.fromName = true
	default:
		return nil, fmt.Errorf("version rule: unknown field %q", r.From)
	}
	re, err := compileAnchored("version pattern", r.Pattern)
	if err != nil {
		return nil, err
	}
	if r.Format == "" {
		return nil, errors.New("version rule: no format")
	}
	for _, m := range groupRefRe.FindAllStringSubmatch(r.Format, -1) {
		var n int
		fmt.Sscan(m[1], &n)
		if n < 1 || n > re.NumSubexp() {
			return nil, fmt.Errorf("version rule: format %q refers to group %d of %d", r.Format, n, re.NumSubexp())
		}
	}
	vr.re = re
	return vr, nil
}

// apply reads s with the rule; ok is false when it does not match or the
// result is not dotted numbers.
func (r *versionRule) apply(s string) (string, bool) {
	m := r.re.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", false
	}
	out := groupRefRe.ReplaceAllStringFunc(r.format, func(ref string) string {
		var n int
		fmt.Sscan(ref[1:], &n)
		return m[n]
	})
	// Groups that did not take part leave empty parts ("144.0." from an
	// optional third group): they are dropped.
	var parts []string
	for _, x := range strings.Split(out, ".") {
		if x != "" {
			parts = append(parts, x)
		}
	}
	out = strings.Join(parts, ".")
	if !dottedNums.MatchString(out) {
		return "", false
	}
	return out, true
}

// Parse reads and validates a catalogue document.
func Parse(b []byte) (*Catalogue, error) {
	var d Document
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("Windows program catalogue: %w", err)
	}
	if d.Schema != Schema {
		return nil, fmt.Errorf("Windows program catalogue: schema %d, this version reads %d", d.Schema, Schema)
	}
	if d.Version == "" {
		return nil, errors.New("Windows program catalogue: no version")
	}
	c := &Catalogue{doc: d, byID: map[string]*Program{}}
	cpes := map[string]string{}
	for i := range c.doc.Programs {
		p := &c.doc.Programs[i]
		fail := func(err error) error { return fmt.Errorf("Windows program catalogue: %s: %w", p.ID, err) }
		if !idPattern.MatchString(p.ID) {
			return nil, fmt.Errorf("Windows program catalogue: program %d: id %q is not lower-case words joined by hyphens", i, p.ID)
		}
		if c.byID[p.ID] != nil {
			return nil, fmt.Errorf("Windows program catalogue: %s is listed twice", p.ID)
		}
		if p.Label == "" || len(p.Names) == 0 || len(p.Publishers) == 0 || len(p.Sources) == 0 {
			return nil, fail(errors.New("needs a label, names, publishers and sources"))
		}
		if _, err := time.Parse("2006-01-02", p.Verified); err != nil {
			return nil, fail(fmt.Errorf("verified %q is not a date", p.Verified))
		}
		for _, list := range []struct {
			what string
			in   []string
			out  *[]*regexp.Regexp
		}{{"name", p.Names, &p.names}, {"exclude", p.Exclude, &p.exclude}, {"publisher", p.Publishers, &p.publishers}} {
			for _, s := range list.in {
				re, err := compileAnchored(list.what, s)
				if err != nil {
					return nil, fail(err)
				}
				*list.out = append(*list.out, re)
			}
		}
		if p.VersionMatch != "" {
			re, err := compileAnchored("version_match", p.VersionMatch)
			if err != nil {
				return nil, fail(err)
			}
			p.versionMatch = re
		}
		if p.ExtendedParity != "" && p.ExtendedParity != "even" && p.ExtendedParity != "odd" {
			return nil, fail(fmt.Errorf("extended_parity %q is not even or odd", p.ExtendedParity))
		}
		if p.SideBySide != "" && p.SideBySide != "major" && p.SideBySide != "major.minor" {
			return nil, fail(fmt.Errorf("side_by_side %q is not major or major.minor", p.SideBySide))
		}
		if p.Version.Pattern != "" || p.Source != nil {
			vr, err := compileRule(p.Version, true)
			if err != nil {
				return nil, fail(err)
			}
			p.version = vr
		}
		switch {
		case p.Source == nil && p.Unmatched == "":
			return nil, fail(errors.New("needs a source, or unmatched saying why it has none"))
		case p.Source != nil && p.Unmatched != "":
			return nil, fail(errors.New("has both a source and an unmatched reason"))
		case p.Source != nil:
			switch {
			case p.Source.Type == SourceMozilla:
				if len(p.Source.Products) == 0 || len(p.Source.CPEs) > 0 || p.Source.Version != nil {
					return nil, fail(errors.New("an mfsa source names products, and no CPEs or version rule"))
				}
				for _, prod := range p.Source.Products {
					switch prod {
					case "Firefox", "Firefox ESR", "Thunderbird", "Thunderbird ESR":
					default:
						return nil, fail(fmt.Errorf("MFSA product %q is not one this version reads", prod))
					}
				}
			case p.Source.PerLine:
				return nil, fail(errors.New("per_line is read for mfsa sources only"))
			case p.Source.Type == SourceMSRC:
				// Read by the Windows updates feed, which knows one product.
				if !msrcPrograms[p.ID] || len(p.Source.CPEs) > 0 || len(p.Source.Products) > 0 || p.Source.Version != nil {
					return nil, fail(errors.New("an msrc source is read for microsoft-edge, dotnet-runtime and aspnetcore-runtime only, with no CPEs or version rule"))
				}
			case p.Source.Type != SourceNVD || len(p.Source.CPEs) == 0 || len(p.Source.Products) > 0:
				return nil, fail(fmt.Errorf("source type %q with %d CPEs: only nvd_cpe with CPEs, mfsa or msrc is read", p.Source.Type, len(p.Source.CPEs)))
			}
			for _, cpe := range p.Source.CPEs {
				if !cpePattern.MatchString(cpe) {
					return nil, fail(fmt.Errorf("CPE %q is not cpe:2.3:a:<vendor>:<product>[:*:*:<more fields>]", cpe))
				}
				if prev, dup := cpes[cpe]; dup {
					return nil, fail(fmt.Errorf("CPE %s is also the source of %s", cpe, prev))
				}
				cpes[cpe] = p.ID
			}
			if p.Source.Version != nil {
				if _, err := compileRule(*p.Source.Version, false); err != nil {
					return nil, fail(fmt.Errorf("source %w", err))
				}
			}
		}
		c.byID[p.ID] = p
	}
	return c, nil
}

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

// Embedded returns the embedded document's bytes (for the second check,
// which reads it with its own code).
func Embedded() []byte { return embedded }

// Version is the document's version, recorded with the findings it produced.
func (c *Catalogue) Version() string { return c.doc.Version }

// Programs lists the catalogued programs in document order.
func (c *Catalogue) Programs() []*Program {
	out := make([]*Program, len(c.doc.Programs))
	for i := range c.doc.Programs {
		out[i] = &c.doc.Programs[i]
	}
	return out
}

// Program returns the entry with the given id.
func (c *Catalogue) Program(id string) *Program { return c.byID[id] }

// Identity is what the catalogue says about one installed program.
type Identity struct {
	// Program is the entry, nil when none applies (Reason says why).
	Program *Program
	// PublisherMissing: the registry entry records no publisher, so the
	// program is matched by name only and needs validation.
	PublisherMissing bool
	Reason           string
}

// Identify finds the catalogue entry for a registry entry's DisplayName,
// Publisher and DisplayVersion.
func (c *Catalogue) Identify(name, publisher, version string) Identity {
	name, publisher, version = strings.TrimSpace(name), strings.TrimSpace(publisher), strings.TrimSpace(version)
	var named []*Program
	for _, p := range c.Programs() {
		if p.matchesName(name) {
			named = append(named, p)
		}
	}
	if len(named) == 0 {
		return Identity{Reason: fmt.Sprintf("not in the curated catalogue of Windows programs (catalogue %s): no vulnerability source is used for it", c.doc.Version)}
	}
	var published, hits []*Program
	for _, p := range named {
		if publisher == "" || p.matchesPublisher(publisher) {
			published = append(published, p)
		}
	}
	for _, p := range published {
		if p.versionMatch == nil || p.versionMatch.MatchString(version) {
			hits = append(hits, p)
		}
	}
	switch {
	case len(published) == 0:
		return Identity{Reason: fmt.Sprintf("named like %s but published by %q, which the curated catalogue does not list for it: not matched", named[0].Label, publisher)}
	case len(hits) == 0:
		return Identity{Reason: fmt.Sprintf("version %q of %s is not of a release track the curated catalogue reads: not matched", version, published[0].Label)}
	case len(hits) > 1:
		ids := make([]string, len(hits))
		for i, p := range hits {
			ids[i] = p.Label
		}
		return Identity{Reason: "matches more than one curated catalogue entry (" + strings.Join(ids, ", ") + "): not matched"}
	}
	return Identity{Program: hits[0], PublisherMissing: publisher == ""}
}

func (p *Program) matchesName(name string) bool {
	for _, re := range p.exclude {
		if re.MatchString(name) {
			return false
		}
	}
	for _, re := range p.names {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

func (p *Program) matchesPublisher(pub string) bool {
	for _, re := range p.publishers {
		if re.MatchString(pub) {
			return true
		}
	}
	return false
}

// Ecosystem is the program's own ecosystem string.
func (p *Program) Ecosystem() string { return Ecosystem + ":" + p.ID }

// NormaliseVersion reads the installed version from a registry entry.
func (p *Program) NormaliseVersion(displayName, displayVersion string) (string, error) {
	if p.version == nil {
		return "", fmt.Errorf("the curated catalogue reads no version for %s", p.Label)
	}
	in := displayVersion
	if p.version.fromName {
		in = displayName
	}
	if strings.TrimSpace(in) == "" {
		return "", fmt.Errorf("no version was recorded for %s", p.Label)
	}
	v, ok := p.version.apply(in)
	if !ok {
		return "", fmt.Errorf("the version %q of %s is not in the form the curated catalogue reads", strings.TrimSpace(in), p.Label)
	}
	return v, nil
}

// SourceVersion reads a version from the program's advisory source: NVD's
// version, or "<version>:<update>" when the CPE has an update field. ok is
// false when it cannot be read as the installed versions are.
func (p *Program) SourceVersion(v string) (string, bool) {
	if p.Source == nil {
		return "", false
	}
	if p.Source.Version != nil {
		r, err := compileRule(*p.Source.Version, false)
		if err != nil {
			return "", false
		}
		return r.apply(v)
	}
	v = strings.TrimSpace(v)
	if !dottedNums.MatchString(v) {
		return "", false
	}
	return v, true
}

// OwnsCPE reports whether a CPE match string (cpe:2.3:a:vendor:product:
// version:update:edition:language:sw_edition:target_sw:...) names one of
// the program's products, in an edition it reads, for Windows or any
// platform.
func (p *Program) OwnsCPE(criteria string) bool {
	if p.Source == nil {
		return false
	}
	f := SplitCPE(criteria)
	if len(f) < 11 || f[2] != "a" {
		return false
	}
	switch ts := strings.ToLower(f[10]); {
	case ts == "*" || ts == "-" || strings.Contains(ts, "windows"):
	default:
		return false // macos, iphone_os, android, linux...
	}
	for _, c := range p.Source.CPEs {
		if cpeOwns(SplitCPE(c), f) {
			return true
		}
	}
	return false
}

// cpeOwns matches a criteria's fields f against a catalogue CPE's fields c.
func cpeOwns(c, f []string) bool {
	if !strings.EqualFold(c[3], f[3]) || !strings.EqualFold(c[4], f[4]) {
		return false
	}
	for i := 7; i < len(c) && i < len(f); i++ {
		if c[i] != "*" && !strings.EqualFold(c[i], f[i]) {
			return false
		}
	}
	if len(c) <= 9 || c[9] == "*" {
		ed := strings.ToLower(f[9])
		return ed == "*" || ed == "-"
	}
	return true
}

// SplitCPE splits a CPE 2.3 formatted string into its fields, keeping
// escaped colons ("\:") inside a field.
func SplitCPE(s string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			cur.WriteByte(s[i])
			cur.WriteByte(s[i+1])
			i++
		case s[i] == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	return append(out, cur.String())
}

// CPEVersion is the version a CPE match string names ("" for "*" or "-"),
// with its update field after a colon when it has one ("1.8.0:update401").
// CPE escapes ("\.") are removed.
func CPEVersion(criteria string) string {
	f := SplitCPE(criteria)
	if len(f) < 7 {
		return ""
	}
	unesc := func(s string) string { return strings.ReplaceAll(s, `\`, "") }
	v, u := unesc(f[5]), unesc(f[6])
	if v == "*" || v == "-" {
		return ""
	}
	if u != "*" && u != "-" && u != "" {
		return v + ":" + u
	}
	return v
}

// Line is the release line a normalised version is on, for a program whose
// lines install side by side ("8" for .NET 8.0.20, "3.12" for Python
// 3.12.10); "" for other programs.
func (p *Program) Line(version string) string {
	parts := strings.Split(version, ".")
	switch {
	case p.SideBySide == "major":
		return parts[0]
	case p.SideBySide == "major.minor" && len(parts) >= 2:
		return parts[0] + "." + parts[1]
	}
	return ""
}
