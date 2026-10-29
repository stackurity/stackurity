// Package vex reads and writes VEX (Vulnerability Exploitability eXchange)
// documents: OpenVEX (v0.2, and the earlier v0.0.1 shape) and CycloneDX
// VEX, standalone or embedded in a CycloneDX BOM, plain or wrapped in a
// signed in-toto attestation (a DSSE envelope, as cosign attest writes it).
//
// Documents are untrusted input. Read bounds the size, the number of
// statements and products, and the length of every text it keeps; it never
// fetches anything a document points at. What a statement means for
// findings (matching products to assets and components, and whether a
// person must approve it) is decided by the store (internal/store/vex.go).
package vex

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/package-url/packageurl-go"
)

// Limits on what Read accepts.
const (
	// MaxDocumentSize is the largest document Read accepts. A CycloneDX
	// BOM with VEX embedded is read up to the SBOM import's limit instead
	// (sbom.MaxDocumentSize) by ReadBOM.
	MaxDocumentSize = 16 << 20
	// MaxStatements is the most statements one document may hold.
	MaxStatements = 20000
	// MaxProducts is the most products (and subcomponents) one statement
	// may name, and MaxProductRefs the most in a whole document.
	MaxProducts    = 1000
	MaxProductRefs = 200000
	maxIDLen       = 512
	maxTextLen     = 4000
	maxAliases     = 50
	maxDepth       = 32
	maxComponents  = 200000
)

// Statuses (OpenVEX's names; CycloneDX analysis states are mapped to them).
const (
	StatusNotAffected        = "not_affected"
	StatusAffected           = "affected"
	StatusFixed              = "fixed"
	StatusUnderInvestigation = "under_investigation"
)

// OpenVEX justifications for not_affected.
const (
	JustComponentNotPresent                         = "component_not_present"
	JustVulnerableCodeNotPresent                    = "vulnerable_code_not_present"
	JustVulnerableCodeNotInExecutePath              = "vulnerable_code_not_in_execute_path"
	JustVulnerableCodeCannotBeControlledByAdversary = "vulnerable_code_cannot_be_controlled_by_adversary"
	JustInlineMitigationsAlreadyExist               = "inline_mitigations_already_exist"
)

// Formats.
const (
	FormatOpenVEX   = "openvex"
	FormatCycloneDX = "cyclonedx"
)

var statuses = map[string]bool{StatusNotAffected: true, StatusAffected: true, StatusFixed: true, StatusUnderInvestigation: true}

var justifications = map[string]bool{
	JustComponentNotPresent: true, JustVulnerableCodeNotPresent: true, JustVulnerableCodeNotInExecutePath: true,
	JustVulnerableCodeCannotBeControlledByAdversary: true, JustInlineMitigationsAlreadyExist: true,
}

// ValidStatus and ValidJustification check OpenVEX values.
func ValidStatus(s string) bool        { return statuses[s] }
func ValidJustification(s string) bool { return justifications[s] }

// ErrUnknownFormat: the document is none of the formats Read knows.
var ErrUnknownFormat = errors.New("not an OpenVEX document, a CycloneDX BOM or VEX, or a DSSE envelope holding one")

// Document is a VEX document in a format-neutral shape.
type Document struct {
	Format    string     `json:"format"`
	ID        string     `json:"id"`
	Author    string     `json:"author"`
	Version   string     `json:"version"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
	// Spec is the OpenVEX @context or the CycloneDX specVersion.
	Spec       string      `json:"spec"`
	Statements []Statement `json:"statements"`
	// Skipped counts CycloneDX vulnerabilities without an analysis: they
	// list a vulnerability but state nothing about it.
	Skipped int `json:"skipped,omitempty"`
	// Envelope is the signed attestation the document came in, if any.
	Envelope *Envelope `json:"-"`
	// Subjects are the in-toto attestation's subjects (name and sha256).
	Subjects []Subject `json:"subjects,omitempty"`
}

// Subject is an in-toto subject: what an attestation is about.
type Subject struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// Statement says how one vulnerability affects some products.
type Statement struct {
	Vulnerability string   `json:"vulnerability"`
	Aliases       []string `json:"aliases,omitempty"`
	Status        string   `json:"status"`
	// Justification is an OpenVEX justification ("" when none was given or
	// it could not be mapped). CycloneDX documents keep what they said in
	// OriginalState and OriginalJustification.
	Justification         string     `json:"justification,omitempty"`
	OriginalState         string     `json:"original_state,omitempty"`
	OriginalJustification string     `json:"original_justification,omitempty"`
	ImpactStatement       string     `json:"impact_statement,omitempty"`
	ActionStatement       string     `json:"action_statement,omitempty"`
	StatusNotes           string     `json:"status_notes,omitempty"`
	Timestamp             *time.Time `json:"timestamp,omitempty"`
	Products              []Product  `json:"products"`
	// Problem is why the statement cannot be applied at all (an unknown
	// status, not_affected without a justification), "" when it can.
	Problem string `json:"problem,omitempty"`
}

// Product identifies what a statement is about: an image by digest, an
// application by its package URL or BOM serial number, or a package by
// package URL or CPE. Subcomponents are the packages inside it the
// statement is about.
type Product struct {
	// ID is the identifier as the document wrote it, for display.
	ID     string `json:"id"`
	Purl   string `json:"purl,omitempty"`
	CPE    string `json:"cpe,omitempty"`
	Digest string `json:"digest,omitempty"` // sha256:<64 hex>
	// Serial is a CycloneDX BOM serial number (urn:uuid:...): the asset
	// that BOM was imported as.
	Serial string `json:"serial,omitempty"`
	// BOMRef addresses a component by its bom-ref in the BOM named by the
	// parent's Serial.
	BOMRef string `json:"bom_ref,omitempty"`
	// Root marks a CycloneDX document's own subject that carries no
	// identifier of its own (only a name): it can stand only for the one
	// asset an import is scoped to.
	Root          bool      `json:"root,omitempty"`
	Subcomponents []Product `json:"subcomponents,omitempty"`
	// Problem is why this product can never match, "" when it may.
	Problem string `json:"problem,omitempty"`
}

// Label is a short name for the product, for messages and display.
func (p Product) Label() string {
	if p.ID != "" {
		return p.ID
	}
	for _, s := range []string{p.Purl, p.Digest, p.CPE, p.Serial, p.BOMRef} {
		if s != "" {
			return s
		}
	}
	return "(unnamed product)"
}

var (
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// An image reference pinned by digest: registry/path[:tag]@sha256:<hex>.
	imageDigestRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@(sha256:[0-9a-f]{64})$`)
	// Vulnerability ids: CVE, GHSA, OSV and distribution ids, and the like.
	vulnIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/+-]{1,200}$`)
)

// NormalizeDigest returns "sha256:<hex>" for a sha256 digest given with or
// without its prefix, or "" when s is not one.
func NormalizeDigest(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !strings.HasPrefix(s, "sha256:") {
		s = "sha256:" + s
	}
	if digestRE.MatchString(s) {
		return s
	}
	return ""
}

// NormalizeVulnID upper-cases CVE and GHSA prefixes the way advisories
// store them ("cve-2021-44228" is "CVE-2021-44228"); "" when the id is not
// one Stackurity could ever match.
func NormalizeVulnID(id string) string {
	id = strings.TrimSpace(id)
	// A URL naming the vulnerability (OpenVEX @id): keep its last segment.
	if strings.HasPrefix(id, "https://") || strings.HasPrefix(id, "http://") {
		if u, err := url.Parse(id); err == nil {
			parts := strings.Split(strings.Trim(u.Path, "/"), "/")
			id = parts[len(parts)-1]
		}
	}
	if !vulnIDRE.MatchString(id) {
		return ""
	}
	up := strings.ToUpper(id)
	for _, p := range []string{"CVE-", "GHSA-"} {
		if strings.HasPrefix(up, p) {
			if p == "GHSA-" {
				return "GHSA-" + strings.ToLower(id[5:])
			}
			return up
		}
	}
	return id
}

// clip keeps a text within n bytes on a rune boundary.
func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func parseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

// productFromID turns an identifier string (an OpenVEX @id, a CycloneDX
// reference) into a product: a package URL, a CPE, or an image reference
// pinned by digest. Anything else is kept with a problem.
func productFromID(id string) Product {
	id = clip(id, maxIDLen)
	p := Product{ID: id}
	switch {
	case strings.HasPrefix(id, "pkg:"):
		pu, err := packageurl.FromString(id)
		if err != nil {
			p.Problem = "not a valid package URL"
			return p
		}
		p.Purl = id
		if pu.Type == "oci" || pu.Type == "docker" {
			if d := NormalizeDigest(pu.Version); d != "" {
				p.Digest = d
			} else {
				p.Problem = "an image without a digest: tags move, so name the image by digest (sha256)"
			}
		}
	case strings.HasPrefix(id, "cpe:"):
		p.CPE = id
	case imageDigestRE.MatchString(id):
		p.Digest = imageDigestRE.FindStringSubmatch(id)[1]
	default:
		p.Problem = "not a package URL, CPE or image digest"
	}
	return p
}

// Read parses a VEX document of any supported format. A DSSE envelope is
// unwrapped (its signature is not checked here: see Envelope.Verify). A
// CycloneDX document counts when it has vulnerabilities with an analysis.
func Read(data []byte) (*Document, error) {
	if len(data) > MaxDocumentSize {
		return nil, fmt.Errorf("VEX document larger than %d MiB", MaxDocumentSize>>20)
	}
	return read(data, 0)
}

// ReadBOM parses the VEX embedded in a CycloneDX BOM read by the SBOM
// import, whose size limit is higher than a VEX document's.
func ReadBOM(data []byte) (*Document, error) {
	return readCycloneDX(data)
}

func read(data []byte, depth int) (*Document, error) {
	if depth > 2 {
		return nil, errors.New("envelopes nested too deep")
	}
	var probe struct {
		Context      json.RawMessage `json:"@context"`
		BOMFormat    string          `json:"bomFormat"`
		PayloadType  string          `json:"payloadType"`
		Payload      string          `json:"payload"`
		Type         string          `json:"_type"`
		Predicate    json.RawMessage `json:"predicate"`
		DSSEEnvelope json.RawMessage `json:"dsseEnvelope"`
		Statements   json.RawMessage `json:"statements"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parse VEX: %w", err)
	}
	switch {
	case probe.PayloadType != "" && probe.Payload != "":
		env, err := parseEnvelope(data)
		if err != nil {
			return nil, err
		}
		doc, err := readStatementPayload(env, depth)
		if err != nil {
			return nil, err
		}
		doc.Envelope = env
		return doc, nil
	case len(probe.DSSEEnvelope) > 0:
		// A Sigstore bundle: the envelope is inside. The transparency log
		// entry and certificate are not checked (see Envelope.Verify).
		return read(probe.DSSEEnvelope, depth+1)
	case probe.Type != "" && len(probe.Predicate) > 0:
		// An unsigned in-toto statement.
		return readInToto(data, depth)
	case probe.BOMFormat == "CycloneDX":
		return readCycloneDX(data)
	case len(probe.Context) > 0 || len(probe.Statements) > 0:
		return readOpenVEX(data)
	}
	return nil, ErrUnknownFormat
}

func readStatementPayload(env *Envelope, depth int) (*Document, error) {
	switch env.PayloadType {
	case "application/vnd.in-toto+json":
		return readInToto(env.Payload, depth)
	case "application/json", "application/openvex+json", "application/vnd.cyclonedx+json":
		return read(env.Payload, depth+1)
	}
	return nil, fmt.Errorf("unsupported envelope payload type %q", clip(env.PayloadType, 100))
}

func readInToto(data []byte, depth int) (*Document, error) {
	var st struct {
		Type          string `json:"_type"`
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		Predicate json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse in-toto statement: %w", err)
	}
	if !strings.HasPrefix(st.PredicateType, "https://openvex.dev/ns") && !strings.HasPrefix(st.PredicateType, "https://cyclonedx.org/vex") &&
		!strings.HasPrefix(st.PredicateType, "https://cyclonedx.org/bom") {
		return nil, fmt.Errorf("the attestation's predicate type %q is not OpenVEX or CycloneDX", clip(st.PredicateType, 100))
	}
	doc, err := read(st.Predicate, depth+1)
	if err != nil {
		return nil, err
	}
	if len(st.Subject) > MaxProducts {
		return nil, errors.New("too many attestation subjects")
	}
	for _, s := range st.Subject {
		doc.Subjects = append(doc.Subjects, Subject{Name: clip(s.Name, maxIDLen), SHA256: NormalizeDigest(s.Digest["sha256"])})
	}
	return doc, nil
}

// --- OpenVEX

type ovDocument struct {
	Context    json.RawMessage   `json:"@context"`
	ID         string            `json:"@id"`
	Author     string            `json:"author"`
	Timestamp  string            `json:"timestamp"`
	Version    json.RawMessage   `json:"version"`
	Statements []json.RawMessage `json:"statements"`
}

type ovStatement struct {
	Vulnerability   json.RawMessage   `json:"vulnerability"`
	Products        []json.RawMessage `json:"products"`
	Subcomponents   []json.RawMessage `json:"subcomponents"` // v0.0.1: on the statement
	Status          string            `json:"status"`
	Justification   string            `json:"justification"`
	ImpactStatement string            `json:"impact_statement"`
	ActionStatement string            `json:"action_statement"`
	StatusNotes     string            `json:"status_notes"`
	Timestamp       string            `json:"timestamp"`
	LastUpdated     string            `json:"last_updated"`
}

type ovVulnerability struct {
	ID      string   `json:"@id"`
	Name    string   `json:"name"`
	Aliases []string `json:"aliases"`
}

type ovProduct struct {
	ID          string `json:"@id"`
	Identifiers struct {
		Purl  string `json:"purl"`
		CPE22 string `json:"cpe22"`
		CPE23 string `json:"cpe23"`
	} `json:"identifiers"`
	Hashes        map[string]string `json:"hashes"`
	Subcomponents []json.RawMessage `json:"subcomponents"`
}

func readOpenVEX(data []byte) (*Document, error) {
	var d ovDocument
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse OpenVEX: %w", err)
	}
	ctx := ""
	_ = json.Unmarshal(d.Context, &ctx)
	if !strings.HasPrefix(ctx, "https://openvex.dev/ns") {
		return nil, fmt.Errorf("OpenVEX @context %q is not https://openvex.dev/ns", clip(ctx, 100))
	}
	if len(d.Statements) > MaxStatements {
		return nil, fmt.Errorf("more than %d statements", MaxStatements)
	}
	doc := &Document{Format: FormatOpenVEX, ID: clip(d.ID, maxIDLen), Author: clip(d.Author, 200), Spec: clip(ctx, 100),
		Timestamp: parseTime(d.Timestamp)}
	var v any
	if json.Unmarshal(d.Version, &v) == nil && v != nil {
		doc.Version = clip(fmt.Sprint(v), 50)
	}
	refs := 0
	for _, raw := range d.Statements {
		var s ovStatement
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("parse OpenVEX statement: %w", err)
		}
		st := Statement{Status: strings.TrimSpace(s.Status), Justification: strings.TrimSpace(s.Justification),
			ImpactStatement: clip(s.ImpactStatement, maxTextLen), ActionStatement: clip(s.ActionStatement, maxTextLen),
			StatusNotes: clip(s.StatusNotes, maxTextLen), Timestamp: parseTime(s.Timestamp)}
		if t := parseTime(s.LastUpdated); t != nil {
			st.Timestamp = t
		}
		var name string
		var vuln ovVulnerability
		if json.Unmarshal(s.Vulnerability, &name) == nil {
			vuln.Name = name // v0.0.1: a plain string
		} else if err := json.Unmarshal(s.Vulnerability, &vuln); err != nil {
			return nil, fmt.Errorf("parse OpenVEX vulnerability: %w", err)
		}
		st.Vulnerability = NormalizeVulnID(vuln.Name)
		if st.Vulnerability == "" {
			st.Vulnerability = NormalizeVulnID(vuln.ID)
		}
		st.Aliases = aliases(vuln.Aliases, st.Vulnerability)
		if len(s.Products) > MaxProducts {
			return nil, fmt.Errorf("a statement names more than %d products", MaxProducts)
		}
		var subs []Product
		for _, rs := range s.Subcomponents {
			p, err := ovReadProduct(rs, 1, &refs)
			if err != nil {
				return nil, err
			}
			subs = append(subs, p)
		}
		for _, rp := range s.Products {
			p, err := ovReadProduct(rp, 0, &refs)
			if err != nil {
				return nil, err
			}
			if len(subs) > 0 && len(p.Subcomponents) == 0 {
				p.Subcomponents = subs
			}
			st.Products = append(st.Products, p)
		}
		checkStatement(&st)
		doc.Statements = append(doc.Statements, st)
	}
	return doc, nil
}

func ovReadProduct(raw json.RawMessage, depth int, refs *int) (Product, error) {
	*refs++
	if *refs > MaxProductRefs {
		return Product{}, fmt.Errorf("more than %d products in the document", MaxProductRefs)
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return productFromID(s), nil // v0.0.1: a plain string
	}
	var op ovProduct
	if err := json.Unmarshal(raw, &op); err != nil {
		return Product{}, fmt.Errorf("parse OpenVEX product: %w", err)
	}
	var p Product
	switch {
	case op.Identifiers.Purl != "":
		p = productFromID(op.Identifiers.Purl)
	case op.ID != "":
		p = productFromID(op.ID)
	case op.Identifiers.CPE23 != "":
		p = productFromID(op.Identifiers.CPE23)
	case op.Identifiers.CPE22 != "":
		p = productFromID(op.Identifiers.CPE22)
	default:
		p = Product{Problem: "no identifier"}
	}
	if op.ID != "" {
		p.ID = clip(op.ID, maxIDLen)
	}
	if p.CPE == "" {
		if c := op.Identifiers.CPE23; c != "" {
			p.CPE = clip(c, maxIDLen)
		} else if c := op.Identifiers.CPE22; c != "" {
			p.CPE = clip(c, maxIDLen)
		}
		if p.CPE != "" && p.Problem == "not a package URL, CPE or image digest" {
			p.Problem = ""
		}
	}
	// An image named without a digest can still carry one in hashes.
	if p.Digest == "" && (p.Purl == "" || isImagePurl(p.Purl)) {
		if d := NormalizeDigest(op.Hashes["sha-256"]); d != "" {
			p.Digest, p.Problem = d, ""
		}
	}
	if depth > 0 && len(op.Subcomponents) > 0 {
		return p, errors.New("subcomponents nested in subcomponents")
	}
	if len(op.Subcomponents) > MaxProducts {
		return p, fmt.Errorf("a product names more than %d subcomponents", MaxProducts)
	}
	for _, rs := range op.Subcomponents {
		sp, err := ovReadProduct(rs, depth+1, refs)
		if err != nil {
			return p, err
		}
		p.Subcomponents = append(p.Subcomponents, sp)
	}
	return p, nil
}

func isImagePurl(purl string) bool {
	return strings.HasPrefix(purl, "pkg:oci/") || strings.HasPrefix(purl, "pkg:docker/")
}

func aliases(in []string, primary string) []string {
	seen := map[string]bool{primary: true}
	var out []string
	for _, a := range in {
		if len(out) >= maxAliases {
			break
		}
		if n := NormalizeVulnID(a); n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// checkStatement records why a statement cannot apply, if it cannot.
func checkStatement(st *Statement) {
	switch {
	case st.Vulnerability == "":
		st.Problem = "no vulnerability id Stackurity can match"
	case !statuses[st.Status]:
		st.Problem = fmt.Sprintf("unknown status %q", clip(st.Status, 50))
	case st.Status == StatusNotAffected && st.Justification != "" && !justifications[st.Justification]:
		st.Problem = fmt.Sprintf("unknown justification %q", clip(st.Justification, 80))
	case st.Status == StatusNotAffected && st.Justification == "" && st.ImpactStatement == "":
		// OpenVEX requires one of them; without either nobody can tell why.
		st.Problem = "not_affected without a justification or an impact statement"
	case len(st.Products) == 0:
		st.Problem = "no products"
	}
	st.Status = clip(st.Status, 50)
	st.Justification = clip(st.Justification, 80)
}
