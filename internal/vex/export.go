package vex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
)

// Stackurity's ignore reasons that VEX statements map to (store.Reason*).
const (
	ReasonFalsePositive = "false_positive"
	ReasonMitigated     = "mitigated"
)

// IgnoreReason is the ignore reason an approved not_affected statement
// gets: the component or its vulnerable code is not there (false
// positive), or it is there and cannot be exploited (mitigated).
func IgnoreReason(st Statement) string {
	if st.OriginalState == "false_positive" {
		return ReasonFalsePositive
	}
	switch st.Justification {
	case JustComponentNotPresent, JustVulnerableCodeNotPresent:
		return ReasonFalsePositive
	}
	return ReasonMitigated
}

// JustificationFor is the OpenVEX justification an ignore rule is exported
// with when it did not come from a VEX statement.
func JustificationFor(reason string) string {
	if reason == ReasonFalsePositive {
		return JustVulnerableCodeNotPresent
	}
	return JustInlineMitigationsAlreadyExist
}

// ImagePurl names an image by digest as a package URL
// (pkg:oci/name@sha256:...?repository_url=registry/path), from a reference
// such as registry.example.com/team/app:1.2 and its digest.
func ImagePurl(ref, digest string) string {
	ref = strings.TrimSpace(ref)
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	// Drop a tag (a colon after the last slash).
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	name := ref
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		name = ref[i+1:]
	}
	if name == "" {
		name = "image"
	}
	var q packageurl.Qualifiers
	if ref != "" && ref != name {
		q = packageurl.QualifiersFromMap(map[string]string{"repository_url": ref})
	}
	return packageurl.NewPackageURL("oci", "", strings.ToLower(name), digest, q, "").ToString()
}

// ExportStatement is one decision to write: a vulnerability's status in a
// component, inside a product when the component is part of one.
type ExportStatement struct {
	Vulnerability   string
	Aliases         []string
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
	StatusNotes     string
	// FalsePositive writes CycloneDX state false_positive rather than
	// not_affected.
	FalsePositive bool
	// Product is an image (Digest and Purl) or application (Purl) holding
	// Component, or empty when the component is the product.
	Product   Product
	Component Product
	Timestamp time.Time
}

// ExportMeta describes the exported document.
type ExportMeta struct {
	Author    string
	Tool      string // "stackurity 0.14.0"
	Timestamp time.Time
	// Scope names what the export covers ("asset 12", "project 3"), for
	// the document's id.
	Scope string
}

// id names the document by what it says (not when it was made), so the
// same decisions exported twice have the same @id and serial number.
func (m ExportMeta) id(sts []ExportStatement) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n", m.Scope, m.Author)
	for _, s := range sts {
		fmt.Fprintf(h, "%s %s %s %s %s %s\n", s.Vulnerability, s.Status, s.Justification, s.Product.Purl, s.Component.Purl, s.ImpactStatement)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// sortStatements orders statements stably: by vulnerability, then product.
func sortStatements(sts []ExportStatement) {
	sort.SliceStable(sts, func(i, j int) bool {
		a, b := sts[i], sts[j]
		if a.Vulnerability != b.Vulnerability {
			return a.Vulnerability < b.Vulnerability
		}
		if a.Product.Purl != b.Product.Purl {
			return a.Product.Purl < b.Product.Purl
		}
		return a.Component.Purl < b.Component.Purl
	})
}

type ovOutProduct struct {
	ID            string            `json:"@id"`
	Identifiers   map[string]string `json:"identifiers,omitempty"`
	Hashes        map[string]string `json:"hashes,omitempty"`
	Subcomponents []ovOutProduct    `json:"subcomponents,omitempty"`
}

type ovOutStatement struct {
	Vulnerability struct {
		Name    string   `json:"name"`
		Aliases []string `json:"aliases,omitempty"`
	} `json:"vulnerability"`
	Timestamp       string         `json:"timestamp"`
	Products        []ovOutProduct `json:"products"`
	Status          string         `json:"status"`
	Justification   string         `json:"justification,omitempty"`
	ImpactStatement string         `json:"impact_statement,omitempty"`
	ActionStatement string         `json:"action_statement,omitempty"`
	StatusNotes     string         `json:"status_notes,omitempty"`
}

func ovOut(p Product) ovOutProduct {
	id := p.Purl
	if id == "" {
		id = p.CPE
	}
	o := ovOutProduct{ID: id}
	if p.Purl != "" {
		o.Identifiers = map[string]string{"purl": p.Purl}
		if p.CPE != "" {
			o.Identifiers["cpe23"] = p.CPE
		}
	}
	if p.Digest != "" {
		o.Hashes = map[string]string{"sha-256": strings.TrimPrefix(p.Digest, "sha256:")}
	}
	return o
}

// WriteOpenVEX writes the statements as an OpenVEX v0.2.0 document. Each
// statement names its component, inside its product when there is one.
func WriteOpenVEX(w io.Writer, meta ExportMeta, sts []ExportStatement) error {
	sortStatements(sts)
	out := struct {
		Context    string           `json:"@context"`
		ID         string           `json:"@id"`
		Author     string           `json:"author"`
		Timestamp  string           `json:"timestamp"`
		Version    int              `json:"version"`
		Tooling    string           `json:"tooling,omitempty"`
		Statements []ovOutStatement `json:"statements"`
	}{Context: "https://openvex.dev/ns/v0.2.0", ID: "urn:stackurity:vex:" + meta.id(sts), Author: meta.Author,
		Timestamp: meta.Timestamp.UTC().Format(time.RFC3339), Version: 1, Tooling: meta.Tool, Statements: []ovOutStatement{}}
	for _, s := range sts {
		o := ovOutStatement{Timestamp: s.Timestamp.UTC().Format(time.RFC3339), Status: s.Status, Justification: s.Justification,
			ImpactStatement: s.ImpactStatement, ActionStatement: s.ActionStatement, StatusNotes: s.StatusNotes}
		o.Vulnerability.Name, o.Vulnerability.Aliases = s.Vulnerability, s.Aliases
		if s.Status == StatusNotAffected && o.Justification == "" && o.ImpactStatement == "" {
			o.Justification = JustInlineMitigationsAlreadyExist
		}
		if s.Status == StatusAffected && o.ActionStatement == "" {
			o.ActionStatement = "No action statement was recorded."
		}
		if s.Product.Purl != "" || s.Product.Digest != "" {
			p := ovOut(s.Product)
			p.Subcomponents = []ovOutProduct{ovOut(s.Component)}
			o.Products = []ovOutProduct{p}
		} else {
			o.Products = []ovOutProduct{ovOut(s.Component)}
		}
		out.Statements = append(out.Statements, o)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

var cdxStateFor = map[string]cdx.ImpactAnalysisState{
	StatusNotAffected:        cdx.IASNotAffected,
	StatusAffected:           cdx.IASExploitable,
	StatusFixed:              cdx.IASResolved,
	StatusUnderInvestigation: cdx.IASInTriage,
}

// WriteCycloneDX writes the statements as a CycloneDX 1.6 VEX document:
// the components (an image or application with its components nested in
// it) and one vulnerability per statement, affecting the component by
// bom-ref.
func WriteCycloneDX(w io.Writer, meta ExportMeta, sts []ExportStatement) error {
	sortStatements(sts)
	bom := cdx.NewBOM()
	bom.SerialNumber = "urn:uuid:" + uuidFrom(meta.id(sts))
	bom.Metadata = &cdx.Metadata{
		Timestamp: meta.Timestamp.UTC().Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{Components: &[]cdx.Component{{
			Type: cdx.ComponentTypeApplication, Name: "stackurity", Version: strings.TrimPrefix(meta.Tool, "stackurity "),
		}}},
	}
	if meta.Author != "" {
		bom.Metadata.Authors = &[]cdx.OrganizationalContact{{Name: meta.Author}}
	}
	var top []cdx.Component
	parents := map[string]int{} // product purl -> index in top
	seen := map[string]bool{}
	vulns := []cdx.Vulnerability{}
	for _, s := range sts {
		comp := cdx.Component{Type: cdx.ComponentTypeLibrary, Name: purlName(s.Component.Purl), Version: purlVersion(s.Component.Purl),
			PackageURL: s.Component.Purl, CPE: s.Component.CPE}
		ref := s.Component.Purl
		if s.Product.Purl != "" {
			ref = s.Product.Purl + "#" + s.Component.Purl
			comp.BOMRef = ref
			i, ok := parents[s.Product.Purl]
			if !ok {
				typ := cdx.ComponentTypeApplication
				if s.Product.Digest != "" {
					typ = cdx.ComponentTypeContainer
				}
				pc := cdx.Component{BOMRef: s.Product.Purl, Type: typ, Name: purlName(s.Product.Purl), Version: purlVersion(s.Product.Purl),
					PackageURL: s.Product.Purl, Components: &[]cdx.Component{}}
				if s.Product.Digest != "" {
					pc.Hashes = &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: strings.TrimPrefix(s.Product.Digest, "sha256:")}}
				}
				top = append(top, pc)
				i = len(top) - 1
				parents[s.Product.Purl] = i
			}
			if !seen[ref] {
				seen[ref] = true
				*top[i].Components = append(*top[i].Components, comp)
			}
		} else if !seen[ref] {
			seen[ref] = true
			comp.BOMRef = ref
			top = append(top, comp)
		}
		state := cdxStateFor[s.Status]
		if s.Status == StatusNotAffected && s.FalsePositive {
			state = cdx.IASFalsePositive
		}
		a := &cdx.VulnerabilityAnalysis{State: state}
		if s.Status == StatusNotAffected {
			a.Justification = cdx.ImpactAnalysisJustification(CycloneDXJustification(s.Justification))
			a.Detail = s.ImpactStatement
		} else {
			a.Detail = strings.TrimSpace(strings.Join(nonEmpty(s.StatusNotes, s.ActionStatement), " "))
		}
		v := cdx.Vulnerability{BOMRef: fmt.Sprintf("vex-%d", len(vulns)+1), ID: s.Vulnerability, Analysis: a,
			Affects: &[]cdx.Affects{{Ref: ref}}}
		if len(s.Aliases) > 0 {
			refs := make([]cdx.VulnerabilityReference, len(s.Aliases))
			for i, al := range s.Aliases {
				refs[i] = cdx.VulnerabilityReference{ID: al, Source: &cdx.Source{Name: aliasSource(al)}}
			}
			v.References = &refs
		}
		if !s.Timestamp.IsZero() {
			a.LastUpdated = s.Timestamp.UTC().Format(time.RFC3339)
		}
		vulns = append(vulns, v)
	}
	bom.Components = &top
	bom.Vulnerabilities = &vulns
	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.EncodeVersion(bom, cdx.SpecVersion1_6)
}

func aliasSource(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "NVD"
	case strings.HasPrefix(id, "GHSA-"):
		return "GitHub"
	}
	return "OSV"
}

func purlName(p string) string {
	if pu, err := packageurl.FromString(p); err == nil {
		if pu.Namespace != "" {
			return pu.Namespace + "/" + pu.Name
		}
		return pu.Name
	}
	return p
}

func purlVersion(p string) string {
	if pu, err := packageurl.FromString(p); err == nil {
		return pu.Version
	}
	return ""
}

// uuidFrom shapes 32 hex characters of a hash as a (version 5 style) UUID,
// so the same export has the same serial number.
func uuidFrom(h string) string {
	b := []byte(h[:32])
	b[12] = '5'
	switch b[16] {
	case '0', '1', '2', '3', '4', '5', '6', '7', 'c', 'd', 'e', 'f':
		b[16] = '8'
	}
	return string(b[0:8]) + "-" + string(b[8:12]) + "-" + string(b[12:16]) + "-" + string(b[16:20]) + "-" + string(b[20:32])
}
