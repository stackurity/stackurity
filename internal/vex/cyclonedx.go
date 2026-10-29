package vex

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// CycloneDX VEX: vulnerabilities[] with an analysis, each affecting
// components by bom-ref. A reference resolves to a component of the same
// BOM (embedded VEX, or a VEX document that lists the components), to a
// component of another BOM by BOM-Link (urn:cdx:<serial>/<version>#<ref>),
// or is itself a package URL.

type cdxBOM struct {
	BOMFormat    string `json:"bomFormat"`
	SpecVersion  string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Version      any    `json:"version"`
	Metadata     *struct {
		Timestamp string        `json:"timestamp"`
		Component *cdxComponent `json:"component"`
		Authors   []struct {
			Name string `json:"name"`
		} `json:"authors"`
		Supplier *struct {
			Name string `json:"name"`
		} `json:"supplier"`
		Manufacturer *struct {
			Name string `json:"name"`
		} `json:"manufacturer"`
	} `json:"metadata"`
	Components      []cdxComponent     `json:"components"`
	Vulnerabilities []cdxVulnerability `json:"vulnerabilities"`
}

type cdxComponent struct {
	BOMRef  string `json:"bom-ref"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl"`
	CPE     string `json:"cpe"`
	Hashes  []struct {
		Alg     string `json:"alg"`
		Content string `json:"content"`
	} `json:"hashes"`
	Components []cdxComponent `json:"components"`
}

type cdxVulnerability struct {
	ID         string `json:"id"`
	References []struct {
		ID string `json:"id"`
	} `json:"references"`
	Recommendation string `json:"recommendation"`
	Workaround     string `json:"workaround"`
	Updated        string `json:"updated"`
	Analysis       *struct {
		State         string   `json:"state"`
		Justification string   `json:"justification"`
		Response      []string `json:"response"`
		Detail        string   `json:"detail"`
		LastUpdated   string   `json:"lastUpdated"`
		FirstIssued   string   `json:"firstIssued"`
	} `json:"analysis"`
	Affects []struct {
		Ref      string `json:"ref"`
		Versions []struct {
			Version string `json:"version"`
			Range   string `json:"range"`
			Status  string `json:"status"`
		} `json:"versions"`
	} `json:"affects"`
}

// CycloneDX analysis states and what they are in OpenVEX terms.
var cdxStates = map[string]string{
	"not_affected":           StatusNotAffected,
	"false_positive":         StatusNotAffected,
	"exploitable":            StatusAffected,
	"in_triage":              StatusUnderInvestigation,
	"resolved":               StatusFixed,
	"resolved_with_pedigree": StatusFixed,
}

// CycloneDX justifications and the nearest OpenVEX one.
var cdxJustifications = map[string]string{
	"code_not_present":                JustVulnerableCodeNotPresent,
	"code_not_reachable":              JustVulnerableCodeNotInExecutePath,
	"requires_configuration":          JustVulnerableCodeCannotBeControlledByAdversary,
	"requires_dependency":             JustComponentNotPresent,
	"requires_environment":            JustVulnerableCodeCannotBeControlledByAdversary,
	"protected_by_compiler":           JustInlineMitigationsAlreadyExist,
	"protected_at_runtime":            JustInlineMitigationsAlreadyExist,
	"protected_at_perimeter":          JustInlineMitigationsAlreadyExist,
	"protected_by_mitigating_control": JustInlineMitigationsAlreadyExist,
}

// CycloneDXJustification is the CycloneDX justification written for an
// OpenVEX one.
func CycloneDXJustification(j string) string {
	switch j {
	case JustComponentNotPresent, JustVulnerableCodeNotPresent:
		return "code_not_present"
	case JustVulnerableCodeNotInExecutePath:
		return "code_not_reachable"
	case JustVulnerableCodeCannotBeControlledByAdversary:
		return "requires_environment"
	case JustInlineMitigationsAlreadyExist:
		return "protected_by_mitigating_control"
	}
	return ""
}

// cdxNode is a component of the BOM with the container or application it
// sits in, if any.
type cdxNode struct {
	c      *cdxComponent
	parent *cdxNode
}

func readCycloneDX(data []byte) (*Document, error) {
	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("parse CycloneDX: %w", err)
	}
	if bom.BOMFormat != "CycloneDX" {
		return nil, ErrUnknownFormat
	}
	if len(bom.Vulnerabilities) > MaxStatements {
		return nil, fmt.Errorf("more than %d vulnerabilities", MaxStatements)
	}
	doc := &Document{Format: FormatCycloneDX, ID: clip(bom.SerialNumber, maxIDLen), Spec: clip(bom.SpecVersion, 20)}
	if bom.Version != nil {
		doc.Version = clip(fmt.Sprint(bom.Version), 50)
	}
	byRef := map[string]*cdxNode{}
	count := 0
	var walk func(cs []cdxComponent, parent *cdxNode, depth int) error
	walk = func(cs []cdxComponent, parent *cdxNode, depth int) error {
		if depth > maxDepth {
			return errors.New("component nesting too deep")
		}
		for i := range cs {
			count++
			if count > maxComponents {
				return errors.New("too many components")
			}
			n := &cdxNode{c: &cs[i], parent: parent}
			if r := cs[i].BOMRef; r != "" {
				if _, dup := byRef[r]; !dup {
					byRef[r] = n
				}
			}
			if err := walk(cs[i].Components, n, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	var subject *cdxNode
	if m := bom.Metadata; m != nil {
		doc.Timestamp = parseTime(m.Timestamp)
		switch {
		case len(m.Authors) > 0 && m.Authors[0].Name != "":
			doc.Author = clip(m.Authors[0].Name, 200)
		case m.Supplier != nil && m.Supplier.Name != "":
			doc.Author = clip(m.Supplier.Name, 200)
		case m.Manufacturer != nil && m.Manufacturer.Name != "":
			doc.Author = clip(m.Manufacturer.Name, 200)
		}
		if m.Component != nil {
			subject = &cdxNode{c: m.Component}
			if r := m.Component.BOMRef; r != "" {
				byRef[r] = subject
			}
			if err := walk(m.Component.Components, subject, 1); err != nil {
				return nil, err
			}
		}
	}
	// Top-level components sit in the document's subject (an SBOM with
	// VEX embedded describes one product).
	if err := walk(bom.Components, subject, 0); err != nil {
		return nil, err
	}
	serial := strings.TrimSpace(bom.SerialNumber)
	refs := 0
	for _, v := range bom.Vulnerabilities {
		if v.Analysis == nil || v.Analysis.State == "" {
			doc.Skipped++
			continue
		}
		a := v.Analysis
		st := Statement{Vulnerability: NormalizeVulnID(v.ID), OriginalState: clip(a.State, 50),
			OriginalJustification: clip(a.Justification, 80), Status: cdxStates[a.State]}
		if st.Status == "" {
			st.Status = clip(a.State, 50) // checkStatement reports it
		}
		if a.Justification != "" {
			st.Justification = cdxJustifications[a.Justification]
			if st.Justification == "" {
				st.Justification = a.Justification // reported as unknown
			}
		} else if a.State == "false_positive" {
			st.Justification = JustVulnerableCodeNotPresent
		}
		detail := clip(a.Detail, maxTextLen)
		switch st.Status {
		case StatusNotAffected:
			st.ImpactStatement = detail
		case StatusAffected:
			action := strings.TrimSpace(strings.Join(nonEmpty(v.Recommendation, v.Workaround, strings.Join(a.Response, ", ")), "; "))
			st.ActionStatement = clip(action, maxTextLen)
			st.StatusNotes = detail
		default:
			st.StatusNotes = detail
		}
		for _, t := range []string{a.LastUpdated, v.Updated, a.FirstIssued} {
			if ts := parseTime(t); ts != nil {
				st.Timestamp = ts
				break
			}
		}
		var al []string
		for _, r := range v.References {
			al = append(al, r.ID)
		}
		st.Aliases = aliases(al, st.Vulnerability)
		if len(v.Affects) > MaxProducts {
			return nil, fmt.Errorf("a vulnerability affects more than %d components", MaxProducts)
		}
		for _, af := range v.Affects {
			refs++
			if refs > MaxProductRefs {
				return nil, fmt.Errorf("more than %d products in the document", MaxProductRefs)
			}
			ps := cdxProducts(af.Ref, byRef, subject, serial)
			// Exact versions listed for a reference without one name the
			// versions the analysis is about; ranges are not matched.
			for _, ver := range af.Versions {
				if ver.Range != "" {
					for i := range ps {
						ps[i].Problem = "version ranges are not matched; list exact versions"
					}
					break
				}
				if ver.Version == "" {
					continue
				}
				if (st.Status == StatusNotAffected && ver.Status == "affected") || (st.Status == StatusAffected && ver.Status == "unaffected") {
					for i := range ps {
						ps[i].Problem = "the version list contradicts the analysis"
					}
					break
				}
			}
			st.Products = append(st.Products, ps...)
		}
		checkStatement(&st)
		doc.Statements = append(doc.Statements, st)
	}
	return doc, nil
}

func nonEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// cdxIdentity is what identifies a component on its own: its package URL
// (an image's carries the digest), a CPE, or an image digest in its hashes.
func cdxIdentity(c *cdxComponent) Product {
	var p Product
	switch {
	case c.Purl != "":
		p = productFromID(c.Purl)
	case c.CPE != "":
		p = productFromID(c.CPE)
	default:
		p = Product{ID: clip(strings.TrimSpace(c.Name+" "+c.Version), maxIDLen), Problem: "no package URL or CPE"}
	}
	if p.CPE == "" && c.CPE != "" {
		p.CPE = clip(c.CPE, maxIDLen)
	}
	if p.Digest == "" && (c.Type == "container" || isImagePurl(p.Purl)) {
		for _, h := range c.Hashes {
			if strings.EqualFold(h.Alg, "SHA-256") {
				if d := NormalizeDigest(h.Content); d != "" {
					p.Digest, p.Problem = d, ""
				}
			}
		}
		// Syft records an image's digest as the root component's version.
		if d := NormalizeDigest(c.Version); p.Digest == "" && strings.HasPrefix(c.Version, "sha256:") && d != "" {
			p.Digest, p.Problem = d, ""
		}
	}
	return p
}

// cdxProducts resolves one affects reference.
func cdxProducts(ref string, byRef map[string]*cdxNode, subject *cdxNode, serial string) []Product {
	ref = clip(ref, maxIDLen)
	if strings.HasPrefix(ref, "urn:cdx:") {
		// BOM-Link: urn:cdx:<serial>/<version>#<bom-ref>.
		rest := strings.TrimPrefix(ref, "urn:cdx:")
		head, frag, _ := strings.Cut(rest, "#")
		sn, _, _ := strings.Cut(head, "/")
		p := Product{ID: ref, Serial: "urn:uuid:" + sn}
		if frag == "" {
			return []Product{p} // the whole BOM
		}
		sub := Product{ID: frag, BOMRef: frag}
		if strings.HasPrefix(frag, "pkg:") {
			s := productFromID(frag)
			sub.Purl, sub.Digest = s.Purl, s.Digest
		}
		p.Subcomponents = []Product{sub}
		return []Product{p}
	}
	n := byRef[ref]
	if n == nil {
		if strings.HasPrefix(ref, "pkg:") || strings.HasPrefix(ref, "cpe:") {
			return []Product{productFromID(ref)}
		}
		return []Product{{ID: ref, Problem: "the reference names no component of this document"}}
	}
	own := cdxIdentity(n.c)
	// Inside a product, a component without a package URL or CPE can still
	// be found by its bom-ref among what that product's SBOM imported.
	inner := own
	if inner.Purl == "" && inner.CPE == "" && n.c.BOMRef != "" {
		inner.BOMRef, inner.Problem = n.c.BOMRef, ""
	}
	// The nearest enclosing image (by digest) or application pins the
	// component to that asset.
	for anc := n.parent; anc != nil; anc = anc.parent {
		id := cdxIdentity(anc.c)
		if id.Digest != "" || (id.Purl != "" && id.Problem == "") {
			id.Problem = ""
			if anc == subject {
				id.Serial = serial
			}
			id.Subcomponents = []Product{inner}
			return []Product{id}
		}
		if anc == subject && anc.parent == nil {
			// The document's subject without an identifier of its own: the
			// BOM's serial number or, failing that, the asset an import is
			// scoped to.
			return []Product{{ID: id.ID, Serial: serial, Root: true, Subcomponents: []Product{inner}}}
		}
	}
	if n == subject {
		if own.Digest != "" || (own.Purl != "" && own.Problem == "") {
			own.Serial = serial
			return []Product{own}
		}
		// The whole product, which has no identifier of its own.
		return []Product{{ID: own.ID, Serial: serial, Root: true}}
	}
	return []Product{own}
}
