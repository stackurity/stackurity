// Package sbom imports CycloneDX and SPDX JSON documents as observation
// batches and exports inventory as CycloneDX. Imported documents are
// untrusted: size, depth and component counts are bounded.
package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/model"
)

const (
	MaxDocumentSize = 64 << 20
	maxDepth        = 32
)

var ErrUnknownFormat = errors.New("document is neither CycloneDX JSON nor SPDX JSON")

// Import reads an SBOM and returns a batch. When asset is non-nil it is used
// as the target asset; otherwise the asset is derived from the document.
func Import(r io.Reader, asset *model.AssetRef, version string) (*model.ObservationBatch, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxDocumentSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxDocumentSize {
		return nil, fmt.Errorf("SBOM larger than %d MiB", MaxDocumentSize>>20)
	}
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parse SBOM: %w", err)
	}
	switch {
	case probe.BOMFormat == "CycloneDX":
		return importCycloneDX(data, asset, version)
	case strings.HasPrefix(probe.SPDXVersion, "SPDX-2"):
		return importSPDX(data, asset, version)
	}
	return nil, ErrUnknownFormat
}

func genericPurl(name, version string) string {
	return packageurl.NewPackageURL("generic", "", name, version, nil, "").ToString()
}

func importCycloneDX(data []byte, asset *model.AssetRef, version string) (*model.ObservationBatch, error) {
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, fmt.Errorf("parse CycloneDX: %w", err)
	}
	ref := model.AssetRef{Kind: model.AssetSBOM, Name: "sbom"}
	rootRef := ""
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		mc := bom.Metadata.Component
		rootRef = mc.BOMRef
		ref.Name = strings.TrimSpace(mc.Name + " " + mc.Version)
		if mc.PackageURL != "" {
			ref.Identifiers = append(ref.Identifiers, model.Identifier{Scheme: "purl", Value: mc.PackageURL})
		}
		if mc.Type == cdx.ComponentTypeContainer {
			ref.Kind = model.AssetImage
		} else if mc.Type == cdx.ComponentTypeApplication {
			ref.Kind = model.AssetApplication
		}
	}
	if bom.SerialNumber != "" {
		ref.Identifiers = append(ref.Identifiers, model.Identifier{Scheme: "sbom-serial", Value: bom.SerialNumber})
	}
	if len(ref.Identifiers) == 0 {
		ref.Identifiers = []model.Identifier{{Scheme: "sbom-name", Value: ref.Name}}
	}
	if asset != nil {
		ref = *asset
	}
	b := model.NewBatch(model.Collector{ID: "cyclonedx-import", Version: version, Method: "sbom"}, ref)
	b.Complete = true

	direct := map[string]bool{}
	hasGraph := false
	if bom.Dependencies != nil && rootRef != "" {
		for _, d := range *bom.Dependencies {
			if d.Ref == rootRef && d.Dependencies != nil {
				hasGraph = true
				for _, dep := range *d.Dependencies {
					direct[dep] = true
				}
			}
		}
	}
	var walk func(cs *[]cdx.Component, depth int) error
	walk = func(cs *[]cdx.Component, depth int) error {
		if cs == nil {
			return nil
		}
		if depth > maxDepth {
			return errors.New("component nesting too deep")
		}
		for _, c := range *cs {
			if len(b.Observations) >= model.MaxObservations {
				return errors.New("too many components")
			}
			if c.Type == cdx.ComponentTypeFile {
				// Files (config, binaries without package metadata) are not
				// software components; nested components are still walked.
				if err := walk(c.Components, depth+1); err != nil {
					return err
				}
				continue
			}
			p, conf := c.PackageURL, model.ConfidenceConfirmed
			ev := map[string]string{"format": "CycloneDX " + bom.SpecVersion.String()}
			if c.Type == cdx.ComponentTypeOS && p == "" && c.Name != "" {
				// Same identity the Linux agent uses, so lifecycle data applies.
				p = genericPurl(strings.ToLower(c.Name), c.Version)
				ev["kind"] = "operating-system"
			} else if p == "" {
				p, conf = genericPurl(c.Name, c.Version), model.ConfidenceLow
			}
			if c.Version == "" {
				conf = model.ConfidenceUnknown
			}
			if c.BOMRef != "" {
				ev["bom_ref"] = clipEvidence(c.BOMRef)
			}
			if c.Supplier != nil && c.Supplier.Name != "" {
				ev["supplier"] = clipEvidence(c.Supplier.Name)
			}
			var d *bool
			if hasGraph {
				v := direct[c.BOMRef]
				d = &v
			}
			b.Observations = append(b.Observations, model.Observation{
				Purl: p, Version: c.Version, Direct: d, Confidence: conf, Evidence: ev,
				Scope: string(c.Scope),
			})
			if err := walk(c.Components, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(bom.Components, 0); err != nil {
		return nil, err
	}
	b.Cover("cyclonedx", "checked", "")
	return b, nil
}

type spdxDoc struct {
	SPDXVersion       string   `json:"spdxVersion"`
	Name              string   `json:"name"`
	DocumentNamespace string   `json:"documentNamespace"`
	DocumentDescribes []string `json:"documentDescribes"`
	Packages          []struct {
		SPDXID       string `json:"SPDXID"`
		Name         string `json:"name"`
		VersionInfo  string `json:"versionInfo"`
		Supplier     string `json:"supplier"`
		ExternalRefs []struct {
			Category string `json:"referenceCategory"`
			Type     string `json:"referenceType"`
			Locator  string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
	Relationships []struct {
		Element string `json:"spdxElementId"`
		Type    string `json:"relationshipType"`
		Related string `json:"relatedSpdxElement"`
	} `json:"relationships"`
}

func importSPDX(data []byte, asset *model.AssetRef, version string) (*model.ObservationBatch, error) {
	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse SPDX: %w", err)
	}
	roots := map[string]bool{}
	for _, id := range doc.DocumentDescribes {
		roots[id] = true
	}
	for _, r := range doc.Relationships {
		if r.Element == "SPDXRef-DOCUMENT" && r.Type == "DESCRIBES" {
			roots[r.Related] = true
		}
	}
	direct := map[string]bool{}
	hasGraph := false
	for _, r := range doc.Relationships {
		if roots[r.Element] && (r.Type == "DEPENDS_ON" || r.Type == "CONTAINS") {
			direct[r.Related] = true
			hasGraph = true
		}
	}
	ref := model.AssetRef{Kind: model.AssetSBOM, Name: doc.Name}
	if ref.Name == "" {
		ref.Name = "spdx document"
	}
	if doc.DocumentNamespace != "" {
		ref.Identifiers = []model.Identifier{{Scheme: "sbom-serial", Value: doc.DocumentNamespace}}
	} else {
		ref.Identifiers = []model.Identifier{{Scheme: "sbom-name", Value: ref.Name}}
	}
	if asset != nil {
		ref = *asset
	}
	b := model.NewBatch(model.Collector{ID: "spdx-import", Version: version, Method: "sbom"}, ref)
	b.Complete = true
	for _, p := range doc.Packages {
		if roots[p.SPDXID] {
			continue // the described artefact itself, not a component of it
		}
		if len(b.Observations) >= model.MaxObservations {
			return nil, errors.New("too many packages")
		}
		v := p.VersionInfo
		if v == "NOASSERTION" {
			v = ""
		}
		purl, conf := "", model.ConfidenceConfirmed
		for _, er := range p.ExternalRefs {
			if er.Type == "purl" {
				purl = er.Locator
				break
			}
		}
		if purl == "" {
			purl, conf = genericPurl(p.Name, v), model.ConfidenceLow
		}
		if v == "" {
			conf = model.ConfidenceUnknown
		}
		ev := map[string]string{"format": clipEvidence(doc.SPDXVersion), "spdx_id": clipEvidence(p.SPDXID)}
		if p.Supplier != "" && p.Supplier != "NOASSERTION" {
			ev["supplier"] = clipEvidence(p.Supplier)
		}
		var d *bool
		if hasGraph {
			x := direct[p.SPDXID]
			d = &x
		}
		b.Observations = append(b.Observations, model.Observation{Purl: purl, Version: v, Direct: d, Confidence: conf, Evidence: ev})
	}
	b.Cover("spdx", "checked", "")
	return b, nil
}

// ExportComponent is one inventory row to export.
type ExportComponent struct {
	Purl    string
	Name    string
	Version string
	Direct  *bool
}

// Property is a name and value recorded in the document's metadata (a
// trial watermark, for example).
type Property struct {
	Name, Value string
}

// ExportCycloneDX writes a CycloneDX 1.6 JSON document for one asset, with
// props as metadata properties.
func ExportCycloneDX(w io.Writer, assetName, assetKind, toolVersion string, comps []ExportComponent, props ...Property) error {
	rootType := cdx.ComponentTypeApplication
	if assetKind == string(model.AssetImage) {
		rootType = cdx.ComponentTypeContainer
	} else if assetKind == string(model.AssetHost) {
		rootType = cdx.ComponentTypeOS
	}
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{Components: &[]cdx.Component{{
			Type: cdx.ComponentTypeApplication, Name: "stackurity", Version: toolVersion,
		}}},
		Component: &cdx.Component{BOMRef: "root", Type: rootType, Name: assetName},
	}
	if len(props) > 0 {
		list := make([]cdx.Property, len(props))
		for i, p := range props {
			list[i] = cdx.Property{Name: p.Name, Value: p.Value}
		}
		bom.Metadata.Properties = &list
	}
	list := make([]cdx.Component, 0, len(comps))
	var directRefs []string
	seen := map[string]bool{}
	for _, c := range comps {
		if seen[c.Purl] {
			continue
		}
		seen[c.Purl] = true
		list = append(list, cdx.Component{
			BOMRef: c.Purl, Type: cdx.ComponentTypeLibrary, Name: c.Name, Version: c.Version, PackageURL: c.Purl,
		})
		if c.Direct != nil && *c.Direct {
			directRefs = append(directRefs, c.Purl)
		}
	}
	bom.Components = &list
	if len(directRefs) > 0 {
		bom.Dependencies = &[]cdx.Dependency{{Ref: "root", Dependencies: &directRefs}}
	}
	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.EncodeVersion(bom, cdx.SpecVersion1_6)
}

// clipEvidence keeps a descriptive value (supplier, document reference)
// within the batch's field limit: one over-long value used to make the
// server refuse the whole document.
func clipEvidence(s string) string {
	if len(s) <= model.MaxFieldLen {
		return s
	}
	cut := model.MaxFieldLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
