package sbom

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stackurity/stackurity/internal/model"
)

const cdxDoc = `{
  "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": "urn:uuid:1111",
  "metadata": {"component": {"bom-ref": "app", "type": "application", "name": "shop", "version": "2.0"}},
  "components": [
    {"bom-ref": "a", "type": "library", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2",
     "components": [{"bom-ref": "n", "type": "library", "name": "inner", "version": "1.0.0"}]},
    {"bom-ref": "b", "type": "library", "name": "debug", "version": "2.6.9", "purl": "pkg:npm/debug@2.6.9"},
    {"bom-ref": "f", "type": "file", "name": "/etc/passwd"},
    {"bom-ref": "os", "type": "operating-system", "name": "Alpine", "version": "3.19.9"}
  ],
  "dependencies": [{"ref": "app", "dependsOn": ["a"]}, {"ref": "a", "dependsOn": ["b"]}]
}`

const spdxDocJSON = `{
  "spdxVersion": "SPDX-2.3", "name": "image", "documentNamespace": "https://example.com/spdx/1",
  "documentDescribes": ["SPDXRef-root"],
  "packages": [
    {"SPDXID": "SPDXRef-root", "name": "image", "versionInfo": "1"},
    {"SPDXID": "SPDXRef-zlib", "name": "zlib", "versionInfo": "1.2.13",
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:apk/alpine/zlib@1.2.13-r0"}]},
    {"SPDXID": "SPDXRef-x", "name": "mystery", "versionInfo": "NOASSERTION"}
  ],
  "relationships": [{"spdxElementId": "SPDXRef-root", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-zlib"}]
}`

func TestCycloneDXImport(t *testing.T) {
	b, err := Import(strings.NewReader(cdxDoc), nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if b.Asset.Kind != model.AssetApplication || b.Asset.Name != "shop 2.0" {
		t.Errorf("asset = %+v", b.Asset)
	}
	if len(b.Observations) != 4 {
		t.Fatalf("files must be skipped: %+v", b.Observations)
	}
	if osObs := b.Observations[3]; osObs.Purl != "pkg:generic/alpine@3.19.9" || osObs.Evidence["kind"] != "operating-system" || osObs.Confidence != model.ConfidenceConfirmed {
		t.Errorf("os component = %+v", osObs)
	}
	ex, inner, dbg := b.Observations[0], b.Observations[1], b.Observations[2]
	if !*ex.Direct || *dbg.Direct {
		t.Errorf("direct flags wrong: express=%v debug=%v", *ex.Direct, *dbg.Direct)
	}
	if inner.Purl != "pkg:generic/inner@1.0.0" || inner.Confidence != model.ConfidenceLow {
		t.Errorf("component without purl = %+v", inner)
	}
}

func TestSPDXImport(t *testing.T) {
	b, err := Import(strings.NewReader(spdxDocJSON), nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(b.Observations) != 2 {
		t.Fatalf("root package must be excluded: %+v", b.Observations)
	}
	if z := b.Observations[0]; z.Purl != "pkg:apk/alpine/zlib@1.2.13-r0" || !*z.Direct {
		t.Errorf("zlib = %+v", z)
	}
	if m := b.Observations[1]; m.Confidence != model.ConfidenceUnknown || m.Version != "" {
		t.Errorf("mystery = %+v", m)
	}
}

func TestRejectsUnknown(t *testing.T) {
	if _, err := Import(strings.NewReader(`{"hello": 1}`), nil, ""); err != ErrUnknownFormat {
		t.Errorf("err = %v", err)
	}
}

func TestExportRoundTrip(t *testing.T) {
	yes := true
	var buf bytes.Buffer
	err := ExportCycloneDX(&buf, "shop", "application", "0.1.0", []ExportComponent{
		{Purl: "pkg:npm/express@4.18.2", Name: "express", Version: "4.18.2", Direct: &yes},
		{Purl: "pkg:npm/debug@2.6.9", Name: "debug", Version: "2.6.9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Import(&buf, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Observations) != 2 || !*b.Observations[0].Direct || *b.Observations[1].Direct {
		t.Errorf("round trip = %+v", b.Observations)
	}
}

// One over-long supplier or reference is clipped, not a reason to refuse
// the whole SBOM.
func TestLongEvidenceIsClipped(t *testing.T) {
	long := strings.Repeat("é", 3000)
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"type":"application","name":"app"}},
	  "components":[{"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21",
	  "bom-ref":"` + long + `","supplier":{"name":"` + long + `"}}]}`
	b, err := Import(strings.NewReader(doc), nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("refused: %v", err)
	}
	if s := b.Observations[0].Evidence["supplier"]; len(s) > 2048 || !utf8.ValidString(s) || len(s) < 2000 {
		t.Errorf("supplier: %d bytes", len(s))
	}
}
