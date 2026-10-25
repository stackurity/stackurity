package sbom

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
)

// FuzzImport feeds arbitrary documents to the importer. It must never
// panic, and whatever it accepts must stay within the batch limits and
// survive validation (which may reject it, cleanly).
func FuzzImport(f *testing.F) {
	for _, s := range []string{cdxDoc, spdxDocJSON, `{}`, `{"bomFormat":"CycloneDX"}`, `{"spdxVersion":"SPDX-2.3"}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"x","purl":"pkg:::"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"bom-ref":"a","name":"a"}},"dependencies":[{"ref":"a","dependsOn":["a"]}]}`,
		`{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"x","externalRefs":[{"referenceType":"purl","referenceLocator":"not a purl"}]}]}`,
		nested(40), `[`, `null`, "\x00\xff"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := Import(bytes.NewReader(data), nil, "fuzz")
		if err != nil {
			return
		}
		if len(b.Observations) > model.MaxObservations {
			t.Fatalf("%d observations", len(b.Observations))
		}
		_ = b.Validate()
	})
}

// nested is a CycloneDX document whose components nest depth levels deep.
func nested(depth int) string {
	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":`)
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&b, `[{"type":"library","name":"c%d","version":"1","components":`, i)
	}
	b.WriteString(`[]`)
	for i := 0; i < depth; i++ {
		b.WriteString(`}]`)
	}
	b.WriteString(`}`)
	return b.String()
}

// TestHostileSBOMs: documents built to exhaust the importer end with a clean
// error, or a batch that validation refuses, quickly.
func TestHostileSBOMs(t *testing.T) {
	huge := strings.Repeat("a", 4<<20)
	many := func(n int, format string) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, format, i)
		}
		return b.String()
	}
	cycle := `{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"bom-ref":"a","name":"a"}},
		"components":[{"bom-ref":"b","type":"library","name":"b","version":"1"}],
		"dependencies":[{"ref":"a","dependsOn":["b"]},{"ref":"b","dependsOn":["a"]},{"ref":"a","dependsOn":["a"]}]}`
	spdxCycle := `{"spdxVersion":"SPDX-2.3","documentDescribes":["A"],"packages":[{"SPDXID":"A","name":"a"},{"SPDXID":"B","name":"b","versionInfo":"1"}],
		"relationships":[{"spdxElementId":"A","relationshipType":"DEPENDS_ON","relatedSpdxElement":"B"},{"spdxElementId":"B","relationshipType":"DEPENDS_ON","relatedSpdxElement":"A"}]}`
	for _, c := range []struct {
		name    string
		doc     string
		wantErr bool // Import itself refuses; otherwise Validate must
		valid   bool // the batch is fine (cycles are harmless data)
	}{
		{"deep nesting", nested(maxDepth + 5), true, false},
		{"JSON nested past the decoder's limit", strings.Repeat(`{"a":`, 20000) + "1" + strings.Repeat("}", 20000), true, false},
		{"enormous name", `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"` + huge + `","version":"1"}]}`, false, false},
		{"enormous purl", `{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"x","name":"x","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/` + huge + `@1"}]}]}`, false, false},
		{"too many components", `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[` + many(model.MaxObservations+1, `{"type":"library","name":"c%d","version":"1"}`) + `]}`, true, false},
		{"too many SPDX packages", `{"spdxVersion":"SPDX-2.3","packages":[` + many(model.MaxObservations+1, `{"SPDXID":"p%d","name":"p","versionInfo":"1"}`) + `]}`, true, false},
		{"dependency cycle", cycle, false, true},
		{"SPDX relationship cycle", spdxCycle, false, true},
		{"wrong types", `{"bomFormat":"CycloneDX","specVersion":"1.5","components":{"a":1}}`, true, false},
		{"truncated", cdxDoc[:len(cdxDoc)/2], true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			b, err := Import(strings.NewReader(c.doc), nil, "t")
			if time.Since(start) > 20*time.Second {
				t.Errorf("took %s", time.Since(start))
			}
			if c.wantErr {
				if err == nil {
					t.Fatalf("accepted (%d observations)", len(b.Observations))
				}
				return
			}
			if err != nil {
				t.Fatalf("import: %v", err)
			}
			verr := b.Validate()
			if c.valid && verr != nil {
				t.Errorf("validate: %v", verr)
			}
			var ve *model.ValidationError
			if !c.valid && !errors.As(verr, &ve) {
				t.Errorf("validation accepted it: %v", verr)
			}
			if ve != nil && len(ve.Error()) > 64<<10 {
				t.Errorf("validation error is %d bytes", len(ve.Error()))
			}
		})
	}

	// Larger than the document limit: refused before parsing.
	big := bytes.NewReader(append([]byte(`{"bomFormat":"CycloneDX","x":"`), bytes.Repeat([]byte("a"), MaxDocumentSize)...))
	if _, err := Import(big, nil, "t"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized document: %v", err)
	}
}
