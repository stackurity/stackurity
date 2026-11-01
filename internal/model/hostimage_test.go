package model

import (
	"strings"
	"testing"
)

func TestHostImageValidation(t *testing.T) {
	host := []Identifier{{Scheme: "machine-id", Value: "m1"}}
	image := func(ref string) *ObservationBatch {
		b := NewBatch(Collector{ID: "linux-docker"}, AssetRef{Kind: AssetImage, Name: ref + " on m1",
			Identifiers: []Identifier{{Scheme: HostImageScheme, Value: ref}}})
		b.Relations = []RelationRef{{Kind: "runs_on", To: host}}
		return b
	}
	if err := image("postgres:16").Validate(); err != nil {
		t.Errorf("valid image: %v", err)
	}
	for name, b := range map[string]*ObservationBatch{
		"no runs_on":   func() *ObservationBatch { b := image("postgres:16"); b.Relations = nil; return b }(),
		"not an image": func() *ObservationBatch { b := image("postgres:16"); b.Asset.Kind = AssetApplication; return b }(),
		"two identifiers": func() *ObservationBatch {
			b := image("x:1")
			b.Asset.Identifiers = append(b.Asset.Identifiers, host...)
			return b
		}(),
		"space":    image("x 1"),
		"too long": image(strings.Repeat("a", 600)),
		"as relation": func() *ObservationBatch {
			b := image("x:1")
			b.Relations[0].To = []Identifier{{Scheme: HostImageScheme, Value: "x:1"}}
			return b
		}(),
		"list on an image": func() *ObservationBatch { b := image("x:1"); b.Images = &ImageList{Refs: []string{"x:1"}}; return b }(),
	} {
		if err := b.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	hb := NewBatch(Collector{ID: "linux-docker"}, AssetRef{Kind: AssetHost, Name: "m1", Identifiers: host})
	hb.Images = &ImageList{Refs: []string{"postgres:16", "sha256:" + strings.Repeat("a", 64)}}
	if err := hb.Validate(); err != nil {
		t.Errorf("host list: %v", err)
	}
	hb.Images.Refs = append(hb.Images.Refs, "bad\nref")
	if err := hb.Validate(); err == nil {
		t.Error("control character in the list accepted")
	}
}
