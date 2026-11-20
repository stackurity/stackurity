package docker

import (
	"testing"

	"github.com/stackurity/stackurity/internal/collect/confcheck"
	"github.com/stackurity/stackurity/internal/collect/gobin"
	"github.com/stackurity/stackurity/internal/model"
)

// An image's attack tool check is complete only when every executable was
// read; one pulled by digest is matched by its digest reference.
func TestFillAttackTools(t *testing.T) {
	mk := func() *model.ObservationBatch {
		return model.NewBatch(model.Collector{ID: CollectorID}, model.AssetRef{Kind: model.AssetImage, Name: "x",
			Attributes: map[string]string{"image": "0123456789ab", "repo_digests": "tomicdd/artex@sha256:abc"}})
	}
	b := mk()
	fill(b, "image:x", Reading{Coverage: []model.CoverageItem{{Scope: gobin.Scope, Status: "checked"}}}, true)
	if cs := b.ConfigFindings; cs == nil || !cs.Complete || len(cs.Found) != 1 || cs.Found[0].Rule != confcheck.RuleAttackToolArtexBackdoor {
		t.Fatalf("full read: %+v", cs)
	}
	b = mk()
	fill(b, "image:x", Reading{Coverage: []model.CoverageItem{{Scope: gobin.Scope, Status: "partial", Reason: "stopped after 10000 executables"}}}, true)
	if cs := b.ConfigFindings; cs.Complete || cs.Reason == "" {
		t.Errorf("partial read marked complete: %+v", cs)
	}
}
