package store_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Pure: digests with or without their algorithm or image name.
func TestNormalizeImageDigest(t *testing.T) {
	hex := strings.Repeat("0a", 32)
	for in, want := range map[string]string{
		"sha256:" + hex:                          "sha256:" + hex,
		hex:                                      "sha256:" + hex,
		"SHA256:" + strings.ToUpper(hex):         "sha256:" + hex,
		"ghcr.io/acme/app@sha256:" + hex:         "sha256:" + hex,
		" sha256:" + hex + " ":                   "sha256:" + hex,
		"sha256:" + hex[:62]:                     "",
		"sha256:" + strings.Repeat("zz", 32):     "",
		"sha512:" + hex + hex:                    "",
		"nginx:1.27":                             "",
		"":                                       "",
		"ghcr.io/acme/app:1@sha256:" + hex + "0": "",
	} {
		if got := store.NormalizeImageDigest(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestGatePolicyChecksStore(t *testing.T) {
	s := store.New(testdb.New(t))
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	web := ingestHost(t, s, ctx, "web", "pkg:generic/openssl@3.0.2")

	// Recorded and listed newest first; long text is cut to fit.
	uid := int64(0)
	c, err := s.RecordGatePolicyCheck(ctx, store.GatePolicyCheck{AssetID: &web, AssetName: "web", Source: store.GateSourceCI,
		ActorType: "token", ActorID: &uid, ActorName: "job", Commit: strings.Repeat("a", 150), Ref: "refs/heads/main",
		Result: store.GateResultWarn, Violations: json.RawMessage(`[{"policy_id":1}]`)})
	if err != nil {
		t.Fatal(err)
	}
	if c.ID == 0 || len(c.Commit) != 100 || c.ActorID != nil || c.Result != "warn" || c.CreatedAt.IsZero() {
		t.Errorf("recorded %+v", c)
	}
	if _, err := s.RecordGatePolicyCheck(ctx, store.GatePolicyCheck{AssetID: &web, AssetName: "web", Source: store.GateSourceDeploy,
		Result: store.GateResultPass}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordGatePolicyCheck(ctx, store.GatePolicyCheck{Source: "cron", Result: "pass"}); err == nil {
		t.Error("an unknown source was stored")
	}
	list, err := s.GatePolicyChecks(ctx, web, 0)
	if err != nil || len(list) != 2 || list[0].Source != "deploy" || string(list[0].Violations) != "[]" || list[1].Source != "ci" {
		t.Fatalf("list %v %+v", err, list)
	}
	if all, err := s.GatePolicyChecks(ctx, 0, 1); err != nil || len(all) != 1 {
		t.Errorf("limit: %v %d", err, len(all))
	}

	// An upload's asset and submitter.
	b := model.NewBatch(model.Collector{ID: "test", Version: "1", Method: "scanner"}, model.AssetRef{Kind: model.AssetImage, Name: "ghcr.io/acme/app:1",
		Identifiers: []model.Identifier{{Scheme: "image-ref", Value: "ghcr.io/acme/app:1"}},
		Attributes:  map[string]string{"digest": "sha256:" + strings.Repeat("c0", 32)}})
	b.Observations = []model.Observation{{Purl: "pkg:deb/debian/bash@5.2", Confidence: model.ConfidenceConfirmed}}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	r, err := s.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	asset, submitter, err := s.CollectionAsset(ctx, r.CollectionID)
	if err != nil || asset != r.AssetID || submitter != nil {
		t.Errorf("collection asset: %d %v %v", asset, submitter, err)
	}
	if _, _, err := s.CollectionAsset(ctx, 99999999); err != store.ErrNotFound {
		t.Errorf("unknown collection: %v", err)
	}

	// Images by digest; repositories by URL, whatever the case.
	if id, err := s.AssetByImageDigest(ctx, "ghcr.io/acme/app@sha256:"+strings.Repeat("C0", 32)); err != nil || id != r.AssetID {
		t.Errorf("by digest: %d %v", id, err)
	}
	if _, err := s.AssetByImageDigest(ctx, "sha256:"+strings.Repeat("c1", 32)); err != store.ErrNotFound {
		t.Errorf("unknown digest: %v", err)
	}
	rb := model.NewBatch(model.Collector{ID: "test", Version: "1", Method: "scanner"}, model.AssetRef{Kind: model.AssetRepository, Name: "app",
		Identifiers: []model.Identifier{{Scheme: "git-url", Value: "https://github.com/acme/app"}}})
	rb.Observations = []model.Observation{{Purl: "pkg:npm/left-pad@1.0.0", Confidence: model.ConfidenceConfirmed}}
	if err := rb.Validate(); err != nil {
		t.Fatal(err)
	}
	rr, err := s.Ingest(ctx, rb, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"https://github.com/acme/app", "https://github.com/Acme/App"} {
		if id, err := s.AssetByGitURL(ctx, u); err != nil || id != rr.AssetID {
			t.Errorf("%s: %d %v", u, id, err)
		}
	}
	if _, err := s.AssetByGitURL(ctx, "https://github.com/acme/lib"); err != store.ErrNotFound {
		t.Errorf("unknown repository: %v", err)
	}
}
