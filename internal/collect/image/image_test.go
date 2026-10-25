package image

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

func TestValidate(t *testing.T) {
	good := []string{"nginx", "nginx:1.25", "library/nginx:1.25-alpine", "ghcr.io/acme/shop:v1.4.0",
		"localhost:5000/app:dev", "nginx@sha256:" + sixtyFour, "ghcr.io/a/b:1@sha256:" + sixtyFour}
	for _, ref := range good {
		if err := (Config{Image: ref}).Validate(); err != nil {
			t.Errorf("%s: %v", ref, err)
		}
	}
	// "docker:nginx" is a valid reference (image docker, tag nginx); the
	// scanner always prefixes "registry:", so no source scheme can be injected.
	bad := []string{"", "dir:/etc", "file:/etc/passwd", "--output=x", "nginx latest", "oci-archive:/x.tar",
		"Nginx", "nginx:" + string(make([]byte, 200))}
	for _, ref := range bad {
		if (Config{Image: ref}).Validate() == nil {
			t.Errorf("%q should be rejected", ref)
		}
	}
	if (Config{Image: "nginx", Platform: "linux/amd64; rm"}).Validate() == nil {
		t.Error("bad platform accepted")
	}
}

const sixtyFour = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestRegistryHost(t *testing.T) {
	for ref, want := range map[string]string{"nginx": "index.docker.io", "library/nginx": "index.docker.io",
		"ghcr.io/a/b": "ghcr.io", "localhost:5000/x": "localhost:5000"} {
		if got := registryHost(ref); got != want {
			t.Errorf("%s = %s", ref, got)
		}
	}
}

// TestScanLive scans a small public image when syft is available and the
// test is explicitly enabled (it needs network access).
func TestScanLive(t *testing.T) {
	bin := os.Getenv("STACKURITY_TEST_SYFT")
	if bin == "" {
		t.Skip("STACKURITY_TEST_SYFT not set")
	}
	if _, err := exec.LookPath(bin); err != nil {
		t.Skip(err)
	}
	s := &Scanner{Syft: bin, Version: "test", WorkDir: t.TempDir()}
	b, err := s.Scan(context.Background(), Config{Image: "alpine:3.19", Platform: "linux/amd64"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range b.Observations {
		if o.Version != "" && len(o.Purl) > 8 && o.Purl[:8] == "pkg:apk/" {
			found = true
		}
	}
	if !found || b.Asset.Kind != "image" {
		t.Errorf("expected apk packages in alpine image: %d observations", len(b.Observations))
	}
	t.Logf("%d observations, digest %s", len(b.Observations), b.Asset.Attributes["digest"])
}

func TestReferenceOnly(t *testing.T) {
	ref := "docker.io/library/nginx@sha256:" + strings.Repeat("a", 64)
	stub := func(kind model.AssetKind, id string, attrs map[string]string) *model.ObservationBatch {
		return model.NewBatch(model.Collector{ID: "plugin:kubernetes"}, model.AssetRef{Kind: kind, Name: id,
			Identifiers: []model.Identifier{{Scheme: "image-ref", Value: id}}, Attributes: attrs})
	}
	cfg, ok := ReferenceOnly(stub(model.AssetImage, ref, map[string]string{"platform": "linux/arm64"}))
	if !ok || cfg.Image != ref || cfg.Platform != "linux/arm64" {
		t.Errorf("stub = %+v %v", cfg, ok)
	}
	if cfg, ok := ReferenceOnly(stub(model.AssetImage, ref, map[string]string{"platform": "--bad"})); !ok || cfg.Platform != "" {
		t.Errorf("bad platform kept: %+v", cfg)
	}
	withPkgs := stub(model.AssetImage, ref, nil)
	withPkgs.Observations = []model.Observation{{Purl: "pkg:deb/debian/bash@5"}}
	for _, b := range []*model.ObservationBatch{
		withPkgs, stub(model.AssetWorkload, ref, nil), stub(model.AssetImage, "registry:--config=/etc/x", nil),
		stub(model.AssetImage, "file:/etc/passwd", nil),
	} {
		if _, ok := ReferenceOnly(b); ok {
			t.Errorf("%s %s accepted", b.Asset.Kind, b.Asset.Name)
		}
	}
}
