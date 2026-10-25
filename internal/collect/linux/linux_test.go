package linux

import (
	"context"
	"errors"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

func fixture(root string) *Collector {
	c := New("test")
	c.Root = root
	c.LookPath = func(string) (string, error) { return "", errors.New("not found") }
	return c
}

func byName(b *model.ObservationBatch) map[string]model.Observation {
	m := map[string]model.Observation{}
	for _, o := range b.Observations {
		m[o.Purl] = o
	}
	return m
}

func TestDebian(t *testing.T) {
	c := fixture("testdata/debian")
	b, err := c.Collect(context.Background(), "web-1", c.MachineID())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if b.Asset.Identifiers[0] != (model.Identifier{Scheme: "machine-id", Value: "abc123machine"}) {
		t.Errorf("identifiers = %+v", b.Asset.Identifiers)
	}
	if !b.Complete {
		t.Errorf("expected complete batch, coverage %+v", b.Coverage)
	}
	obs := byName(b)
	if len(obs) != 3 { // os + libssl3 + bash; removed-pkg excluded
		t.Fatalf("got %d observations: %v", len(obs), obs)
	}
	ssl, ok := obs["pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl"]
	if !ok {
		t.Fatalf("libssl3 missing: %v", obs)
	}
	if ssl.Evidence["source_package"] != "openssl" || ssl.Confidence != model.ConfidenceConfirmed {
		t.Errorf("libssl3 = %+v", ssl)
	}
	if o := obs["pkg:deb/debian/bash@5.2.15-2%2Bb2?arch=amd64&distro=debian-12&upstream=bash"]; o.Evidence["source_version"] != "5.2.15-2" {
		t.Errorf("bash source version = %+v", o)
	}
	if _, ok := obs["pkg:generic/debian@12"]; !ok {
		t.Error("os component missing")
	}
}

func TestAlpine(t *testing.T) {
	b, err := fixture("testdata/alpine").Collect(context.Background(), "a", "")
	if err != nil {
		t.Fatal(err)
	}
	obs := byName(b)
	if _, ok := obs["pkg:apk/alpine/libcrypto3@3.1.4-r5?arch=aarch64&distro=alpine-3.19.1&upstream=openssl"]; !ok {
		t.Errorf("libcrypto3 missing: %v", obs)
	}
}

func TestRPMMissingBinaryIsVisible(t *testing.T) {
	b, err := fixture("testdata/rocky").Collect(context.Background(), "r", "")
	if err != nil {
		t.Fatal(err)
	}
	if b.Complete {
		t.Error("batch must not be complete when rpm was skipped")
	}
	if b.Coverage[0].Scope != "rpm" || b.Coverage[0].Status != "skipped" {
		t.Errorf("coverage = %+v", b.Coverage)
	}
}

func TestRPMParse(t *testing.T) {
	c := fixture("testdata/rocky")
	c.LookPath = func(string) (string, error) { return "/usr/bin/rpm", nil }
	c.RunRPM = func(context.Context, string) ([]byte, error) {
		return []byte("openssl-libs\t1\t3.0.7\t24.el9\tx86_64\topenssl-3.0.7-24.el9.src.rpm\ngpg-pubkey\t0\tabc\tdef\t(none)\t(none)\n"), nil
	}
	b, err := c.Collect(context.Background(), "r", "")
	if err != nil {
		t.Fatal(err)
	}
	obs := byName(b)
	o, ok := obs["pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?arch=x86_64&distro=rocky-9.3&epoch=1"]
	if !ok || o.Version != "1:3.0.7-24.el9" {
		t.Errorf("openssl-libs = %+v (all %v)", o, obs)
	}
	if len(obs) != 2 {
		t.Errorf("gpg-pubkey must be skipped: %v", obs)
	}
}

func TestUnsupportedDistro(t *testing.T) {
	b, err := fixture("testdata/empty").Collect(context.Background(), "n", "")
	if err != nil {
		t.Fatal(err)
	}
	if b.Complete || b.Coverage[0].Status != "unsupported" {
		t.Errorf("coverage = %+v complete=%v", b.Coverage, b.Complete)
	}
}
