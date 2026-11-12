package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	if a := b.Asset.Attributes; a["cloud_provider"] != "digitalocean" || a["cloud_service"] != "Droplet" {
		t.Errorf("cloud attributes = %v", a)
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

// dpkg writes "Source: name (version)" when the source version differs
// from the binary's, and "Source: name" (or nothing) when it does not.
func TestParseDpkgStatusSourceVersion(t *testing.T) {
	const status = `Package: telnet
Status: install ok installed
Architecture: amd64
Source: inetutils (2:2.5-3ubuntu4.2)
Version: 0.17+2.5-3ubuntu4.2

Package: inetutils-telnet
Status: install ok installed
Architecture: amd64
Source: inetutils
Version: 2:2.5-3ubuntu4.2

Package: curl
Status: install ok installed
Architecture: amd64
Version: 8.5.0-2ubuntu10.6
`
	obs, err := parseDpkgStatus(strings.NewReader(status), "ubuntu", "ubuntu-24.04")
	if err != nil || len(obs) != 3 {
		t.Fatalf("%d observations, %v", len(obs), err)
	}
	for i, w := range []struct{ version, pkg, srcVersion string }{
		{"0.17+2.5-3ubuntu4.2", "inetutils", "2:2.5-3ubuntu4.2"},
		{"2:2.5-3ubuntu4.2", "inetutils", ""},
		{"8.5.0-2ubuntu10.6", "", ""},
	} {
		o := obs[i]
		if o.Version != w.version || o.Evidence["source_package"] != w.pkg || o.Evidence["source_version"] != w.srcVersion {
			t.Errorf("%d: %+v", i, o)
		}
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
		return []byte("openssl-libs\t1\t3.0.7\t24.el9\tx86_64\topenssl-3.0.7-24.el9.src.rpm\tRSA/SHA256, Wed May  1 06:03:07 2024, Key ID 702d426d350d275d\n" +
			"gpg-pubkey\t0\tabc\tdef\t(none)\t(none)\t(none)\n" +
			"tree\t0\t1.7.0\t15.el8\tx86_64\ttree-1.7.0-15.el8.src.rpm\t(none)\n" + // unsigned (a local build)
			"bash\t0\t5.1.8\t9.el9\tx86_64\tbash-5.1.8-9.el9.src.rpm\n"), nil // no signature field: the plain format
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
	if o.Evidence["signing_key"] != "702d426d350d275d" {
		t.Errorf("openssl-libs signing key = %q", o.Evidence["signing_key"])
	}
	if o := obs["pkg:rpm/rocky/tree@1.7.0-15.el8?arch=x86_64&distro=rocky-9.3"]; o.Evidence["signing_key"] != "none" {
		t.Errorf("unsigned tree: %+v", o)
	}
	if o, ok := obs["pkg:rpm/rocky/bash@5.1.8-9.el9?arch=x86_64&distro=rocky-9.3"]; !ok || o.Evidence["signing_key"] != "" {
		t.Errorf("bash without a signature field: %+v", o)
	}
	if len(obs) != 4 {
		t.Errorf("gpg-pubkey must be skipped: %v", obs)
	}
}

func TestRPMSigningKey(t *testing.T) {
	for in, want := range map[string]string{
		"RSA/SHA256, Tue Aug 26 11:11:40 2025, Key ID 82562ea9ad986da3": "82562ea9ad986da3", // EL8
		"RSA/SHA256, Wed May  1 06:03:07 2024, Key ID BC4D06A08D8B756F": "bc4d06a08d8b756f",
		"DSA/SHA1, Mon Jan  1 00:00:00 2012, Key ID 66ced3de1e5e0159":   "66ced3de1e5e0159", // a DSA key of an old release
		"(none)": "none",
		"RSA/SHA256, Tue Aug 26 11:11:40 2025, Key fingerprint: 99db70fae1d7ce227fb6488205b555b38483c65d": "05b555b38483c65d", // v4 fingerprint
		"":                         "",
		"RSA/SHA256, Key ID oops":  "",
		"something rpm says later": "",
	} {
		if got := rpmSigningKey(in); got != want {
			t.Errorf("rpmSigningKey(%q) = %q, want %q", in, got, want)
		}
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

// dnfRoot is an rpm host root with the given /etc/dnf/modules.d files (nil:
// no such directory).
func dnfRoot(t *testing.T, modules map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range map[string]string{
		"etc/os-release":           "ID=\"ol\"\nVERSION_ID=\"8.10\"\n",
		"var/lib/rpm/rpmdb.sqlite": "",
	} {
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if modules != nil {
		dir := filepath.Join(root, "etc/dnf/modules.d")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range modules {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

func TestDNFModules(t *testing.T) {
	collect := func(modules map[string]string) (string, bool) {
		t.Helper()
		c := fixture(dnfRoot(t, modules))
		c.LookPath = func(string) (string, error) { return "/usr/bin/rpm", nil }
		c.RunRPM = func(context.Context, string) ([]byte, error) { return nil, nil }
		b, err := c.Collect(context.Background(), "h", "")
		if err != nil {
			t.Fatal(err)
		}
		v, ok := b.Asset.Attributes[DNFModulesAttribute]
		return v, ok
	}
	// As dnf writes them on Oracle Linux 8: a default stream enabled by
	// installing nodejs, an explicitly enabled one, and a reset module.
	got, ok := collect(map[string]string{
		"container-tools.module": "[container-tools]\nname=container-tools\nstream=ol8\nprofiles=\nstate=enabled\n",
		"nodejs.module":          "[nodejs]\nname=nodejs\nstream=\nprofiles=\nstate=\n",
		"php.module":             "[php]\nname=php\nstream=8.2\nprofiles=common\nstate=enabled\n",
		"perl.module":            "[perl]\nname=perl\nstream=5.32\nprofiles=\nstate=disabled\n",
		"README":                 "not a module file",
	})
	if !ok || got != "container-tools:ol8 php:8.2" {
		t.Errorf("modules = %q, %v", got, ok)
	}
	// The directory with nothing enabled: reported as none, so a stream
	// enabled before is cleared on the server.
	if got, ok := collect(map[string]string{}); !ok || got != "" {
		t.Errorf("no module enabled = %q, %v", got, ok)
	}
	// No dnf module state (EL7, Amazon Linux): not reported.
	if got, ok := collect(nil); ok {
		t.Errorf("without modules.d = %q", got)
	}
}
