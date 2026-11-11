package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// --- image archives built here, in docker save's and the OCI layout's
// formats (as internal/collect/docker's tests build them).

type tarEntry struct{ name, body, link string }

func layerTar(entries ...tarEntry) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	dirs := map[string]bool{}
	for _, e := range entries {
		parts := strings.Split(e.name, "/")
		for i := 1; i < len(parts); i++ {
			d := strings.Join(parts[:i], "/") + "/"
			if !dirs[d] {
				dirs[d] = true
				tw.WriteHeader(&tar.Header{Name: d, Typeflag: tar.TypeDir, Mode: 0o755})
			}
		}
		if e.link != "" {
			tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeSymlink, Linkname: e.link, Mode: 0o777})
			continue
		}
		tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(e.body))})
		tw.Write([]byte(e.body))
	}
	tw.Close()
	return buf.Bytes()
}

type tarWriter struct {
	buf bytes.Buffer
	tw  *tar.Writer
}

func newTar() *tarWriter { w := &tarWriter{}; w.tw = tar.NewWriter(&w.buf); return w }

func (w *tarWriter) put(name string, b []byte) {
	w.tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(b))})
	w.tw.Write(b)
}

func (w *tarWriter) bytes() []byte { w.tw.Close(); return w.buf.Bytes() }

func imageConfig(arch, workdir string) []byte {
	b, _ := json.Marshal(map[string]any{"architecture": arch, "os": "linux", "config": map[string]any{"WorkingDir": workdir}})
	return b
}

func digestOf(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// saveArchive is what docker save writes (the layout before Docker 25):
// layers first, in reverse order, then the config and manifest.json.
func saveArchive(tags []string, cfg []byte, layers ...[]byte) []byte {
	w := newTar()
	var names []string
	for i := len(layers) - 1; i >= 0; i-- {
		w.put(fmt.Sprintf("%064d/layer.tar", i), layers[i])
	}
	for i := range layers {
		names = append(names, fmt.Sprintf("%064d/layer.tar", i))
	}
	cfgName := strings.TrimPrefix(digestOf(cfg), "sha256:") + ".json"
	w.put(cfgName, cfg)
	m, _ := json.Marshal([]map[string]any{{"Config": cfgName, "RepoTags": tags, "Layers": names}})
	w.put("manifest.json", m)
	return w.bytes()
}

const apkDB = "C:Q1abc=\nP:musl\nV:1.2.5-r0\nA:x86_64\no:musl\n\nC:Q1def=\nP:busybox\nV:1.36.1-r29\nA:x86_64\no:busybox\n\n"

const dpkgStatus = "Package: libssl3\nStatus: install ok installed\nArchitecture: amd64\nSource: openssl\nVersion: 3.0.11-1~deb12u2\n\n" +
	"Package: curl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 7.88.1-10+deb12u5\n\n"

func npmLock(dep, version string) string {
	return fmt.Sprintf(`{"name":"shop","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"shop","version":"1.0.0","dependencies":{%q:%q}},"node_modules/%s":{"version":%q}}}`,
		dep, version, dep, version)
}

func alpineLayers() [][]byte {
	return [][]byte{
		layerTar(tarEntry{name: "etc/os-release", body: "ID=alpine\nVERSION_ID=3.20.3\n"}, tarEntry{name: "lib/apk/db/installed", body: apkDB}),
		layerTar(tarEntry{name: "app/package.json", body: `{"name":"shop","version":"1.0.0","dependencies":{"lodash":"4.17.20"}}`},
			tarEntry{name: "app/package-lock.json", body: npmLock("lodash", "4.17.20")}),
	}
}

// A Debian image whose application is in its working directory (not a
// place discovery looks), so finding it shows the config was read.
func debianLayers() [][]byte {
	return [][]byte{
		layerTar(tarEntry{name: "usr/lib/os-release", body: "ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n"},
			tarEntry{name: "etc/os-release", link: "../usr/lib/os-release"},
			tarEntry{name: "var/lib/dpkg/status", body: dpkgStatus}),
		layerTar(tarEntry{name: "opt/odd/place/package.json", body: `{"name":"api","version":"2.0.0","dependencies":{"express":"4.17.1"}}`},
			tarEntry{name: "opt/odd/place/package-lock.json", body: npmLock("express", "4.17.1")}),
	}
}

func purlsOf(b *Batch) []string {
	var out []string
	for _, o := range b.Observations {
		p, _, _ := strings.Cut(o.Purl, "?")
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

func coverageOf(b *Batch, scope string) Coverage {
	for _, c := range b.Coverage {
		if c.Scope == scope {
			return c
		}
	}
	return Coverage{}
}

// A docker save archive is read with no Docker engine: OS packages and the
// application in the image's working directory, named by its tag, with the
// platform from its config. A gzip-compressed archive file reads the same.
func TestImageArchiveDockerSave(t *testing.T) {
	cfg := imageConfig("amd64", "/opt/odd/place")
	arch := saveArchive([]string{"api:2", "api:latest"}, cfg, debianLayers()...)
	work := t.TempDir()
	b, err := ImageArchive(context.Background(), bytes.NewReader(arch), "test", ImageArchiveOptions{WorkDir: work})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []string{"pkg:deb/debian/curl@7.88.1-10%2Bdeb12u5", "pkg:deb/debian/libssl3@3.0.11-1~deb12u2", "pkg:generic/debian@12", "pkg:npm/express@4.17.1"}
	if !slices.Equal(purlsOf(b), want) {
		t.Errorf("packages = %v", purlsOf(b))
	}
	if b.Asset.Kind != "image" || b.Asset.Name != "api:2" || len(b.Asset.Identifiers) != 1 ||
		b.Asset.Identifiers[0] != (Identifier{Scheme: "image-ref", Value: "api:2"}) || len(b.Relations) != 0 {
		t.Errorf("asset = %+v relations %+v", b.Asset, b.Relations)
	}
	if a := b.Asset.Attributes; a["image_id"] != digestOf(cfg) || a["platform"] != "linux/amd64" || a["tags"] != "api:2, api:latest" ||
		a["os"] != "debian" || a["source"] != "archive" {
		t.Errorf("attributes = %v", a)
	}
	if coverageOf(b, "image:api:2").Status != "checked" || coverageOf(b, "lockfile:/opt/odd/place/package-lock.json").Status != "checked" ||
		b.Collector.ID != "linux-docker" {
		t.Errorf("coverage=%+v collector=%+v", b.Coverage, b.Collector)
	}
	if ents, _ := os.ReadDir(work); len(ents) != 0 {
		t.Errorf("work directory not cleaned: %v", ents)
	}

	// A tag the archive carries names it; gzip'd on disk reads the same.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(arch)
	zw.Close()
	p := filepath.Join(t.TempDir(), "api.tar.gz")
	if err := os.WriteFile(p, gz.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	b2, err := ImageArchiveFile(context.Background(), p, "test", ImageArchiveOptions{Tag: "api:latest", WorkDir: work})
	if err != nil {
		t.Fatal(err)
	}
	if b2.Asset.Name != "api:latest" || !slices.Equal(purlsOf(b2), want) {
		t.Errorf("gzip'd archive: %s %v", b2.Asset.Name, purlsOf(b2))
	}

	// On a host: named, identified and linked as RunningContainers does.
	host := &AssetRef{Kind: "host", Name: "web-1", Identifiers: []Identifier{{Scheme: "hostname", Value: "web-1"}}}
	b3, err := ImageArchive(context.Background(), bytes.NewReader(arch), "test", ImageArchiveOptions{Host: host, WorkDir: work})
	if err != nil {
		t.Fatal(err)
	}
	if err := b3.Validate(); err != nil {
		t.Fatal(err)
	}
	if b3.Asset.Name != "api:2 on web-1" || b3.Asset.Identifiers[0] != (Identifier{Scheme: "host-image", Value: "api:2"}) ||
		len(b3.Relations) != 1 || b3.Relations[0].Kind != "runs_on" {
		t.Errorf("on a host: %+v %+v", b3.Asset, b3.Relations)
	}
}

// An OCI layout (Docker 25+, buildx, skopeo): the manifest for the asked
// architecture is read, with its name from the index's annotation in
// Docker's short form; with no name the image is identified by its ID.
func TestImageArchiveOCI(t *testing.T) {
	build := func(named bool) ([]byte, string, string) {
		blobs := map[string][]byte{}
		put := func(b []byte) string { d := digestOf(b); blobs[d] = b; return d }
		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		zw.Write(alpineLayers()[0])
		zw.Close()
		l1, l2 := put(gz.Bytes()), put(alpineLayers()[1])
		armLayer := put(layerTar(tarEntry{name: "etc/os-release", body: "ID=debian\nVERSION_ID=12\n"}, tarEntry{name: "var/lib/dpkg/status", body: dpkgStatus}))
		amdCfg, armCfg := imageConfig("amd64", ""), imageConfig("arm64", "")
		mf := func(cfg []byte, layers ...string) string {
			var ls []map[string]string
			for _, l := range layers {
				ls = append(ls, map[string]string{"digest": l})
			}
			b, _ := json.Marshal(map[string]any{"schemaVersion": 2, "config": map[string]string{"digest": put(cfg)}, "layers": ls})
			return put(b)
		}
		amd, arm := mf(amdCfg, l1, l2), mf(armCfg, armLayer)
		ann := map[string]string{}
		if named {
			ann = map[string]string{"io.containerd.image.name": "docker.io/library/shop:2", "org.opencontainers.image.ref.name": "2"}
		}
		inner, _ := json.Marshal(map[string]any{"manifests": []map[string]any{
			{"digest": arm, "platform": map[string]string{"architecture": "arm64", "os": "linux"}},
			{"digest": amd, "platform": map[string]string{"architecture": "amd64", "os": "linux"}},
		}})
		idx, _ := json.Marshal(map[string]any{"manifests": []map[string]any{{"digest": put(inner), "annotations": ann}}})
		w := newTar()
		w.put("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))
		w.put("index.json", idx)
		for d, b := range blobs {
			alg, h, _ := strings.Cut(d, ":")
			w.put("blobs/"+alg+"/"+h, b)
		}
		return w.bytes(), digestOf(amdCfg), digestOf(armCfg)
	}
	arch, amdID, armID := build(true)
	b, err := ImageArchive(context.Background(), bytes.NewReader(arch), "test", ImageArchiveOptions{Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(purlsOf(b), []string{"pkg:apk/alpine/busybox@1.36.1-r29", "pkg:apk/alpine/musl@1.2.5-r0", "pkg:generic/alpine@3.20.3", "pkg:npm/lodash@4.17.20"}) {
		t.Errorf("amd64 packages = %v", purlsOf(b))
	}
	if b.Asset.Name != "shop:2" || b.Asset.Attributes["image_id"] != amdID || b.Asset.Attributes["platform"] != "linux/amd64" {
		t.Errorf("amd64 asset = %+v", b.Asset)
	}
	b, err = ImageArchive(context.Background(), bytes.NewReader(arch), "test", ImageArchiveOptions{Arch: "arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if b.Asset.Attributes["image_id"] != armID || b.Asset.Attributes["platform"] != "linux/arm64" || !slices.Contains(purlsOf(b), "pkg:deb/debian/curl@7.88.1-10%2Bdeb12u5") {
		t.Errorf("arm64 = %+v %v", b.Asset, purlsOf(b))
	}

	unnamed, amdID, _ := build(false)
	b, err = ImageArchive(context.Background(), bytes.NewReader(unnamed), "test", ImageArchiveOptions{Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	short := strings.TrimPrefix(amdID, "sha256:")[:12]
	if b.Asset.Name != short || b.Asset.Identifiers[0] != (Identifier{Scheme: "image-id", Value: amdID}) {
		t.Errorf("unnamed asset = %+v", b.Asset)
	}
}

// An image whose files pass the limit is reported as skipped, still named
// from the archive (whose manifest comes after the layers), and never as an
// empty, complete image.
func TestImageArchiveOversize(t *testing.T) {
	layers := append(alpineLayers(), layerTar(tarEntry{name: "blob.bin", body: strings.Repeat("x", 64<<10)}))
	work := t.TempDir()
	b, err := ImageArchive(context.Background(), bytes.NewReader(saveArchive([]string{"big:1"}, imageConfig("amd64", ""), layers...)), "test",
		ImageArchiveOptions{MaxImageBytes: 32 << 10, WorkDir: work})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	c := coverageOf(b, "image:big:1")
	if b.Asset.Name != "big:1" || b.Complete || len(b.Observations) != 0 || c.Status != "skipped" || !strings.Contains(c.Reason, "larger than") {
		t.Errorf("oversize image = %+v", b)
	}
	if ents, _ := os.ReadDir(work); len(ents) != 0 {
		t.Errorf("work directory not cleaned: %v", ents)
	}
}

// Input that is not an image archive is a clear error, not an empty image.
func TestImageArchiveNotAnArchive(t *testing.T) {
	plainTar := newTar()
	plainTar.put("readme.txt", []byte("hello"))
	for name, in := range map[string][]byte{
		"text":         []byte(strings.Repeat("not a tar archive\n", 100)),
		"empty":        nil,
		"tar of files": plainTar.bytes(),
		"bad gzip":     {0x1f, 0x8b, 0, 0},
	} {
		_, err := ImageArchive(context.Background(), bytes.NewReader(in), "test", ImageArchiveOptions{WorkDir: t.TempDir()})
		if !errors.Is(err, ErrNotImageArchive) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := ImageArchiveFile(context.Background(), t.TempDir(), "test", ImageArchiveOptions{}); !errors.Is(err, ErrNotImageArchive) {
		t.Errorf("directory: err = %v", err)
	}
	if _, err := ImageArchiveFile(context.Background(), filepath.Join(t.TempDir(), "missing.tar"), "test", ImageArchiveOptions{}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: err = %v", err)
	}
}
