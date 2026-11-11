package docker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
)

// --- a fake Docker daemon on a Unix socket, serving the Engine API paths
// the agent uses, with image archives built here in docker save's format.

type fakeImage struct {
	info    Image
	archive []byte
}

type fakeDocker struct {
	mu         sync.Mutex
	containers []Container
	images     map[string]*fakeImage
	exports    map[string]int
	socket     string
}

func startDocker(t *testing.T) *fakeDocker {
	t.Helper()
	// Unix socket paths are short (104 bytes on macOS): not t.TempDir().
	dir, err := os.MkdirTemp("/tmp", "stkdk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fakeDocker{images: map[string]*fakeImage{}, exports: map[string]int{}, socket: filepath.Join(dir, "docker.sock")}
	ln, err := net.Listen("unix", f.socket)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /containers/json", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		json.NewEncoder(w).Encode(f.containers)
	})
	mux.HandleFunc("GET /images/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		im := f.images[r.PathValue("id")]
		if im == nil {
			http.Error(w, `{"message":"No such image"}`, 404)
			return
		}
		json.NewEncoder(w).Encode(im.info)
	})
	mux.HandleFunc("GET /images/{id}/get", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		im := f.images[r.PathValue("id")]
		f.exports[r.PathValue("id")]++
		f.mu.Unlock()
		if im == nil {
			http.Error(w, `{"message":"No such image"}`, 404)
			return
		}
		w.Header().Set("Content-Type", "application/x-tar")
		w.Write(im.archive)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return f
}

func (f *fakeDocker) add(id string, tags []string, workdir string, layers ...[]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	arch := saveArchive(id, layers...)
	info := Image{ID: id, RepoTags: tags, Size: int64(len(arch)), Os: "linux", Architecture: "amd64"}
	if workdir != "" {
		info.Config = &ImageConfig{WorkingDir: workdir}
	}
	for _, tg := range tags {
		name, _, _ := strings.Cut(tg, ":")
		info.RepoDigests = append(info.RepoDigests, name+"@sha256:"+strings.Repeat("d", 64))
	}
	f.images[id] = &fakeImage{info: info, archive: arch}
}

func (f *fakeDocker) run(cs ...Container) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.containers = cs
}

func (f *fakeDocker) exported(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.exports[id]
}

type entry struct {
	name, body, link string
	typ              byte
	mode             int64
}

func file(name, body string) entry { return entry{name: name, body: body, typ: tar.TypeReg} }
func exe(name, body string) entry {
	return entry{name: name, body: body, typ: tar.TypeReg, mode: 0o755}
}
func link(name, target string) entry { return entry{name: name, link: target, typ: tar.TypeSymlink} }

func layerTar(entries ...entry) []byte {
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
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: mode, Linkname: e.link, Size: int64(len(e.body))}
		if e.typ != tar.TypeReg {
			h.Size = 0
		}
		tw.WriteHeader(h)
		if e.typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	return buf.Bytes()
}

// saveArchive builds what docker save writes for one image (the layout
// before Docker 25: <n>/layer.tar, the config and manifest.json).
func saveArchive(id string, layers ...[]byte) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	put := func(name string, b []byte) {
		tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(b))})
		tw.Write(b)
	}
	var names []string
	// Layers in reverse order: an archive need not list them bottom first.
	for i := len(layers) - 1; i >= 0; i-- {
		name := fmt.Sprintf("%064d/layer.tar", i)
		put(name, layers[i])
	}
	for i := range layers {
		names = append(names, fmt.Sprintf("%064d/layer.tar", i))
	}
	cfg := strings.TrimPrefix(id, "sha256:") + ".json"
	put(cfg, []byte(`{"architecture":"amd64","os":"linux"}`))
	m, _ := json.Marshal([]map[string]any{{"Config": cfg, "RepoTags": nil, "Layers": names}})
	put("manifest.json", m)
	tw.Close()
	return buf.Bytes()
}

const apkDB = `C:Q1abc=
P:musl
V:1.2.5-r0
A:x86_64
o:musl

C:Q1def=
P:busybox
V:1.36.1-r29
A:x86_64
o:busybox

`

const dpkgStatus = `Package: libssl3
Status: install ok installed
Architecture: amd64
Source: openssl
Version: 3.0.11-1~deb12u2

Package: curl
Status: install ok installed
Architecture: amd64
Version: 7.88.1-10+deb12u5

`

func lockfile(dep, version string) string {
	return fmt.Sprintf(`{"name":"shop","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"shop","version":"1.0.0","dependencies":{%q:%q}},"node_modules/%s":{"version":%q}}}`,
		dep, version, dep, version)
}

// An alpine image with an application in /app, in two layers.
func alpineLayers() [][]byte {
	return [][]byte{
		layerTar(file("etc/os-release", "ID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=\"Alpine Linux v3.20\"\n"),
			file("lib/apk/db/installed", apkDB)),
		layerTar(file("app/package.json", `{"name":"shop","version":"1.0.0","dependencies":{"lodash":"4.17.20"}}`),
			file("app/package-lock.json", lockfile("lodash", "4.17.20"))),
	}
}

// A Debian image whose application lives in its working directory, with
// os-release as a link (as Debian ships it) and a file a later layer
// removes.
func debianLayers() [][]byte {
	return [][]byte{
		layerTar(file("usr/lib/os-release", "ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"),
			link("etc/os-release", "../usr/lib/os-release"),
			file("var/lib/dpkg/status", dpkgStatus),
			file("usr/src/app/old.txt", "x")),
		layerTar(file("usr/src/app/package.json", `{"name":"api","version":"2.0.0","dependencies":{"express":"4.17.1"}}`),
			file("usr/src/app/package-lock.json", lockfile("express", "4.17.1")),
			file("usr/src/app/.wh.old.txt", "")),
	}
}

const (
	idShop  = "sha256:aaaa000000000000000000000000000000000000000000000000000000000001"
	idAPI   = "sha256:bbbb000000000000000000000000000000000000000000000000000000000002"
	idOther = "sha256:cccc000000000000000000000000000000000000000000000000000000000003"
)

var hostRef = model.AssetRef{Kind: model.AssetHost, Name: "web-1",
	Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "m1"}, {Scheme: "hostname", Value: "web-1"}}}

func purls(b *model.ObservationBatch) []string {
	var out []string
	for _, o := range b.Observations {
		p, _, _ := strings.Cut(o.Purl, "?")
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

func byIdentity(bs []*model.ObservationBatch) map[string]*model.ObservationBatch {
	out := map[string]*model.ObservationBatch{}
	for _, b := range bs[1:] {
		out[b.Asset.Identifiers[0].Value] = b
	}
	return out
}

func coverage(b *model.ObservationBatch, scope string) model.CoverageItem {
	for _, c := range b.Coverage {
		if c.Scope == scope {
			return c
		}
	}
	return model.CoverageItem{}
}

func newScanner(t *testing.T, socket string) *Scanner {
	return &Scanner{Engine: NewEngine(socket), Version: "test", WorkDir: t.TempDir()}
}

// Two containers on one image read it once; an untagged image (a local
// build whose tag moved on) is named by its short ID and identified by its
// image ID; the real collectors read the OS packages and the applications.
func TestCollectRunningImages(t *testing.T) {
	d := startDocker(t)
	d.add(idShop, []string{"shop:1.0", "shop:latest"}, "", alpineLayers()...)
	d.add(idAPI, nil, "/usr/src/app", debianLayers()...)
	d.run(
		Container{ID: "c1", Names: []string{"/shop-1"}, Image: "shop:1.0", ImageID: idShop, State: "running"},
		Container{ID: "c2", Names: []string{"/shop-2"}, Image: "shop:1.0", ImageID: idShop, State: "running"},
		Container{ID: "c3", Names: []string{"/api"}, Image: idAPI, ImageID: idAPI, State: "running"},
	)
	s := newScanner(t, d.socket)
	bs := s.Collect(context.Background(), hostRef)
	for _, b := range bs {
		if err := b.Validate(); err != nil {
			t.Fatalf("%s: %v", b.Asset.Name, err)
		}
	}
	if len(bs) != 3 {
		t.Fatalf("%d batches, want host + 2 images", len(bs))
	}
	host := bs[0]
	if host.Asset.Kind != model.AssetHost || host.Collector.ID != CollectorID || coverage(host, "docker").Status != "checked" || !host.Complete {
		t.Errorf("host batch = %+v", host)
	}
	if host.Images == nil || !slices.Equal(host.Images.Refs, []string{"shop:1.0", idAPI}) {
		t.Errorf("image list = %+v", host.Images)
	}
	if n := d.exported(idShop); n != 1 {
		t.Errorf("shared image exported %d times", n)
	}
	got := byIdentity(bs)
	shop := got["shop:1.0"]
	if shop == nil || shop.Asset.Name != "shop:1.0 on web-1" || shop.Asset.Kind != model.AssetImage {
		t.Fatalf("shop image = %+v", shop)
	}
	if !slices.Equal(purls(shop), []string{"pkg:apk/alpine/busybox@1.36.1-r29", "pkg:apk/alpine/musl@1.2.5-r0", "pkg:generic/alpine@3.20.3", "pkg:npm/lodash@4.17.20"}) {
		t.Errorf("shop packages = %v", purls(shop))
	}
	if a := shop.Asset.Attributes; a["image_id"] != idShop || a["containers"] != "shop-1, shop-2" || a["os"] != "alpine" ||
		a["digest"] != "sha256:"+strings.Repeat("d", 64) || a["platform"] != "linux/amd64" {
		t.Errorf("shop attributes = %v", a)
	}
	if len(shop.Relations) != 1 || shop.Relations[0].Kind != "runs_on" || !slices.Equal(shop.Relations[0].To, hostRef.Identifiers) {
		t.Errorf("relations = %+v", shop.Relations)
	}
	if !shop.Complete || coverage(shop, "image:shop:1.0").Status != "checked" {
		t.Errorf("shop coverage = %+v complete=%v", shop.Coverage, shop.Complete)
	}
	api := got[idAPI]
	if api == nil || api.Asset.Name != "bbbb00000000 on web-1" {
		t.Fatalf("untagged image = %+v", api)
	}
	if !slices.Equal(purls(api), []string{"pkg:deb/debian/curl@7.88.1-10%2Bdeb12u5", "pkg:deb/debian/libssl3@3.0.11-1~deb12u2", "pkg:generic/debian@12", "pkg:npm/express@4.17.1"}) {
		t.Errorf("api packages = %v", purls(api))
	}

	// The next collection reuses both readings: nothing is exported.
	bs = s.Collect(context.Background(), hostRef)
	if len(bs) != 3 || d.exported(idShop) != 1 || d.exported(idAPI) != 1 {
		t.Errorf("second collection exported again: shop %d, api %d", d.exported(idShop), d.exported(idAPI))
	}
	if !slices.Equal(purls(byIdentity(bs)["shop:1.0"]), purls(shop)) {
		t.Error("cached reading differs")
	}
	// After the rescan interval it is read again.
	s.Now = func() time.Time { return time.Now().Add(DefaultRescan + time.Hour) }
	s.Collect(context.Background(), hostRef)
	if d.exported(idShop) != 2 {
		t.Errorf("not read again after the rescan interval: %d", d.exported(idShop))
	}
}

// An image no container runs any more drops out of the host's list (the
// server then marks it removed) and out of the cache; a rebuilt image under
// the same tag keeps its identity and is read again.
func TestVanishedAndRebuiltImages(t *testing.T) {
	d := startDocker(t)
	d.add(idShop, []string{"shop:1.0"}, "", alpineLayers()...)
	d.add(idAPI, []string{"api:2"}, "/usr/src/app", debianLayers()...)
	d.run(Container{ID: "c1", Image: "shop:1.0", ImageID: idShop, State: "running"},
		Container{ID: "c2", Image: "api:2", ImageID: idAPI, State: "running"})
	s := newScanner(t, d.socket)
	s.Collect(context.Background(), hostRef)

	d.run(Container{ID: "c2", Image: "api:2", ImageID: idAPI, State: "running"},
		Container{ID: "c9", Image: "old", ImageID: idShop, State: "exited"})
	bs := s.Collect(context.Background(), hostRef)
	if len(bs) != 2 || !slices.Equal(bs[0].Images.Refs, []string{"api:2"}) {
		t.Fatalf("after shop stopped: %d batches, list %+v", len(bs), bs[0].Images)
	}
	if _, ok := s.cache[idShop]; ok {
		t.Error("the stopped image's reading is still cached")
	}

	// shop:1.0 rebuilt: a new image ID under the same tag.
	d.add(idOther, []string{"shop:1.0"}, "", layerTar(file("etc/os-release", "ID=alpine\nVERSION_ID=3.21.0\n"), file("lib/apk/db/installed", apkDB)))
	d.run(Container{ID: "c3", Image: "shop:1.0", ImageID: idOther, State: "running"})
	bs = s.Collect(context.Background(), hostRef)
	b := byIdentity(bs)["shop:1.0"]
	if b == nil || b.Asset.Attributes["image_id"] != idOther || d.exported(idOther) != 1 {
		t.Fatalf("rebuilt image = %+v", b)
	}
	if !slices.Contains(purls(b), "pkg:generic/alpine@3.21.0") {
		t.Errorf("rebuilt image packages = %v", purls(b))
	}
}

// Docker absent, or a socket the agent may not use: a coverage item on the
// host saying so, and no image list (so nothing is taken as removed).
func TestDockerUnreadable(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "stkdk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	bs := newScanner(t, filepath.Join(dir, "missing.sock")).Collect(context.Background(), hostRef)
	if len(bs) != 1 || bs[0].Images != nil || coverage(bs[0], "docker").Status != "skipped" ||
		!strings.Contains(coverage(bs[0], "docker").Reason, "docker is not running") {
		t.Errorf("no socket: %+v", bs[0])
	}
	if err := bs[0].Validate(); err != nil {
		t.Error(err)
	}

	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permissions do not apply")
	}
	d := startDocker(t)
	d.run(Container{ID: "c1", Image: "x", ImageID: idShop, State: "running"})
	if err := os.Chmod(d.socket, 0o000); err != nil {
		t.Fatal(err)
	}
	bs = newScanner(t, d.socket).Collect(context.Background(), hostRef)
	c := coverage(bs[0], "docker")
	if len(bs) != 1 || bs[0].Images != nil || bs[0].Complete || c.Status != "failed" ||
		!strings.Contains(c.Reason, "permission denied on the Docker socket") || !strings.Contains(c.Reason, "docs/install.md") {
		t.Errorf("unreadable socket: %+v", bs[0])
	}
}

// An image over the size limit is reported, skipped with the reason, never
// exported; one whose files turn out larger than the limit while it is read
// is stopped. Neither is shown as having no packages and complete.
func TestOversizeImage(t *testing.T) {
	d := startDocker(t)
	d.add(idShop, []string{"big:1"}, "", alpineLayers()...)
	d.add(idAPI, []string{"liar:1"}, "", layerTar(file("etc/os-release", "ID=alpine\nVERSION_ID=3.20.3\n"),
		file("blob.bin", strings.Repeat("x", 64<<10))))
	d.mu.Lock()
	d.images[idShop].info.Size = 10 << 30
	d.images[idAPI].info.Size = 1 << 10 // understated
	d.mu.Unlock()
	d.run(Container{ID: "c1", Image: "big:1", ImageID: idShop, State: "running"},
		Container{ID: "c2", Image: "liar:1", ImageID: idAPI, State: "running"})
	s := newScanner(t, d.socket)
	s.MaxImageBytes = 32 << 10
	bs := s.Collect(context.Background(), hostRef)
	got := byIdentity(bs)
	big := got["big:1"]
	if big == nil || big.Complete || len(big.Observations) != 0 || coverage(big, "image:big:1").Status != "skipped" ||
		!strings.Contains(coverage(big, "image:big:1").Reason, "10 GiB unpacked, above the") {
		t.Errorf("oversize image = %+v", big)
	}
	if d.exported(idShop) != 0 {
		t.Error("oversize image was exported")
	}
	liar := got["liar:1"]
	if liar == nil || liar.Complete || coverage(liar, "image:liar:1").Status != "skipped" ||
		!strings.Contains(coverage(liar, "image:liar:1").Reason, "larger than") {
		t.Errorf("image larger than reported = %+v", liar)
	}
	// Both are still on the host's list: they run, they were not read.
	if !slices.Equal(bs[0].Images.Refs, []string{"big:1", "liar:1"}) {
		t.Errorf("list = %+v", bs[0].Images)
	}
	for _, b := range bs {
		if err := b.Validate(); err != nil {
			t.Error(err)
		}
	}
	// Nothing is left in the work directory.
	if ents, _ := os.ReadDir(s.WorkDir); len(ents) != 0 {
		t.Errorf("work directory not cleaned: %v", ents)
	}
}

// A hostile image cannot lead extraction or the collectors outside its
// root: names with "..", absolute names, writes through a link, and links
// pointing at the host's files or climbing out with "..".
func TestHostileImage(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	os.WriteFile(secret, []byte("host secret"), 0o600)
	work := t.TempDir()
	layers := [][]byte{
		layerTar(file("etc/os-release", "ID=alpine\nVERSION_ID=3.20.3\n"),
			link("escape", outside),
			link("up", strings.Repeat("../", 40)+outside),
			link("hostfile", secret),
			link("lib", "usr/lib"),
			link("loop", "loop2"), link("loop2", "loop"),
			link("rel", "x/.."),
			link("x", "../.."),
		),
		layerTar(file("escape/planted", "x"), file("usr/lib/ok", "fine")),
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range []string{"../evil", "/abs-evil"} {
		tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
		tw.Write([]byte("x"))
	}
	tw.Close()
	layers = append(layers, buf.Bytes())

	root, err := extractImage(context.Background(), bytes.NewReader(saveArchive(idShop, layers...)), work, 1<<20, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "planted")); err == nil {
		t.Error("a file was written through a link to outside the root")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(work), "evil")); err == nil {
		t.Error("a .. name was written")
	}
	realRoot, _ := filepath.EvalSymlinks(root)
	for _, name := range []string{"escape", "up", "hostfile", "rel", "x", "lib/ok"} {
		p, err := filepath.EvalSymlinks(filepath.Join(root, name))
		if err != nil {
			continue // dangling inside the root is fine
		}
		if p != realRoot && !strings.HasPrefix(p, realRoot+string(filepath.Separator)) {
			t.Errorf("%s resolves outside the root: %s", name, p)
		}
	}
	for _, p := range []string{"hostfile", "up/secret"} {
		if b, err := os.ReadFile(filepath.Join(root, p)); err == nil {
			t.Errorf("read the host's file through the image's %s: %q", p, b)
		}
	}
	if b, err := os.ReadFile(filepath.Join(root, "lib", "ok")); err != nil || string(b) != "fine" {
		t.Errorf("a link inside the image no longer works: %q %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "loop")); err == nil {
		t.Error("a link loop was kept")
	}
}

// A later layer's whiteout removes a lower layer's file, and an opaque
// directory hides the lower layer's contents.
func TestLayerWhiteouts(t *testing.T) {
	layers := [][]byte{
		layerTar(file("a/keep", "1"), file("a/gone", "1"), file("b/old", "1")),
		layerTar(file("a/.wh.gone", ""), file("b/.wh..wh..opq", ""), file("b/new", "2")),
	}
	root, err := extractImage(context.Background(), bytes.NewReader(saveArchive(idShop, layers...)), t.TempDir(), 1<<20, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{"a/keep": true, "a/gone": false, "b/old": false, "b/new": true, "a/.wh.gone": false, "b/.wh..wh..opq": false} {
		_, err := os.Lstat(filepath.Join(root, p))
		if (err == nil) != want {
			t.Errorf("%s present = %v, want %v", p, err == nil, want)
		}
	}
}

// Within a layer the last entry at a path wins, and nothing is created
// through a link of the same layer, whatever the order of the entries.
func TestLayerLinkOrder(t *testing.T) {
	layers := [][]byte{layerTar(
		link("x", "/etc"), file("x", "now a file"), // a file after a link replaces it
		file("y", "a file"), link("y", "/etc/os-release"), // a link after a file replaces it
		link("d", "/"), link("d/through", "/etc"), file("d/inside", "1"), // nothing through the link d
	)}
	root, err := extractImage(context.Background(), bytes.NewReader(saveArchive(idShop, layers...)), t.TempDir(), 1<<20, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	isLink := func(p string) bool {
		fi, err := os.Lstat(filepath.Join(root, p))
		return err == nil && fi.Mode()&os.ModeSymlink != 0
	}
	if b, err := os.ReadFile(filepath.Join(root, "x")); err != nil || isLink("x") || string(b) != "now a file" {
		t.Errorf("x: %q %v link=%v", b, err, isLink("x"))
	}
	if !isLink("y") {
		t.Error("y is not a link")
	}
	if !isLink("d") {
		t.Error("d is not a link")
	}
	for _, p := range []string{"through", "inside"} {
		if _, err := os.Lstat(filepath.Join(root, p)); err == nil {
			t.Errorf("%s was created through the link d", p)
		}
	}
}

// Docker 25 and the containerd image store write an OCI layout: blobs by
// digest (layers possibly gzip-compressed) and index.json, with no
// manifest.json; a multi-platform index picks the image's architecture.
func TestOCIArchive(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(layerTar(file("etc/os-release", "ID=alpine\nVERSION_ID=3.20.3\n"), file("lib/apk/db/installed", apkDB)))
	zw.Close()
	blobs := map[string][]byte{}
	digest := func(b []byte) string {
		h := sha256.Sum256(b)
		d := "sha256:" + hex.EncodeToString(h[:])
		blobs[d] = b
		return d
	}
	l1 := digest(gz.Bytes())
	l2 := digest(layerTar(file("app/package.json", `{"name":"shop","dependencies":{"lodash":"4.17.20"}}`),
		file("app/package-lock.json", lockfile("lodash", "4.17.20"))))
	wrong := digest(layerTar(file("etc/os-release", "ID=debian\nVERSION_ID=12\n")))
	mf := func(layers ...string) string {
		var ls []map[string]string
		for _, l := range layers {
			ls = append(ls, map[string]string{"digest": l})
		}
		b, _ := json.Marshal(map[string]any{"schemaVersion": 2, "layers": ls})
		return digest(b)
	}
	amd, arm := mf(l1, l2), mf(wrong)
	idx, _ := json.Marshal(map[string]any{"manifests": []map[string]any{
		{"digest": arm, "platform": map[string]string{"architecture": "arm64", "os": "linux"}},
		{"digest": amd, "platform": map[string]string{"architecture": "amd64", "os": "linux"}},
	}})
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	put := func(name string, b []byte) {
		tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(b))})
		tw.Write(b)
	}
	put("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))
	for d, b := range blobs {
		put(blobPath(d), b)
	}
	put("index.json", idx)
	tw.Close()

	root, err := extractImage(context.Background(), &buf, t.TempDir(), 1<<20, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	r := ReadRoot(context.Background(), root, &Image{}, "test")
	var got []string
	for _, o := range r.Observations {
		p, _, _ := strings.Cut(o.Purl, "?")
		got = append(got, p)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"pkg:apk/alpine/busybox@1.36.1-r29", "pkg:apk/alpine/musl@1.2.5-r0", "pkg:generic/alpine@3.20.3", "pkg:npm/lodash@4.17.20"}) {
		t.Errorf("packages = %v", got)
	}
}

// A scratch image (one static binary, no os-release) is not shown as an
// empty, complete image: its missing package database is coverage.
func TestScratchImage(t *testing.T) {
	root, err := extractImage(context.Background(), bytes.NewReader(saveArchive(idShop, layerTar(file("cloudflared", "\x7fELF")))), t.TempDir(), 1<<20, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	r := ReadRoot(context.Background(), root, &Image{}, "test")
	found := false
	for _, c := range r.Coverage {
		found = found || (c.Scope == "os-packages" && c.Status == "unsupported")
	}
	if !found {
		t.Errorf("coverage = %+v", r.Coverage)
	}
}
