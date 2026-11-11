package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"testing"
)

// taggedArchive is docker save's archive for one image with its tags and
// working directory in the archive itself, and the image ID Docker gives
// it (the config's digest).
func taggedArchive(tags []string, workdir string, layers ...[]byte) ([]byte, string) {
	cfg, _ := json.Marshal(map[string]any{"architecture": "amd64", "os": "linux", "config": map[string]any{"WorkingDir": workdir}})
	sum := sha256.Sum256(cfg)
	id := "sha256:" + hex.EncodeToString(sum[:])
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	put := func(name string, b []byte) {
		tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(b))})
		tw.Write(b)
	}
	var names []string
	for i, l := range layers {
		names = append(names, fmt.Sprintf("%064d/layer.tar", i))
		put(names[i], l)
	}
	put(id[7:]+".json", cfg)
	m, _ := json.Marshal([]map[string]any{{"Config": id[7:] + ".json", "RepoTags": tags, "Layers": names}})
	put("manifest.json", m)
	tw.Close()
	return buf.Bytes(), id
}

// The same image read from its archive on a host and through the running
// containers of that host is the same asset with the same contents: only
// what the Docker engine adds (containers, repo digest) and the source
// differ.
func TestArchiveMatchesRunningImage(t *testing.T) {
	arch, id := taggedArchive([]string{"api:2", "api:latest"}, "/usr/src/app", debianLayers()...)
	d := startDocker(t)
	d.mu.Lock()
	d.images[id] = &fakeImage{archive: arch, info: Image{ID: id, RepoTags: []string{"api:2", "api:latest"}, Size: int64(len(arch)),
		Os: "linux", Architecture: "amd64", Config: &struct {
			WorkingDir string `json:"WorkingDir"`
		}{"/usr/src/app"}}}
	d.mu.Unlock()
	d.run(Container{ID: "c1", Names: []string{"/api"}, Image: "api:latest", ImageID: id, State: "running"})
	running := newScanner(t, d.socket).Collect(context.Background(), hostRef)[1]

	got, err := ReadArchive(context.Background(), bytes.NewReader(arch), ArchiveOptions{Version: "test", WorkDir: t.TempDir(),
		Ref: "api:latest", Host: &hostRef})
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if got.Asset.Name != running.Asset.Name || !slices.Equal(got.Asset.Identifiers, running.Asset.Identifiers) ||
		got.Collector != running.Collector || len(got.Relations) != 1 || !slices.Equal(got.Relations[0].To, running.Relations[0].To) {
		t.Errorf("archive asset %+v, running %+v", got.Asset, running.Asset)
	}
	if !slices.Equal(purls(got), purls(running)) || got.Complete != running.Complete || len(got.Coverage) != len(running.Coverage) {
		t.Errorf("archive %v %+v, running %v %+v", purls(got), got.Coverage, purls(running), running.Coverage)
	}
	want := maps.Clone(running.Asset.Attributes)
	delete(want, "containers")
	want["source"] = "archive"
	if !maps.Equal(got.Asset.Attributes, want) {
		t.Errorf("attributes %v, want %v", got.Asset.Attributes, want)
	}
}
