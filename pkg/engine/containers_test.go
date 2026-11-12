package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// RunningContainersWith reads each running image from the archive Export
// supplies, not from the engine's export, and names it as RunningContainers
// does (stackurity-scan saves the archive once for its layer key scan too).
func TestRunningContainersWithExport(t *testing.T) {
	cfg := imageConfig("amd64", "")
	archive := saveArchive([]string{"shop:1.0"}, cfg, alpineLayers()...)
	id := digestOf(cfg)

	// Unix socket paths are short (104 bytes on macOS): not t.TempDir().
	dir, err := os.MkdirTemp("/tmp", "stkeng")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	engineExports := 0
	mux := http.NewServeMux()
	mux.HandleFunc("GET /containers/json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{{"Id": "c1", "Names": []string{"/shop"}, "Image": "shop:1.0", "ImageID": id, "State": "running"}})
	})
	mux.HandleFunc("GET /images/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"Id": id, "RepoTags": []string{"shop:1.0"}, "Size": len(archive), "Os": "linux", "Architecture": "amd64"})
	})
	mux.HandleFunc("GET /images/{id}/get", func(w http.ResponseWriter, r *http.Request) {
		engineExports++
		http.Error(w, `{"message":"not this way"}`, http.StatusInternalServerError)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	var asked []string
	bs := RunningContainersWith(context.Background(), "test", ContainerOptions{
		Socket: sock,
		Export: func(ctx context.Context, imageID string) (io.ReadCloser, error) {
			asked = append(asked, imageID)
			return io.NopCloser(bytes.NewReader(archive)), nil
		},
	})
	if len(bs) != 2 {
		t.Fatalf("%d batches, want host + 1 image", len(bs))
	}
	if engineExports != 0 || !slices.Equal(asked, []string{id}) {
		t.Errorf("engine exports %d, Export asked %v", engineExports, asked)
	}
	b := bs[1]
	host, _ := os.Hostname()
	if b.Asset.Kind != "image" || b.Asset.Name != "shop:1.0 on "+host || !b.Complete ||
		b.Asset.Attributes["image_id"] != id || b.Asset.Attributes["containers"] != "shop" {
		t.Errorf("image batch = %+v", b.Asset)
	}
	if want := []string{"pkg:apk/alpine/busybox@1.36.1-r29", "pkg:apk/alpine/musl@1.2.5-r0", "pkg:generic/alpine@3.20.3", "pkg:npm/lodash@4.17.20"}; !slices.Equal(purlsOf(b), want) {
		t.Errorf("packages = %v", purlsOf(b))
	}

	// Without Export the engine's export is used, as by RunningContainers.
	bs = RunningContainers(context.Background(), sock, "test")
	if engineExports != 1 || len(bs) != 2 || coverageOf(bs[1], "image:shop:1.0").Status != "failed" {
		t.Errorf("RunningContainers: engine exports %d, batches %d", engineExports, len(bs))
	}
}
