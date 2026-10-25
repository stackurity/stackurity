package packs

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stackurity/stackurity/pkg/pack"
)

func TestRemotePacksLoadOnlyWhenNeeded(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keys := &Keyring{}
	keys.Add("acme", base64.StdEncoding.EncodeToString(pub), false)
	m := manifest("java")
	m.Files = []string{"*.jar", "pom.xml"}
	m.MaxMemoryMB = 384
	a := archive(t, "java", m)
	Sign(a, priv)
	data, _ := a.Bytes()

	var downloads atomic.Int32
	serveSHA := a.SHA256()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/packs":
			json.NewEncoder(w).Encode(map[string]any{"installed": []map[string]any{
				{"id": "java", "enabled": true, "sha256": serveSHA, "files": m.Files}}})
		case "/api/v1/packs/java/archive":
			downloads.Add(1)
			w.Write(data)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	get := func(ctx context.Context, path string, w io.Writer) error {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		_, err = io.Copy(w, resp.Body)
		return err
	}
	r := &Remote{Get: get, Keys: keys}
	exts, err := r.Extensions(context.Background())
	if err != nil || len(exts) != 1 || !exts[0].Matches("shop.jar") || exts[0].Matches("package.json") {
		t.Fatalf("extensions: %v %v", exts, err)
	}
	if downloads.Load() != 0 {
		t.Fatal("a pack was downloaded before any file needed it")
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("META-INF/maven/org.yaml/snakeyaml/pom.properties")
	w.Write([]byte("groupId=org.yaml\nartifactId=snakeyaml\nversion=1.33\n"))
	zw.Close()
	files := []pack.File{{Path: "lib/snakeyaml.jar", Content: buf.Bytes()}}
	for i := 0; i < 2; i++ {
		obs, _, err := exts[0].Scan(context.Background(), files)
		if err != nil || len(obs) != 1 || obs[0].Purl != "pkg:maven/org.yaml/snakeyaml@1.33" {
			t.Fatalf("scan %d: %+v %v", i, obs, err)
		}
	}
	if downloads.Load() != 1 {
		t.Errorf("downloads: %d (want one, reused)", downloads.Load())
	}
	r.Close(context.Background())

	// A download that is not the pack the server listed is refused.
	serveSHA = strings.Repeat("0", 64)
	r2 := &Remote{Get: get, Keys: keys}
	exts, _ = r2.Extensions(context.Background())
	if _, _, err := exts[0].Scan(context.Background(), files); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("mismatched download: %v", err)
	}
}
