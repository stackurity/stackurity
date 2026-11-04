package lockfile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

func TestManifestNames(t *testing.T) {
	files := map[string]string{
		"package.json":   `{"name": "commmerce-analytics", "version": "1.0.0"}`,
		"composer.json":  `{"name": "Acme/Help-Centre"}`,
		"go.mod":         "// a comment\nmodule github.com/acme/shop\n\ngo 1.22\n",
		"pubspec.yaml":   "name: commmerce_chat\nversion: 1.0.0+1\n",
		"pyproject.toml": "[project]\nname = \"My_Tool.CLI\"\n",
		"Cargo.toml":     "[package]\nname = \"shop-core\"\n",
	}
	read := func(name string) ([]byte, error) {
		if v, ok := files[name]; ok {
			return []byte(v), nil
		}
		return nil, os.ErrNotExist
	}
	want := []string{"cargo:shop-core", "composer:acme/help-centre", "golang:github.com/acme/shop", "npm:commmerce-analytics",
		"pub:commmerce_chat", "pypi:my-tool-cli"}
	if got := ManifestNames(read); !reflect.DeepEqual(got, want) {
		t.Errorf("names = %v, want %v", got, want)
	}
	if got := JoinPackageNames(want); got != strings.Join(want, ",") {
		t.Errorf("joined = %q", got)
	}
	// Bad manifests, and names that are not package names, give nothing.
	files = map[string]string{"package.json": `{"name": "has space"}`, "composer.json": `{`, "pubspec.yaml": "name: [1, 2]\n"}
	if got := ManifestNames(read); len(got) != 0 {
		t.Errorf("bad manifests: %v", got)
	}
	if got := ManifestNames(func(string) ([]byte, error) { return nil, errors.New("no") }); len(got) != 0 {
		t.Errorf("no files: %v", got)
	}
}

// A repository scan records the root manifests' names; a symbolic link
// named package.json is not followed out of the directory.
func TestScanDirRecordsPackageNames(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("pubspec.yaml", "name: commmerce_chat\n")
	write("package-lock.json", `{"lockfileVersion":3,"packages":{"":{"name":"whatsapp-chat"}}}`)
	outside := filepath.Join(t.TempDir(), "secret.json")
	if err := os.WriteFile(outside, []byte(`{"name":"outside-name"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "package.json")); err != nil {
		t.Fatal(err)
	}
	asset := model.AssetRef{Kind: model.AssetRepository, Name: "commmerce_chat", Attributes: map[string]string{"git_url": "https://github.com/acme/chat"}}
	b, err := ScanDirWith(context.Background(), dir, asset, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.Asset.Attributes[PackageNamesAttr]; got != "pub:commmerce_chat" {
		t.Errorf("package_names = %q", got)
	}
	if b.Asset.Attributes["git_url"] != "https://github.com/acme/chat" || len(asset.Attributes) != 1 {
		t.Errorf("attributes %v; caller's map %v", b.Asset.Attributes, asset.Attributes)
	}
}
