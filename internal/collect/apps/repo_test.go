package apps

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

func writeRepoFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A PHP site's repository with copied libraries and a CDN link and no
// manifest reports each library, by its path in the repository.
func TestRepoWebAssets(t *testing.T) {
	dir := t.TempDir()
	writeRepoFile(t, dir, "js/jquery-3.6.0.min.js", "/*! jQuery v3.6.0 | (c) OpenJS Foundation and other contributors | jquery.org/license */\n!function(e,t){}")
	writeRepoFile(t, dir, "js/bootstrap.bundle.min.js", "/*!\n  * Bootstrap v5.1.3 (https://getbootstrap.com/)\n  */\n!function(t,e){}")
	writeRepoFile(t, dir, "index.php", `<?php include "inc/head.php"; ?>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.20/lodash.min.js"></script>`)
	// Not what the site serves: Composer's tree, dependencies, docs, git.
	writeRepoFile(t, dir, "vendor/composer/installed.json", "{}")
	writeRepoFile(t, dir, "vendor/some/pkg/jquery.min.js", "/*! jQuery v1.4.2 | (c) */")
	writeRepoFile(t, dir, "node_modules/jquery/dist/jquery.min.js", "/*! jQuery v2.2.4 | (c) */")
	writeRepoFile(t, dir, "docs/demo.html", `<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>`)
	writeRepoFile(t, dir, ".git/x/jquery.min.js", "/*! jQuery v1.11.0 | (c) */")

	obs, web, _ := RepoWebAssets(context.Background(), dir, nil, nil)
	got := map[string]model.Observation{}
	for _, o := range obs {
		got[o.Purl] = o
	}
	want := map[string]string{
		"pkg:npm/jquery@3.6.0":    "js/jquery-3.6.0.min.js",
		"pkg:npm/bootstrap@5.1.3": "js/bootstrap.bundle.min.js",
		"pkg:npm/lodash@4.17.20":  "index.php",
	}
	for purl, loc := range want {
		o, ok := got[purl]
		if !ok {
			t.Errorf("%s not reported (got %v)", purl, keys(got))
			continue
		}
		if o.Location != loc {
			t.Errorf("%s location %q, want %q", purl, o.Location, loc)
		}
		if !model.Usable(o) {
			t.Errorf("%s: not usable", purl)
		}
	}
	for purl := range got {
		if strings.Contains(purl, "jquery@1.") || strings.Contains(purl, "jquery@2.") {
			t.Errorf("%s comes from a directory the site does not serve", purl)
		}
	}
	if web.Scope != "web-assets:." || web.Status != "checked" {
		t.Errorf("web-assets coverage %+v", web)
	}
}

// A copy the lockfile scan already reports (package-lock.json lists the
// same release) is not reported twice.
func TestRepoWebAssetsYieldToManifest(t *testing.T) {
	dir := t.TempDir()
	writeRepoFile(t, dir, "public/js/jquery.min.js", "/*! jQuery v3.6.0 | (c) OpenJS Foundation */")
	manifest := []model.Observation{{Purl: "pkg:npm/jquery@3.6.0", Version: "3.6.0", Location: "package-lock.json"}}
	obs, _, _ := RepoWebAssets(context.Background(), dir, manifest, nil)
	if len(obs) != 0 {
		t.Errorf("reported again: %+v", obs)
	}
}

// A read limit marks the web-assets item partial, so a library past it is
// never taken for removed.
func TestRepoWebAssetsLimit(t *testing.T) {
	defer func(f, b int) { webFiles, webBytes = f, b }(webFiles, webBytes)
	webFiles = 1
	dir := t.TempDir()
	writeRepoFile(t, dir, "a/jquery.min.js", "/*! jQuery v3.6.0 | (c) */")
	writeRepoFile(t, dir, "b/jquery.min.js", "/*! jQuery v3.5.1 | (c) */")
	_, web, _ := RepoWebAssets(context.Background(), dir, nil, nil)
	if web.Status != "partial" {
		t.Errorf("web-assets coverage %+v", web)
	}
}

// In a local checkout, a build's output that git ignores is not the
// repository's; a repository with no templates or scripts still says it
// looked ("web-assets:." checked), so a deleted copy is proven gone.
func TestRepoWebAssetsIgnoredAndEmpty(t *testing.T) {
	dir := t.TempDir()
	writeRepoFile(t, dir, "public/build/jquery.min.js", "/*! jQuery v3.6.0 | (c) OpenJS Foundation */")
	writeRepoFile(t, dir, "static/old.js", "/*! jQuery v1.12.4 | (c) jQuery Foundation */")
	obs, _, _ := RepoWebAssets(context.Background(), dir, nil, map[string]bool{"public/build": true, "static/old.js": true})
	if len(obs) != 0 {
		t.Errorf("ignored paths reported: %+v", obs)
	}
	obs, web, more := RepoWebAssets(context.Background(), t.TempDir(), nil, nil)
	if len(obs) != 0 || len(more) != 0 || web.Scope != "web-assets:." || web.Status != "checked" {
		t.Errorf("empty repository: obs %v web %+v more %+v", obs, web, more)
	}
}

// A CI workspace reached through a symbolic link is read like the
// directory itself; source maps are not read (the server's clone has none).
func TestRepoWebAssetsLinkedRootAndMaps(t *testing.T) {
	real := t.TempDir()
	writeRepoFile(t, real, "js/jquery-3.6.0.min.js", "/*! jQuery v3.6.0 | (c) OpenJS Foundation */")
	writeRepoFile(t, real, "dist/app.3f9a2c.js.map", `{"version":3,"sources":["webpack:///./node_modules/lodash/lodash.js"],"sourcesContent":["/** @license Lodash 4.17.20 */"]}`)
	link := filepath.Join(t.TempDir(), "ws")
	if err := os.Symlink(real, link); err != nil {
		t.Skip(err)
	}
	obs, web, more := RepoWebAssets(context.Background(), link, nil, nil)
	if len(obs) != 1 || obs[0].Purl != "pkg:npm/jquery@3.6.0" || web.Status != "checked" {
		t.Errorf("obs %+v web %+v", obs, web)
	}
	if len(more) != 0 {
		t.Errorf("a source map was read: %+v", more)
	}
}

// A path the scan may not read leaves the web-assets item partial.
func TestRepoWebAssetsUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	dir := t.TempDir()
	writeRepoFile(t, dir, "assets/js/jquery.min.js", "/*! jQuery v3.6.0 | (c) */")
	if err := os.Chmod(filepath.Join(dir, "assets"), 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Join(dir, "assets"), 0o755)
	_, web, _ := RepoWebAssets(context.Background(), dir, nil, nil)
	if web.Status != "partial" {
		t.Errorf("web-assets coverage %+v, want partial", web)
	}
}
