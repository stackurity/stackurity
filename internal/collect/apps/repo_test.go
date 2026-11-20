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

	obs, cov, complete := RepoWebAssets(context.Background(), dir, nil, nil)
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
	if !complete {
		t.Error("complete = false with no limit reached")
	}
	if len(cov) == 0 || cov[0].Scope != "web-assets:." || cov[0].Status != "checked" {
		t.Errorf("coverage %+v", cov)
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

// A read limit makes the scan incomplete, so a library past it is never
// taken for removed.
func TestRepoWebAssetsLimit(t *testing.T) {
	defer func(f, b int) { webFiles, webBytes = f, b }(webFiles, webBytes)
	webFiles = 1
	dir := t.TempDir()
	writeRepoFile(t, dir, "a/jquery.min.js", "/*! jQuery v3.6.0 | (c) */")
	writeRepoFile(t, dir, "b/jquery.min.js", "/*! jQuery v3.5.1 | (c) */")
	_, cov, complete := RepoWebAssets(context.Background(), dir, nil, nil)
	if complete {
		t.Error("complete after the file limit stopped the walk")
	}
	if len(cov) == 0 || cov[0].Status != "partial" {
		t.Errorf("coverage %+v", cov)
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
	obs, cov, complete := RepoWebAssets(context.Background(), t.TempDir(), nil, nil)
	if len(obs) != 0 || !complete || len(cov) != 1 || cov[0].Scope != "web-assets:." || cov[0].Status != "checked" {
		t.Errorf("empty repository: obs %v cov %+v complete %v", obs, cov, complete)
	}
}
