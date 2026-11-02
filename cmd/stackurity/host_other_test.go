//go:build !windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stackurity/stackurity/internal/collect/apps"
	"github.com/stackurity/stackurity/internal/model"
)

func TestReportableApp(t *testing.T) {
	libs := []model.Observation{{Purl: "pkg:npm/jquery@2.2.1"}}
	gap := []model.CoverageItem{{Scope: apps.PermissionScope + "/opt/tool", Status: "partial"}}
	for _, c := range []struct {
		name     string
		app      apps.App
		explicit bool
		by       string
		want     bool
	}{
		{"explicit, empty", apps.App{}, true, "", true},
		{"discovered with libraries", apps.App{Observations: libs}, false, "index.php", true},
		{"discovered, empty", apps.App{}, false, "package.json", false},
		// A vendor tool under /opt with one root-only directory.
		{"discovered, empty, some files unreadable", apps.App{Coverage: gap}, false, "package.json", false},
		{"discovered, directory unreadable", apps.App{Coverage: gap, Unreadable: true}, false, "nginx:/etc/nginx/conf.d/x.conf", true},
		{"discovered as unreadable", apps.App{}, false, "unreadable", true},
	} {
		if got := reportable(c.app, c.explicit, c.by); got != c.want {
			t.Errorf("%s: reportable = %v", c.name, got)
		}
	}
}

// The agent's application collection on a host whose only application is
// a compiled front-end build (a Flutter web app in /var/www/chat, a Vite
// build): its components are reported, and what cannot be identified is
// coverage rather than an application with no components.
func TestAgentReportsCompiledBundles(t *testing.T) {
	root := t.TempDir()
	write := func(p, data string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/os-release", "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n")
	write("var/lib/dpkg/status", "")
	write("var/www/chat/index.html", `<!DOCTYPE html><html><body><script src="flutter_bootstrap.js" async></script></body></html>`)
	write("var/www/chat/flutter_bootstrap.js", `_flutter.buildConfig = {"engineRevision":"18818009497c581ede5d8a3b8b833b81d00cebb7","builds":[{"compileTarget":"dart2js","renderer":"canvaskit","mainJsPath":"main.dart.js"}]};`)
	write("var/www/chat/main.dart.js", "(function dartProgram(){function copyProperties(a,b){}})()\n")
	write("var/www/chat/canvaskit/canvaskit.wasm", "\x00asm")
	write("srv/dash/index.html", `<!doctype html><script type="module" src="/assets/index-Dk53Pw_R.js"></script>`)
	write("srv/dash/assets/index-Dk53Pw_R.js", "e.useTransition=function(){return T.H.useTransition()},e.version=`19.1.0`;var q={bundleType:0,version:`19.1.0`,rendererPackageName:`react-dom`};")
	write("srv/own/assets/app-1a2b3c4d.js", `(()=>{var __webpack_modules__={1:()=>{const cfg={name:"React dashboard",version:"18.2.0"}}}})();`)

	collect, err := hostCollector(&hostOptions{root: root, appDirs: []string{"/var/www/chat", "/srv/dash", "/srv/own"}})
	if err != nil {
		t.Fatal(err)
	}
	batches, err := collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	apps := map[string]*model.ObservationBatch{}
	for _, b := range batches {
		if err := b.Validate(); err != nil {
			t.Fatalf("%s: %v", b.Asset.Name, err)
		}
		if d := b.Asset.Attributes["app_dir"]; d != "" {
			apps[d] = b
		}
	}
	has := func(dir, purl string) bool {
		for _, o := range apps[dir].Observations {
			if o.Purl == purl {
				return true
			}
		}
		return false
	}
	scope := func(dir, scope string) model.CoverageItem {
		for _, c := range apps[dir].Coverage {
			if c.Scope == scope {
				return c
			}
		}
		return model.CoverageItem{}
	}
	if len(apps) != 3 {
		t.Fatalf("applications = %v", apps)
	}
	if !has("/var/www/chat", "pkg:generic/flutter-engine@18818009497c581ede5d8a3b8b833b81d00cebb7") || scope("/var/www/chat", "flutter:/var/www/chat").Status != "partial" {
		t.Errorf("chat = %+v %+v", apps["/var/www/chat"].Observations, apps["/var/www/chat"].Coverage)
	}
	if !has("/srv/dash", "pkg:npm/react@19.1.0") || !has("/srv/dash", "pkg:npm/react-dom@19.1.0") {
		t.Errorf("dash = %+v", apps["/srv/dash"].Observations)
	}
	if len(apps["/srv/own"].Observations) != 0 || scope("/srv/own", "bundles:/srv/own").Status != "unsupported" {
		t.Errorf("own = %+v %+v", apps["/srv/own"].Observations, apps["/srv/own"].Coverage)
	}
}
