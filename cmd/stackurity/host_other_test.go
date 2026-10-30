//go:build !windows

package main

import (
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
