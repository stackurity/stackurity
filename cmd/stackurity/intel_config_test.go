package main

import (
	"strings"
	"testing"
)

// STACKURITY_WORDPRESS_ORG_URL on a mirror without the list URLs leaves the
// lists unavailable and warns once at startup; with them set, no warning.
func TestIntelConfigWordPressMirror(t *testing.T) {
	t.Setenv("STACKURITY_WORDPRESS_ORG_URL", "https://mirror.example/wp-api")
	t.Setenv("STACKURITY_WORDPRESS_PLUGINS_LIST_URL", "")
	t.Setenv("STACKURITY_WORDPRESS_THEMES_LIST_URL", "")
	cfg, warnings := intelConfig(t.TempDir())
	if cfg.WordPressOrgURL != "https://mirror.example/wp-api" || cfg.WordPressPluginsListURL != "" || cfg.WordPressThemesListURL != "" ||
		len(warnings) != 1 || !strings.Contains(warnings[0], "points at a mirror") {
		t.Errorf("mirror without lists: %+v %q", cfg, warnings)
	}
	t.Setenv("STACKURITY_WORDPRESS_PLUGINS_LIST_URL", "https://mirror.example/plugins-svn/")
	t.Setenv("STACKURITY_WORDPRESS_THEMES_LIST_URL", "https://mirror.example/themes-svn/")
	cfg, warnings = intelConfig(t.TempDir())
	if cfg.WordPressPluginsListURL != "https://mirror.example/plugins-svn/" || cfg.WordPressThemesListURL != "https://mirror.example/themes-svn/" || len(warnings) != 0 {
		t.Errorf("mirror with lists: %+v %q", cfg, warnings)
	}
	t.Setenv("STACKURITY_WORDPRESS_ORG_URL", "")
	t.Setenv("STACKURITY_WORDPRESS_PLUGINS_LIST_URL", "")
	t.Setenv("STACKURITY_WORDPRESS_THEMES_LIST_URL", "")
	if cfg, warnings = intelConfig(t.TempDir()); cfg.WordPressPluginsListURL != "https://plugins.svn.wordpress.org/" || len(warnings) != 0 {
		t.Errorf("defaults: %+v %q", cfg, warnings)
	}
}
