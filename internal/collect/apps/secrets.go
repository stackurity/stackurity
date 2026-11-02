package apps

import (
	"context"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/stackurity/stackurity/internal/collect/secretscan"
	"github.com/stackurity/stackurity/internal/model"
)

// Secrets on a server are reported only where anyone can download them:
// files the web server sends as they are. Configuration the application
// reads (wp-config.php, a Laravel .env outside public/) is where its
// credentials belong and is not reported.

// publicDirs are served as they are by convention; dist, build and out
// only when they hold an index.html (otherwise they may be a server's
// compiled code).
var publicDirs = map[string]bool{"public": true, "static": true, "www": true, "htdocs": true, "html": true, "web": true,
	"wwwroot": true, "public_html": true}

var builtDirs = map[string]bool{"dist": true, "build": true, "out": true}

// servedExt: files a web server sends as they are (scripts the server
// runs, such as .php, are not).
var servedExt = map[string]bool{".js": true, ".mjs": true, ".cjs": true, ".map": true, ".json": true, ".html": true,
	".htm": true, ".txt": true, ".xml": true, ".yml": true, ".yaml": true, ".ini": true, ".conf": true, ".cfg": true,
	".env": true, ".bak": true, ".old": true, ".orig": true, ".save": true, ".sql": true, ".log": true,
	".properties": true, ".toml": true, ".config": true, ".backup": true}

// served reports whether the file at slash path p (relative to the
// application) is sent to anyone who asks for it.
func served(fsys fs.FS, siteRoot bool, p string) bool {
	base := strings.ToLower(path.Base(p))
	if !servedExt[path.Ext(base)] && !strings.HasPrefix(base, ".env") {
		return false
	}
	parts := strings.Split(p, "/")
	for _, d := range parts[:len(parts)-1] {
		if strings.HasPrefix(d, ".") || skipWebDir[d] {
			return false
		}
	}
	if siteRoot {
		return true
	}
	if len(parts) < 2 {
		return false
	}
	top := strings.ToLower(parts[0])
	return publicDirs[top] || builtDirs[top] && hasIndex(fsys, parts[0])
}

func hasIndex(fsys fs.FS, dir string) bool {
	for _, n := range []string{"index.html", "index.htm", "index.php"} {
		if _, err := fs.Stat(fsys, path.Join(dir, n)); err == nil {
			return true
		}
	}
	return false
}

// scanSecrets looks for secrets in the files the application serves.
func (s *Scanner) scanSecrets(ctx context.Context, dir string) *model.SecretList {
	fsys := os.DirFS(s.path(dir))
	siteRoot := hasIndex(fsys, ".")
	return secretscan.Scan(ctx, fsys, secretscan.Options{
		Exposure: secretscan.ExposurePublic,
		Include: func(p string) bool {
			return served(fsys, siteRoot, p) && !s.nestedApp(dir, path.Join(dir, path.Dir(p)))
		},
	})
}
