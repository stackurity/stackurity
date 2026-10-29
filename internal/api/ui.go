package api

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

const placeholder = `<!doctype html><html><head><meta charset="utf-8"><title>Stackurity</title></head>
<body>
<h1>Stackurity</h1><p>The API is running at <code>/api/v1</code>. The dashboard was not built into this binary.</p>
</body></html>`

// uiHandler serves the built dashboard and falls back to index.html for
// client-side routes.
func (s *Server) uiHandler() http.Handler {
	if s.UI == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(placeholder))
		})
	}
	files := http.FileServer(http.FS(s.UI))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		// Unknown paths and directories (which would otherwise get a
		// listing, e.g. /assets) fall back to the SPA entry point.
		if st, err := fs.Stat(s.UI, p); err != nil || st.IsDir() {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		} else if strings.HasPrefix(p, "static/") {
			// Vite emits content-hashed file names under static/.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, r)
	})
}
