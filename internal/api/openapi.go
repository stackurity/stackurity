package api

import (
	_ "embed"
	"net/http"
)

// openAPISpec describes every /api/v1 operation (OpenAPI 3.1). It is kept
// by hand next to the router; TestOpenAPICoversEveryRoute fails when a
// route has no entry, or an entry no route.
//
//go:embed openapi.json
var openAPISpec []byte

// openAPI serves the spec. It is public: it describes the API, not any
// workspace's data.
func (s *Server) openAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(openAPISpec)
}
