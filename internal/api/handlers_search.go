package api

import (
	"net/http"
	"strconv"

	"github.com/stackurity/stackurity/internal/store"
)

// search is the global search: vulnerabilities, components, assets and teams
// of the current workspace matching q, grouped by type.
func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	q, err := store.NormalizeSearch(r.URL.Query().Get("q"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	res, err := s.Store.Search(r.Context(), q, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, res)
}
