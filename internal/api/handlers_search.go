package api

import (
	"net/http"
	"strconv"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
)

// search is the global search: vulnerabilities, finding titles, components,
// assets, teams and members of the current workspace matching q, grouped by
// type. Members are included for engineers and above, who can already list
// them in the user directory.
func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	q, err := store.NormalizeSearch(r.URL.Query().Get("q"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	members := principal(r).Role.AtLeast(auth.RoleEngineer)
	res, err := s.Store.SearchWith(r.Context(), q, store.SearchOptions{Limit: limit, Members: members})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, res)
}
