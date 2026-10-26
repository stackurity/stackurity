package api

import (
	"net/http"

	"github.com/stackurity/stackurity/internal/updates"
)

// updatesStatus tells instance admins whether a newer release exists and
// what changed. Only operators of the installation can act on it, so other
// users get 403. It reads the stored result of the periodic check and never
// contacts anything itself.
func (s *Server) updatesStatus(w http.ResponseWriter, r *http.Request) {
	rep, err := updates.Status(r.Context(), s.Store, s.Version, s.UpdateCheck)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, rep)
}
