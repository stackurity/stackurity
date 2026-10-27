package api

import "net/http"

// assetUsage reports the organisation's monitored assets against its limit
// (docs/asset-limits.md), for the banner and Settings, Usage.
func (s *Server) assetUsage(w http.ResponseWriter, r *http.Request) {
	u, err := s.Store.AssetUsage(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, u)
}
