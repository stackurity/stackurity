package api

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/store"
)

// listFixGroups returns the action plan: findings grouped by the action that
// resolves them, most urgent first.
func (s *Server) listFixGroups(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.FixGroupFilter{AssetID: qInt(r, "asset_id"), Kind: q.Get("kind"), Environment: q.Get("environment"),
		Search: q.Get("q"), Page: page(r)}
	items, total, err := s.Store.ListFixGroups(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, f.Page))
}

func (s *Server) fixPlanSummary(w http.ResponseWriter, r *http.Request) {
	sum, err := s.Store.SummarizeFixPlan(r.Context(), qInt(r, "asset_id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, sum)
}

// getFixGroup returns one group with its findings (paged via limit/offset).
func (s *Server) getFixGroup(w http.ResponseWriter, r *http.Request) {
	id, err := url.PathUnescape(chi.URLParam(r, "id"))
	if err != nil {
		s.fail(w, r, badRequest("invalid id"))
		return
	}
	g, err := s.Store.GetFixGroup(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := page(r)
	findings, total, err := s.Store.ListFindings(r.Context(), store.FindingFilter{FixGroup: id, Page: p})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"group": json.RawMessage(g), "findings": paged(findings, total, p)})
}
