package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/store"
)

// listFixGroups returns the action plan: findings grouped by the action that
// resolves them, most urgent first. With merge=true the same upgrade on
// several assets (in view after the filters) is one item.
func (s *Server) listFixGroups(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.FixGroupFilter{AssetID: qInt(r, "asset_id"), Kind: q.Get("kind"), Environment: q.Get("environment"),
		Search: q.Get("q"), Bucket: q.Get("bucket"), Merge: q.Get("merge") == "true", Page: page(r)}
	if f.Bucket != "" {
		if !slices.Contains(store.FixBuckets, f.Bucket) {
			s.fail(w, r, badRequest("bucket must be one of "+strings.Join(store.FixBuckets, ", ")))
			return
		}
		pol, err := s.Store.RiskPolicy(r.Context())
		if err != nil {
			s.fail(w, r, err)
			return
		}
		f.ProductionEnvs = pol.ProductionEnvironments
	}
	items, total, err := s.Store.ListFixGroups(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, f.Page))
}

func (s *Server) fixPlanSummary(w http.ResponseWriter, r *http.Request) {
	assetID := qInt(r, "asset_id")
	merge := r.URL.Query().Get("merge") == "true"
	sum, err := s.Store.SummarizeFixPlan(r.Context(), assetID, merge)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pol, err := s.Store.RiskPolicy(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	focus, err := s.Store.SummarizeFixFocus(r.Context(), assetID, pol.ProductionEnvironments, merge)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, struct {
		*store.FixPlanSummary
		Focus *store.FixFocus `json:"focus"`
	}{sum, focus})
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
