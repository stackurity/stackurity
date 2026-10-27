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
// resolves them, most urgent first.
func (s *Server) listFixGroups(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.FixGroupFilter{AssetID: qInt(r, "asset_id"), Kind: q.Get("kind"), Environment: q.Get("environment"),
		Search: q.Get("q"), Bucket: q.Get("bucket"), Page: page(r)}
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
	byFix, ok := s.groupByFix(w, r)
	if !ok {
		return
	}
	f.ByFix = byFix
	items, total, err := s.Store.ListFixGroups(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, f.Page))
}

// groupByFix reads group_by (fix or asset; the workspace's setting when
// absent): whether the same fix in several places is one entry.
func (s *Server) groupByFix(w http.ResponseWriter, r *http.Request) (bool, bool) {
	by := r.URL.Query().Get("group_by")
	if by == "" {
		var err error
		if by, err = s.Store.FixGrouping(r.Context()); err != nil {
			s.fail(w, r, err)
			return false, false
		}
	}
	if by != store.FixGroupingFix && by != store.FixGroupingAsset {
		s.fail(w, r, badRequest("group_by must be fix or asset"))
		return false, false
	}
	return by == store.FixGroupingFix, true
}

// fixPlanSummary counts fixes as the list shows them: grouped by fix, the
// same fix in several places counts once.
func (s *Server) fixPlanSummary(w http.ResponseWriter, r *http.Request) {
	assetID := qInt(r, "asset_id")
	byFix, ok := s.groupByFix(w, r)
	if !ok {
		return
	}
	sum, err := s.Store.SummarizeFixPlan(r.Context(), assetID, byFix)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pol, err := s.Store.RiskPolicy(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	focus, err := s.Store.SummarizeFixFocus(r.Context(), assetID, pol.ProductionEnvironments, byFix)
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

type fixGroupingBody struct {
	FixGrouping string `json:"fix_grouping"`
}

// getFixGrouping says how fix lists show the same fix in several places.
func (s *Server) getFixGrouping(w http.ResponseWriter, r *http.Request) {
	v, err := s.Store.FixGrouping(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, fixGroupingBody{v})
}

func (s *Server) putFixGrouping(w http.ResponseWriter, r *http.Request) {
	var b fixGroupingBody
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.SetFixGrouping(r.Context(), b.FixGrouping); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "settings.update", "settings", "fix_grouping", b)
	s.getFixGrouping(w, r)
}
