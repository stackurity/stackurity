package api

import (
	"net/http"

	"github.com/stackurity/stackurity/internal/license"
)

// planFeature is one paid feature in GET /plan/options.
type planFeature struct {
	Feature     license.Feature `json:"feature"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	// Offer is set for a feature the plan does not include.
	Offer *license.Offer `json:"offer,omitempty"`
}

// planOptions is GET /plan/options: the paid features the caller's
// organisation has and those it lacks, each lacking one with its offer
// (planOption: the plans that include it and, on Stackurity Cloud, their
// prices in the organisation's currency). Any member may read it, as
// /auth/me shows everyone the edition. It is what MCP's plan_options tool
// reads, for people who ask about their plan; it changes nothing.
func (s *Server) planOptions(w http.ResponseWriter, r *http.Request) {
	included, missing := []planFeature{}, []planFeature{}
	for _, f := range license.PaidFeatures() {
		o, on := s.planOption(r, f)
		pf := planFeature{Feature: f, Name: f.Name(), Description: f.Description()}
		if on {
			included = append(included, pf)
			continue
		}
		pf.Offer = o
		missing = append(missing, pf)
	}
	writeJSON(w, 200, map[string]any{"edition": s.Gate.Edition(r.Context()), "included": included, "not_included": missing,
		"plans_url": license.PlansURL})
}
