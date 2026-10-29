package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/why"
)

// findingWhy builds the why-it-matched explanation of a finding from what
// the matcher stored, the inventory row, the source and the second check.
func (s *Server) findingWhy(ctx context.Context, f *store.Finding) (*why.Explanation, error) {
	var ev map[string]any
	_ = json.Unmarshal(f.Evidence, &ev)
	feed, _ := ev["feed"].(string)
	if f.Kind == "end_of_life" {
		feed, _ = ev["source"].(string)
	}
	in, err := s.Store.FindingWhyInputs(ctx, f, feed)
	if err != nil {
		return nil, err
	}
	pol, err := s.Store.RiskPolicy(ctx)
	if err != nil {
		return nil, err
	}
	e := why.Build(why.Input{Finding: f, Evidence: ev, Inventory: in.Inventory, Feed: in.Feed, SecondCheck: in.SecondCheck,
		Covered: in.Covered, Policy: &pol}, time.Now())
	return &e, nil
}

// secondChecks summarises the independent second check of high-impact
// findings: results of open findings, those waiting, and the latest
// logged disagreements (for the Coverage page and corpus work).
func (s *Server) secondChecks(w http.ResponseWriter, r *http.Request) {
	sum, err := s.Store.SummarizeSecondChecks(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, sum)
}
