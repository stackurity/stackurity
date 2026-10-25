package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/upgrade"
)

// findingUpgrade recommends a version for the component behind a finding,
// covering every open finding on that installed copy.
func (s *Server) findingUpgrade(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f, err := s.Store.GetFinding(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rec, err := upgrade.ForFinding(r.Context(), s.Store, f, time.Now())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"finding_id": f.ID, "asset_id": f.AssetID, "asset_name": f.AssetName,
		"component_id": f.ComponentID, "component": f.ComponentName, "upgrade": rec})
}

// componentUpgrade recommends a version for each installed version of a
// component that has open findings.
func (s *Server) componentUpgrade(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	recs, total, err := upgrade.ForComponent(r.Context(), s.Store, id, time.Now())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, list[upgrade.VersionRecommendation]{Items: recs, Total: int64(total)})
}

// explainFinding returns why a finding has its priority, with the evidence
// and the sources behind it, each citable.
func (s *Server) explainFinding(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := r.Context()
	f, err := s.Store.GetFinding(ctx, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pol, err := s.Store.RiskPolicy(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var factors []risk.Factor
	_ = json.Unmarshal(f.PriorityFactors, &factors)
	if factors == nil {
		factors = []risk.Factor{}
	}
	var ev map[string]any
	_ = json.Unmarshal(f.Evidence, &ev)

	type advisory struct {
		ID             string     `json:"id"`
		Feed           string     `json:"feed"`
		Severity       string     `json:"severity"`
		Score          *float32   `json:"score"`
		Vector         string     `json:"vector,omitempty"`
		SeveritySource string     `json:"severity_source,omitempty"`
		Published      *time.Time `json:"published"`
		Modified       time.Time  `json:"modified"`
		Withdrawn      *time.Time `json:"withdrawn,omitempty"`
		KnownExploited bool       `json:"known_exploited"`
		URL            string     `json:"url"`
	}
	advs := []advisory{}
	feedNames := map[string]bool{}
	if f.Kind == "vulnerability" {
		group, err := s.Store.AdvisoryGroup(ctx, f.Key)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		matched := map[string]bool{}
		for _, id := range f.Sources {
			matched[id] = true
		}
		for _, a := range group {
			if !matched[a.ID] {
				continue
			}
			advs = append(advs, advisory{a.ID, a.Feed, a.SeverityLevel, a.SeverityScore, a.SeverityVector, a.SeveritySource, a.Published,
				a.Modified, a.Withdrawn, a.KnownExploited, "https://osv.dev/vulnerability/" + url.PathEscape(a.ID)})
			feedNames[a.Feed] = true
		}
	}
	if fd, ok := ev["feed"].(string); ok && fd != "" {
		feedNames[fd] = true
	}
	if fd, ok := ev["source"].(string); ok && fd != "" && f.Kind == "end_of_life" {
		feedNames[fd] = true
	}
	type feedState struct {
		Name        string     `json:"name"`
		LastSuccess *time.Time `json:"last_success"`
		Stale       bool       `json:"stale"`
		LastError   string     `json:"last_error,omitempty"`
	}
	feeds := []feedState{}
	known, err := s.Store.ListFeeds(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, fd := range known {
		if feedNames[fd.Name] {
			feeds = append(feeds, feedState{fd.Name, fd.LastSuccess, fd.Stale, fd.LastError})
		}
	}
	sort.Slice(feeds, func(i, j int) bool { return feeds[i].Name < feeds[j].Name })
	last, complete, err := s.Store.AssetCollectionTimes(ctx, f.AssetID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sla := pol.SLA[f.Priority]
	writeJSON(w, 200, map[string]any{
		"finding": map[string]any{
			"id": f.ID, "kind": f.Kind, "key": f.Key, "title": f.Title, "status": f.Status, "state": f.State,
			"verification": f.Verification, "severity": f.Severity, "score": f.Score, "known_exploited": f.KnownExploited,
			"first_seen": f.FirstSeen, "last_evaluated": f.LastSeen, "resolved_at": f.ResolvedAt, "resolution": f.Resolution,
			"asset": map[string]any{"id": f.AssetID, "name": f.AssetName, "kind": f.AssetKind, "environment": f.Environment},
			"component": map[string]any{"id": f.ComponentID, "name": f.ComponentName, "type": f.ComponentType, "version": f.Version,
				"location": f.Location, "direct": f.Direct, "fixed_version": f.FixedVersion},
		},
		"risk": map[string]any{
			"priority": f.Priority, "score": f.PriorityScore, "factors": factors, "sos": f.SOS, "sos_rule": f.SOSRule,
			"policy_version": pol.Version(),
			"thresholds":     map[string]float64{"P1": pol.Thresholds.P1, "P2": pol.Thresholds.P2, "P3": pol.Thresholds.P3},
			"sla":            map[string]int{"ack_hours": sla.AckHours, "fix_days": sla.FixDays},
			"ack_due":        f.AckDue, "fix_due": f.FixDue, "overdue": f.Overdue,
			"note": "Factors were stored when the finding was last prioritised; open findings are re-prioritised when the policy " +
				"or the evidence changes. policy_version identifies the current policy.",
		},
		"evidence":   ev,
		"advisories": advs,
		"feeds":      feeds,
		"collection": map[string]any{"last_collection_at": last, "last_complete_collection_at": complete},
	})
}

// verifySince lists findings resolved since a time and those that existed
// then and are still open, with when each asset last reported.
func (s *Server) verifySince(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("since")
	since, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		if d, derr := time.Parse("2006-01-02", raw); derr == nil {
			since, err = d, nil
		}
	}
	if err != nil {
		s.fail(w, r, badRequest("since must be an RFC 3339 time or a date (YYYY-MM-DD)"))
		return
	}
	if since.After(time.Now()) {
		s.fail(w, r, badRequest("since is in the future"))
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rep, err := s.Store.VerifySince(r.Context(), since, qInt(r, "asset_id"), limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, rep)
}

// outcomesReport measures remediation over the last `days` days (default
// 90, at most 365).
func (s *Server) outcomesReport(w http.ResponseWriter, r *http.Request) {
	days := 90
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 365 {
			s.fail(w, r, badRequest("days must be between 1 and 365"))
			return
		}
		days = n
	}
	pol, err := s.Store.RiskPolicy(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	fixDays := map[string]int{}
	for p, sla := range pol.SLA {
		fixDays[p] = sla.FixDays
	}
	to := time.Now().UTC()
	rep, err := s.Store.OutcomesReport(r.Context(), to.AddDate(0, 0, -days), to, fixDays)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"days": days, "policy_version": pol.Version(), "report": rep})
}
