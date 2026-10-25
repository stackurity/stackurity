package api

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/upgrade"
)

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.FindingFilter{
		Kind: q.Get("kind"), Status: q.Get("status"), Verification: q.Get("verification"),
		AssetID: qInt(r, "asset_id"), ComponentID: qInt(r, "component_id"), Environment: q.Get("environment"),
		Search: q.Get("q"), Key: q.Get("key"), Exploited: q.Get("known_exploited") == "true", Page: page(r),
	}
	if sev := q.Get("severity"); sev != "" {
		f.Severity = strings.Split(sev, ",")
	}
	if pr := q.Get("priority"); pr != "" {
		f.Priority = strings.Split(pr, ",")
	}
	f.State = q.Get("state")
	f.SOS = q.Get("sos") == "true"
	f.Overdue = q.Get("overdue") == "true"
	f.AssigneeUser = qInt(r, "assignee_user")
	f.Unassigned = q.Get("assignee") == "none"
	f.FixGroup = q.Get("fix_group")
	f.AssigneeTeam = qInt(r, "assignee_team")
	f.IncidentID = qInt(r, "incident_id")
	switch f.State {
	case "", "active", "new", "acknowledged", "in_progress", "suppressed", "risk_accepted":
	default:
		s.fail(w, r, badRequest("state must be active, new, acknowledged, in_progress, suppressed or risk_accepted"))
		return
	}
	switch f.Status {
	case "", "open", "resolved", "all":
	default:
		s.fail(w, r, badRequest("status must be open, resolved or all"))
		return
	}
	items, total, err := s.Store.ListFindings(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, f.Page))
}

func (s *Server) findingSummary(w http.ResponseWriter, r *http.Request) {
	sum, err := s.Store.SummarizeFindings(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, sum)
}

// getFinding returns the finding with every advisory in its group, so the
// operator can see each source's claim and judge it independently.
func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
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
	resp := map[string]any{"finding": f}
	if f.Kind == "vulnerability" {
		advs, err := s.Store.AdvisoryGroup(r.Context(), f.Key)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		// Advisories that matched this component vs. others sharing the CVE
		// (e.g. the same issue in a different package).
		matched := map[string]bool{}
		for _, id := range f.Sources {
			matched[id] = true
		}
		sources, related := []store.Advisory{}, []store.Advisory{}
		for _, a := range advs {
			if matched[a.ID] {
				sources = append(sources, a)
			} else {
				related = append(related, a)
			}
		}
		resp["advisories"] = sources
		resp["related_advisories"] = related
	}
	if f.Status == "open" {
		rec, err := upgrade.ForFinding(r.Context(), s.Store, f, time.Now())
		if err != nil {
			s.fail(w, r, err)
			return
		}
		resp["upgrade"] = rec
	}
	writeJSON(w, 200, resp)
}

func (s *Server) getAdvisory(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	advs, err := s.Store.AdvisoryGroup(r.Context(), key)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(advs) == 0 {
		writeError(w, 404, "not_found", "no advisory with that id or alias group")
		return
	}
	writeJSON(w, 200, all(advs))
}

func (s *Server) listFeeds(w http.ResponseWriter, r *http.Request) {
	fs, err := s.Store.ListFeeds(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(fs))
}

// refreshFeed queues an immediate sync (manual refresh, FR-06).
// feedName decodes the {name} parameter: chi matches on the escaped path,
// so names such as "osv:Rocky Linux" arrive percent-encoded.
func feedName(r *http.Request) string {
	raw := chi.URLParam(r, "name")
	if n, err := url.PathUnescape(raw); err == nil {
		return n
	}
	return raw
}

func (s *Server) refreshFeed(w http.ResponseWriter, r *http.Request) {
	name := feedName(r)
	if _, err := s.Store.GetFeed(r.Context(), name); err != nil {
		s.fail(w, r, err)
		return
	}
	jobID, err := s.Store.Enqueue(r.Context(), "feed.sync", map[string]string{"feed": name}, "feed:"+name, time.Time{})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "feed.refresh", "feed", name, nil)
	writeJSON(w, 202, map[string]any{"job_id": jobID, "queued": jobID != 0})
}

func (s *Server) updateFeed(w http.ResponseWriter, r *http.Request) {
	name := feedName(r)
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Enabled == nil {
		s.fail(w, r, badRequest("enabled is required"))
		return
	}
	if err := s.Store.SetFeedEnabled(r.Context(), name, *req.Enabled); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "feed.update", "feed", name, req)
	f, err := s.Store.GetFeed(r.Context(), name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, f)
}

func (s *Server) listEvaluationGaps(w http.ResponseWriter, r *http.Request) {
	items, total, err := s.Store.ListEvaluationGaps(r.Context(), page(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, page(r)))
}

// reevaluate queues a full evaluation of all inventory.
func (s *Server) reevaluate(w http.ResponseWriter, r *http.Request) {
	jobID, err := s.Store.Enqueue(r.Context(), "evaluate", map[string]bool{"all": true}, "evaluate:all", time.Time{})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "evaluate.all", "", "", nil)
	writeJSON(w, 202, map[string]any{"job_id": jobID, "queued": jobID != 0})
}

// componentIntel returns release and lifecycle data for a component.
func (s *Server) componentIntel(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.Store.GetComponent(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	resp := map[string]any{"component": c}
	if rel, err := s.Store.GetRelease(r.Context(), id); err == nil {
		rel.VersionDates = nil // large; not needed here
		resp["release"] = rel
	}
	prods, err := s.Store.LifecycleProductsByPurl(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if product := prods[strings.ToLower(c.PurlKey)]; product != "" {
		cycles, err := s.Store.LifecycleCycles(r.Context(), product)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		resp["lifecycle"] = map[string]any{"product": product, "cycles": cycles}
	}
	writeJSON(w, 200, resp)
}
