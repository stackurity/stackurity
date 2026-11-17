package api

import (
	"net/http"

	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
)

// POST /api/v1/usage-counts: the dashboard reports what only the browser sees, a
// locked paid-plan notice shown or a link in it clicked, and exports made
// in the browser (the evidence report's JSON download, printing a report).
// Only the organisation, the event, a key from a fixed list and the day
// are kept (store.CountUsage); nothing about the person or the page.
// Answers 204, also for keys it does not know, so a newer dashboard never
// shows an error against an older server.
func (s *Server) postUsage(w http.ResponseWriter, r *http.Request) {
	if p := principal(r); p != nil && (p.Token != nil || p.Assistant != nil || p.FeedbackAgent != nil || p.FeedbackReviewer != nil) {
		writeError(w, 403, "forbidden", "usage counts come from the dashboard only")
		return
	}
	var req struct {
		Event string `json:"event"`
		Key   string `json:"key"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	switch req.Event {
	case store.UsageTeaserView, store.UsageTeaserClick:
		if !teaserFeatures[req.Key] {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	case store.UsageExport:
		if !store.ClientExportKinds[req.Key] {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	default:
		s.fail(w, r, badRequest("event must be teaser_view, teaser_click or export"))
		return
	}
	s.countUsage(r, req.Event, req.Key)
	w.WriteHeader(http.StatusNoContent)
}

// teaserFeatures are the paid features a locked notice (ProNotice in the
// dashboard) can be about.
var teaserFeatures = map[string]bool{
	string(license.Remediation): true, string(license.Teams): true, string(license.EvidenceReport): true,
	string(license.SSO): true, string(license.EnterprisePacks): true, string(license.PhishingResistantMFA): true,
}
