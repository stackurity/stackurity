package api

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
)

// Release 0.7, "the loop": check again, "I applied this", ignore rules and
// the approval inbox. See docs/api.md, "The loop".

// agentPollSeconds is how often agents ask whether to report now; they add
// up to a third of it as jitter.
const agentPollSeconds = 45

// agentCheck answers an agent's poll: should it report now? asset_id lists
// the assets it reported (repeat the parameter or separate with commas).
// Older agents never ask and report on their interval.
func (s *Server) agentCheck(w http.ResponseWriter, r *http.Request) {
	var ids []int64
	for _, v := range r.URL.Query()["asset_id"] {
		for _, part := range strings.Split(v, ",") {
			if id, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64); err == nil && id > 0 {
				ids = append(ids, id)
			}
		}
	}
	// A host-bound token may only ask about what it may report for: its
	// host and the applications on it, as ingest enforces.
	bound, err := s.boundAsset(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if bound != nil {
		if ids, err = s.Store.AssetsReportingThrough(r.Context(), *bound, ids); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	due, err := s.Store.AgentCheckDue(r.Context(), ids)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"check": due, "poll_seconds": agentPollSeconds})
}

// requestCheck records a check and starts what produces its evidence: a
// server-side scan for an asset with an integration. Agents pick theirs
// up on their next poll; uploads wait for the next one.
func (s *Server) requestCheck(w http.ResponseWriter, r *http.Request, in store.CheckRequest) {
	actor := principal(r).Actor(r)
	c, created, err := s.Store.RequestCheck(r.Context(), in, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if created && c.Method == store.CheckIntegration && c.IntegrationID != nil {
		key := "integration:" + itoa(*c.IntegrationID)
		if _, err := s.Store.Enqueue(r.Context(), "integration.run", map[string]int64{"integration_id": *c.IntegrationID}, key, time.Time{}); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if created {
		_ = s.Store.Audit(r.Context(), actor, "check.request", "asset", itoa(c.AssetID),
			map[string]any{"check_id": c.ID, "fix_group": c.FixGroup, "reason": c.Reason, "method": c.Method})
	}
	writeJSON(w, map[bool]int{true: 201, false: 200}[created], c)
}

func (s *Server) checkAsset(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.requestCheck(w, r, store.CheckRequest{AssetID: id})
}

func fixGroupParam(r *http.Request) (string, error) {
	id, err := url.PathUnescape(chi.URLParam(r, "id"))
	if err != nil || id == "" {
		return "", badRequest("invalid id")
	}
	return id, nil
}

func (s *Server) checkFixGroup(w http.ResponseWriter, r *http.Request) {
	id, err := fixGroupParam(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.requestCheck(w, r, store.CheckRequest{FixGroup: id})
}

// fixApplied records "I applied this": the fix's active issues go to in
// progress ("applied, waiting for a check") and a check is requested.
// Nothing is resolved until fresh evidence shows the issues gone.
func (s *Server) fixApplied(w http.ResponseWriter, r *http.Request) {
	id, err := fixGroupParam(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	actor := principal(r).Actor(r)
	// The check first, so it keeps the fix's issues before they change state.
	c, created, err := s.Store.RequestCheck(r.Context(), store.CheckRequest{FixGroup: id, Reason: "applied"}, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	n, err := s.Store.MarkFixApplied(r.Context(), id, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if created && c.Method == store.CheckIntegration && c.IntegrationID != nil {
		key := "integration:" + itoa(*c.IntegrationID)
		if _, err := s.Store.Enqueue(r.Context(), "integration.run", map[string]int64{"integration_id": *c.IntegrationID}, key, time.Time{}); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	_ = s.Store.Audit(r.Context(), actor, "fix.applied", "fix_group", id, map[string]any{"check_id": c.ID, "issues": n})
	writeJSON(w, 200, map[string]any{"updated": n, "check": c})
}

func (s *Server) listChecks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.CheckFilter{AssetID: qInt(r, "asset_id"), FixGroup: q.Get("fix_group"), Open: q.Get("open") == "true", Page: page(r)}
	items, total, err := s.Store.ListChecks(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, f.Page))
}

func (s *Server) getCheck(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.Store.GetCheck(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, c)
}

// --- ignore rules and requests

func (s *Server) exceptionMaxDays(r *http.Request) (int, error) {
	pol, err := s.Store.RiskPolicy(r.Context())
	if err != nil {
		return 0, err
	}
	return pol.ExceptionMaxDays, nil
}

func (s *Server) listIgnoreRules(w http.ResponseWriter, r *http.Request) {
	p := page(r)
	items, total, err := s.Store.ListIgnoreRules(r.Context(), r.URL.Query().Get("status") == "all", p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, p))
}

func (s *Server) endIgnoreRule(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	actor := principal(r).Actor(r)
	n, err := s.Store.EndIgnoreRule(r.Context(), id, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), actor, "ignore_rule.end", "ignore_rule", itoa(id), map[string]any{"reopened": n})
	writeJSON(w, 200, map[string]any{"reopened": n})
}

type ignoreRequestBody struct {
	FindingIDs []int64    `json:"finding_ids"`
	FixGroup   string     `json:"fix_group"`
	Reason     string     `json:"reason"`
	Note       string     `json:"note"`
	Mitigation string     `json:"mitigation"`
	Scope      string     `json:"scope"`
	Expiry     string     `json:"expiry"`
	Until      *time.Time `json:"until"`
}

// createIgnoreRequest lets anyone in the workspace ask for issues to be
// ignored; security and admin users decide in the approval inbox.
func (s *Server) createIgnoreRequest(w http.ResponseWriter, r *http.Request) {
	var b ignoreRequestBody
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(b.Note) > 2000 || len(b.Mitigation) > 2000 {
		s.fail(w, r, badRequest("note and mitigation are limited to 2000 characters"))
		return
	}
	if (len(b.FindingIDs) == 0) == (b.FixGroup == "") {
		s.fail(w, r, badRequest("send finding_ids or fix_group"))
		return
	}
	maxDays, err := s.exceptionMaxDays(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	actor := principal(r).Actor(r)
	req, err := s.Store.CreateIgnoreRequest(r.Context(), store.NewIgnoreRequest{FindingIDs: b.FindingIDs, FixGroup: b.FixGroup,
		IgnoreSpec: store.IgnoreSpec{Reason: b.Reason, Scope: b.Scope, Expiry: b.Expiry, Until: b.Until,
			Note: strings.TrimSpace(b.Note), Mitigation: strings.TrimSpace(b.Mitigation)}}, maxDays, actor)
	if err != nil {
		s.failAction(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), actor, "ignore_request.create", "ignore_request", itoa(req.ID),
		map[string]any{"issues": len(req.FindingIDs), "reason": req.Reason, "scope": req.Scope, "expiry": req.Expiry})
	writeJSON(w, 201, req)
}

// canDecide: security and admin users may ignore issues and decide requests.
func canDecide(r *http.Request) bool { return principal(r).Role.AtLeast(auth.RoleSecurity) }

// listIgnoreRequests: the inbox for those who decide, a person's own
// requests for everyone else. status=pending (the default), approved,
// declined or all.
func (s *Server) listIgnoreRequests(w http.ResponseWriter, r *http.Request) {
	f := store.IgnoreRequestFilter{Status: r.URL.Query().Get("status"), Page: page(r)}
	switch f.Status {
	case "":
		f.Status = "pending"
	case "all":
		f.Status = ""
	case "pending", "approved", "declined":
	default:
		s.fail(w, r, badRequest("status must be pending, approved, declined or all"))
		return
	}
	if !canDecide(r) {
		p := principal(r)
		if p.User == nil {
			writeJSON(w, 200, paged([]store.IgnoreRequest{}, 0, f.Page))
			return
		}
		f.RequestedBy = p.User.ID
	}
	items, total, err := s.Store.ListIgnoreRequests(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": nonNil(items), "total": total, "limit": paged(items, total, f.Page).Limit,
		"offset": f.Offset, "can_decide": canDecide(r)})
}

func (s *Server) getIgnoreRequest(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	req, err := s.Store.GetIgnoreRequest(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := principal(r)
	if !canDecide(r) && (p.User == nil || req.RequestedBy == nil || *req.RequestedBy != p.User.ID) {
		s.fail(w, r, store.ErrNotFound)
		return
	}
	writeJSON(w, 200, req)
}

func (s *Server) decideIgnoreRequest(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var b struct {
		Decision string `json:"decision"` // approve or decline
		Note     string `json:"note"`
	}
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	if b.Decision != "approve" && b.Decision != "decline" {
		s.fail(w, r, badRequest("decision must be approve or decline"))
		return
	}
	if len(b.Note) > 2000 {
		s.fail(w, r, badRequest("note is limited to 2000 characters"))
		return
	}
	maxDays, err := s.exceptionMaxDays(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	actor := principal(r).Actor(r)
	req, err := s.Store.DecideIgnoreRequest(r.Context(), id, b.Decision == "approve", strings.TrimSpace(b.Note), maxDays, actor)
	if err != nil {
		s.failAction(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), actor, "ignore_request."+b.Decision, "ignore_request", itoa(id),
		map[string]any{"note": b.Note, "applied": req.Applied, "requested_by": req.RequestedByName})
	writeJSON(w, 200, req)
}

// failAction answers invalid workflow requests with 400 and the reason.
func (s *Server) failAction(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrInvalidAction) {
		writeError(w, 400, "invalid_action", err.Error())
		return
	}
	s.fail(w, r, err)
}
