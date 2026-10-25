package api

import (
	"encoding/json"
	"errors"
	"github.com/stackurity/stackurity/internal/license"
	"net/http"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
)

type actionRequest struct {
	Action     string     `json:"action"`
	Note       string     `json:"note"`
	Mitigation string     `json:"mitigation"`
	Until      *time.Time `json:"until"`
	UserID     *int64     `json:"user_id"`
	TeamID     *int64     `json:"team_id"`
	IDs        []int64    `json:"ids"` // bulk only
}

// Suppression and risk acceptance are reserved for the security role (FR-09).
var securityActions = map[string]bool{"suppress": true, "accept_risk": true, "reopen": true}

func (s *Server) checkAction(w http.ResponseWriter, r *http.Request, req *actionRequest) bool {
	p := principal(r)
	if securityActions[req.Action] && !p.Role.AtLeast(auth.RoleSecurity) {
		writeError(w, 403, "forbidden", req.Action+" requires the security role")
		return false
	}
	if len(req.Note) > 2000 || len(req.Mitigation) > 2000 {
		s.fail(w, r, badRequest("note and mitigation are limited to 2000 characters"))
		return false
	}
	req.Note = strings.TrimSpace(req.Note)
	req.Mitigation = strings.TrimSpace(req.Mitigation)
	return true
}

func (s *Server) applyAction(w http.ResponseWriter, r *http.Request, ids []int64, req actionRequest) {
	actor := principal(r).Actor(r)
	a := store.FindingAction{Action: req.Action, Note: req.Note, Until: req.Until, Mitigation: req.Mitigation,
		AssignUser: req.UserID, AssignTeam: req.TeamID}
	if req.Action == "suppress" || req.Action == "accept_risk" {
		pol, err := s.Store.RiskPolicy(r.Context())
		if err != nil {
			s.fail(w, r, err)
			return
		}
		a.MaxDays = pol.ExceptionMaxDays
	}
	done := 0
	var failures []string
	for _, id := range ids {
		if err := s.Store.ApplyFindingAction(r.Context(), id, a, actor); err != nil {
			if errors.Is(err, store.ErrInvalidAction) || errors.Is(err, store.ErrNotFound) {
				failures = append(failures, itoa(id)+": "+err.Error())
				continue
			}
			s.fail(w, r, err)
			return
		}
		done++
	}
	_ = s.Store.Audit(r.Context(), actor, "finding."+req.Action, "finding", joinIDs(ids),
		map[string]any{"note": req.Note, "mitigation": req.Mitigation, "until": req.Until, "user_id": req.UserID, "team_id": req.TeamID, "applied": done})
	if done == 0 && len(failures) > 0 {
		writeError(w, 400, "invalid_action", "no finding was changed", failures...)
		return
	}
	writeJSON(w, 200, map[string]any{"applied": done, "failed": failures})
}

func joinIDs(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for i, id := range ids {
		if i == 20 {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, itoa(id))
	}
	return strings.Join(parts, ",")
}

func (s *Server) findingAction(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req actionRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.checkAction(w, r, &req) {
		return
	}
	s.applyAction(w, r, []int64{id}, req)
}

func (s *Server) bulkFindingAction(w http.ResponseWriter, r *http.Request) {
	var req actionRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > 500 {
		s.fail(w, r, badRequest("ids must list 1-500 findings"))
		return
	}
	if !s.checkAction(w, r, &req) {
		return
	}
	s.applyAction(w, r, req.IDs, req)
}

func (s *Server) findingEvents(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	evs, err := s.Store.FindingEvents(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(evs))
}

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.IncidentFilter{Status: q.Get("status"), Kind: q.Get("kind"), Priority: q.Get("priority"),
		SOS: q.Get("sos") == "true", Escalated: q.Get("escalated") == "true", TeamID: qInt(r, "team_id"), Page: page(r)}
	items, total, err := s.Store.ListIncidents(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, f.Page))
}

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	in, err := s.Store.GetIncident(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	findings, _, err := s.Store.ListFindings(r.Context(), store.FindingFilter{IncidentID: id, Status: "all", Page: store.Page{Limit: 500}})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	resp := map[string]any{"incident": in, "findings": findings}
	if principal(r).Role.AtLeast(auth.RoleSecurity) {
		dels, _, err := s.Store.ListDeliveries(r.Context(), store.DeliveryFilter{IncidentID: id, Page: store.Page{Limit: 100}})
		if err != nil {
			s.fail(w, r, err)
			return
		}
		resp["deliveries"] = dels
	}
	writeJSON(w, 200, resp)
}

// incidentAction applies an action to every open finding in the incident.
func (s *Server) incidentAction(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req actionRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.checkAction(w, r, &req) {
		return
	}
	ids, err := s.Store.IncidentFindingIDs(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(ids) == 0 {
		writeError(w, 404, "not_found", "incident has no open findings")
		return
	}
	s.applyAction(w, r, ids, req)
}

func (s *Server) getRiskPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := s.Store.RiskPolicy(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"policy": p, "default": risk.DefaultPolicy()})
}

func (s *Server) putRiskPolicy(w http.ResponseWriter, r *http.Request) {
	var p risk.Policy
	if err := decode(r, &p); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := p.Validate(); err != nil {
		s.fail(w, r, badRequest(err.Error()))
		return
	}
	if err := s.Store.SetRiskPolicy(r.Context(), p); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "risk_policy.update", "settings", "risk_policy", p)
	writeJSON(w, 200, map[string]any{"policy": p})
}

// --- channels and routes

type channelRequest struct {
	Kind      string          `json:"kind"`
	Name      *string         `json:"name"`
	Config    json.RawMessage `json:"config"`
	SecretRef *string         `json:"secret_ref"`
	Enabled   *bool           `json:"enabled"`
}

func (s *Server) validateChannel(kind string, cfgRaw json.RawMessage, secretRef string) error {
	var cfg notify.ChannelConfig
	if len(cfgRaw) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(cfgRaw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return badRequest("invalid config: " + err.Error())
		}
	}
	if secretRef != "" {
		if err := s.Secrets.Validate(secretRef); err != nil {
			return badRequest(err.Error())
		}
	}
	if err := notify.ValidateChannel(kind, cfg, secretRef != "", s.AllowHTTPWebhooks); err != nil {
		return badRequest(err.Error())
	}
	return nil
}

func (s *Server) listChannels(w http.ResponseWriter, r *http.Request) {
	cs, err := s.Store.ListChannels(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(cs))
}

func (s *Server) createChannel(w http.ResponseWriter, r *http.Request) {
	var req channelRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Name == nil || strings.TrimSpace(*req.Name) == "" {
		s.fail(w, r, badRequest("name is required"))
		return
	}
	ref := ""
	if req.SecretRef != nil {
		ref = *req.SecretRef
	}
	if len(req.Config) == 0 {
		req.Config = json.RawMessage("{}")
	}
	if err := s.validateChannel(req.Kind, req.Config, ref); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := checkSecretRef(r, ref); err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.Store.CreateChannel(r.Context(), req.Kind, strings.TrimSpace(*req.Name), req.Config, ref)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "channel.create", "channel", itoa(c.ID), map[string]string{"kind": c.Kind, "name": c.Name})
	writeJSON(w, 201, c)
}

func (s *Server) updateChannel(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cur, err := s.Store.GetChannel(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req channelRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	cfg, ref := cur.Config, cur.SecretRef
	if len(req.Config) > 0 {
		cfg = req.Config
	}
	if req.SecretRef != nil {
		ref = *req.SecretRef
	}
	if err := s.validateChannel(cur.Kind, cfg, ref); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := checkSecretRef(r, ref); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.UpdateChannel(r.Context(), id, req.Name, req.Config, req.SecretRef, req.Enabled); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "channel.update", "channel", itoa(id), map[string]any{"name": req.Name, "enabled": req.Enabled})
	c, _ := s.Store.GetChannel(r.Context(), id)
	writeJSON(w, 200, c)
}

func (s *Server) deleteChannel(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.DeleteChannel(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "channel.delete", "channel", itoa(id), nil)
	w.WriteHeader(204)
}

func (s *Server) testChannel(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.Store.GetChannel(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.Dispatcher == nil {
		writeError(w, 503, "unavailable", "notifications are not running")
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "channel.test", "channel", itoa(id), nil)
	if err := s.Dispatcher.SendTest(r.Context(), c); err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

var priorities = map[string]bool{"P1": true, "P2": true, "P3": true, "P4": true}

func (s *Server) saveRoute(w http.ResponseWriter, r *http.Request, id int64) {
	var rt store.Route
	if err := decode(r, &rt); err != nil {
		s.fail(w, r, err)
		return
	}
	rt.ID = id
	rt.Name = strings.TrimSpace(rt.Name)
	if rt.Timezone == "" {
		rt.Timezone = "UTC"
	}
	if rt.MinPriority == "" {
		rt.MinPriority = "P2"
	}
	switch {
	case rt.Name == "":
		s.fail(w, r, badRequest("name is required"))
		return
	case !priorities[rt.MinPriority]:
		s.fail(w, r, badRequest("min_priority must be P1-P4"))
		return
	case !notify.ValidQuietTime(rt.QuietStart) || !notify.ValidQuietTime(rt.QuietEnd) || (rt.QuietStart == "") != (rt.QuietEnd == ""):
		s.fail(w, r, badRequest("quiet_start and quiet_end must both be HH:MM or both empty"))
		return
	case rt.MaxPerHour < 0 || rt.MaxPerHour > 1000:
		s.fail(w, r, badRequest("max_per_hour must be 0-1000 (0 = unlimited)"))
		return
	}
	if (len(rt.TeamIDs) > 0 || rt.Escalation) && !s.has(r, license.Teams) {
		planRequired(w, license.Teams)
		return
	}
	if _, err := time.LoadLocation(rt.Timezone); err != nil {
		s.fail(w, r, badRequest("unknown timezone"))
		return
	}
	for _, k := range rt.Kinds {
		switch k {
		case "vulnerability", "end_of_life", "feed", "collection", "coverage":
		default:
			s.fail(w, r, badRequest("kinds may contain vulnerability, end_of_life, feed, collection, coverage"))
			return
		}
	}
	out, err := s.Store.SaveRoute(r.Context(), rt)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	action := "route.update"
	if id == 0 {
		action = "route.create"
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), action, "route", itoa(out.ID), out)
	writeJSON(w, map[bool]int{true: 201, false: 200}[id == 0], out)
}

func (s *Server) listRoutes(w http.ResponseWriter, r *http.Request) {
	rs, err := s.Store.ListRoutes(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(rs))
}

func (s *Server) createRoute(w http.ResponseWriter, r *http.Request) { s.saveRoute(w, r, 0) }

func (s *Server) updateRoute(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.saveRoute(w, r, id)
}

func (s *Server) deleteRoute(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.DeleteRoute(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "route.delete", "route", itoa(id), nil)
	w.WriteHeader(204)
}

func (s *Server) listDeliveries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.DeliveryFilter{Status: q.Get("status"), IncidentID: qInt(r, "incident_id"), ChannelID: qInt(r, "channel_id"), Page: page(r)}
	items, total, err := s.Store.ListDeliveries(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, f.Page))
}

func (s *Server) retryDelivery(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.RetryDelivery(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "delivery.retry", "delivery", itoa(id), nil)
	w.WriteHeader(204)
}

// userDirectory lists active users for assignment pickers. It exposes only
// id, email and name, so engineers can assign without admin rights.
func (s *Server) userDirectory(w http.ResponseWriter, r *http.Request) {
	us, err := s.Store.ListUsers(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type entry struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	out := []entry{}
	for _, u := range us {
		if !u.Disabled {
			out = append(out, entry{u.ID, u.Email, u.Name})
		}
	}
	writeJSON(w, 200, all(out))
}
