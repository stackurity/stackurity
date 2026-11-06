package api

// Leaked keys (store/leaks.go): keys, tokens and passwords collectors found
// written in an asset's files. Reading them is for anyone who can see the
// asset; dismissing one, like ignoring a finding, is for the security role.
// Assigning one, marking it rotated and asking for a check again are for the
// engineer role, like assigning a finding and Check again: none of them
// resolves the leak, which only a complete scan that no longer sees the key
// does.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
)

// FeatureLeaks, in GET /meta's features, says that POST /ingest stores a
// batch's leaks. Collectors send them only to servers that say so.
const FeatureLeaks = "leaks"

func leakFilter(r *http.Request) (store.LeakFilter, error) {
	q := r.URL.Query()
	f := store.LeakFilter{Status: q.Get("status"), Severity: q.Get("severity"), State: q.Get("state"),
		AssigneeUser: qInt(r, "assignee_user"), AssigneeTeam: qInt(r, "assignee_team"), Unassigned: q.Get("assignee") == "none", Page: page(r)}
	switch f.State {
	case "", "overdue", store.LeakNeedsRotation, store.LeakWaitingCheck, store.LeakStillFound, store.LeakVerifiedGone, store.LeakDismissed:
	default:
		return f, badRequest("state must be needs_rotation, waiting_check, still_found, verified_gone, dismissed or overdue")
	}
	if f.Severity != "" {
		for _, sev := range strings.Split(f.Severity, ",") {
			switch sev {
			case "critical", "high", "medium", "low":
			default:
				return f, badRequest("severity must be critical, high, medium or low, or several comma-separated")
			}
		}
	}
	if v := q.Get("asset_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id <= 0 {
			return f, badRequest("asset_id must be a number")
		}
		f.AssetID = id
	}
	return f, nil
}

func (s *Server) listLeaks(w http.ResponseWriter, r *http.Request) {
	f, err := leakFilter(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, total, err := s.Store.ListLeaks(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// How many assets were scanned at all, so an empty list can say
	// whether that means none found or nothing checked yet.
	scanned, err := s.Store.LeakScannedAssets(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, struct {
		list[store.Leak]
		ScannedAssets int64 `json:"scanned_assets"`
	}{paged(items, total, f.Page), scanned})
}

// assetLeaks lists one asset's leaks, with its last key scans: no scan
// means its files were never checked, which is not the same as no leaks.
func (s *Server) assetLeaks(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.Store.GetAsset(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	f, err := leakFilter(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f.AssetID = id
	items, total, err := s.Store.ListLeaks(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	scans, err := s.Store.LeakScans(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if scans == nil {
		scans = []store.LeakScan{}
	}
	writeJSON(w, 200, struct {
		list[store.Leak]
		Scans []store.LeakScan `json:"scans"`
	}{paged(items, total, f.Page), scans})
}

// dismissLeak and undismissLeak: POST /leaks/{id}/dismiss and
// /leaks/{id}/undismiss.
func (s *Server) dismissLeak(w http.ResponseWriter, r *http.Request)   { s.leakAction(w, r, true) }
func (s *Server) undismissLeak(w http.ResponseWriter, r *http.Request) { s.leakAction(w, r, false) }

func (s *Server) leakAction(w http.ResponseWriter, r *http.Request, dismiss bool) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			s.fail(w, r, badRequest("body must be JSON: {\"note\": \"...\"}"))
			return
		}
	}
	req.Note = strings.TrimSpace(req.Note)
	if len(req.Note) > 1000 {
		s.fail(w, r, badRequest("note is limited to 1000 characters"))
		return
	}
	p := principal(r)
	if !s.leakAllowed(w, r, id, auth.RoleSecurity, "dismissing a leaked key") {
		return
	}
	var l *store.Leak
	action := "leak.dismiss"
	if dismiss {
		var by *int64
		if u := userID(p); u > 0 {
			by = &u
		}
		l, err = s.Store.DismissLeak(r.Context(), id, by, req.Note)
	} else {
		action = "leak.undismiss"
		l, err = s.Store.UndismissLeak(r.Context(), id)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), action, "leak", itoa(id), map[string]any{"asset_id": l.AssetID, "path": l.Path,
		"rule": l.Rule, "note": req.Note})
	writeJSON(w, 200, l)
}

// leakAllowed checks the caller has role, organisation-wide or from a
// project grant on the leak's asset; a leak the caller cannot see is not
// found.
func (s *Server) leakAllowed(w http.ResponseWriter, r *http.Request, id int64, role auth.Role, what string) bool {
	p := principal(r)
	if !auth.Higher(p.Role, p.ProjectRole).AtLeast(role) {
		writeError(w, 403, "forbidden", what+" requires the "+string(role)+" role")
		return false
	}
	if p.Role.AtLeast(role) {
		return true
	}
	assets, err := s.Store.LeakAssets(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	if len(assets) == 0 {
		s.fail(w, r, store.ErrNotFound)
		return false
	}
	return s.requireOn(w, r, role, assets...)
}

// leakSummary: GET /leaks/summary, counts for the summary strip, the Fixes
// page and the dashboard, with the list's asset_id and severity.
func (s *Server) leakSummary(w http.ResponseWriter, r *http.Request) {
	f, err := leakFilter(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sum, err := s.Store.SummariseLeaks(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, sum)
}

// assignLeak: POST /leaks/{id}/assign {"user_id", "team_id"}; 0 clears one,
// a field left out keeps it.
func (s *Server) assignLeak(w http.ResponseWriter, r *http.Request) {
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
	if req.UserID == nil && req.TeamID == nil {
		s.fail(w, r, badRequest("user_id or team_id is required (0 clears it)"))
		return
	}
	if !s.leakAllowed(w, r, id, auth.RoleEngineer, "assigning a leaked key") || !s.assigneesAllowed(w, r, req) {
		return
	}
	l, err := s.Store.AssignLeak(r.Context(), id, req.UserID, req.TeamID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "leak.assign", "leak", itoa(id), map[string]any{"asset_id": l.AssetID,
		"path": l.Path, "rule": l.Rule, "user_id": req.UserID, "team_id": req.TeamID})
	writeJSON(w, 200, l)
}

// leakRotated: POST /leaks/{id}/rotated {"note"}: "I've revoked it and
// issued a new one". The leak stays open until a complete scan no longer
// sees the key; a check of its asset is asked for when check is true.
func (s *Server) leakRotated(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Note  string `json:"note"`
		Check bool   `json:"check"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			s.fail(w, r, badRequest("body must be JSON: {\"note\": \"...\", \"check\": true}"))
			return
		}
	}
	req.Note = strings.TrimSpace(req.Note)
	if len(req.Note) > 1000 {
		s.fail(w, r, badRequest("note is limited to 1000 characters"))
		return
	}
	if !s.leakAllowed(w, r, id, auth.RoleEngineer, "marking a leaked key rotated") {
		return
	}
	p := principal(r)
	var by *int64
	if u := userID(p); u > 0 {
		by = &u
	}
	l, err := s.Store.MarkLeakRotated(r.Context(), id, by, req.Note)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "leak.rotated", "leak", itoa(id), map[string]any{"asset_id": l.AssetID, "path": l.Path,
		"rule": l.Rule, "note": req.Note})
	resp := map[string]any{"leak": l}
	if req.Check {
		// The rotation is recorded either way; a check that cannot start
		// (the plan's cooldown) says why without undoing it.
		c, _, err := s.startCheck(r, store.CheckRequest{AssetID: l.AssetID, Cooldown: true})
		if err != nil {
			resp["check_error"] = err.Error()
		} else {
			resp["check"] = c
		}
	}
	writeJSON(w, 200, resp)
}

// leakCheckAgain: POST /leaks/{id}/check-again asks the leak's asset to be
// scanned again (the asset's Check again): its agent, integration or next
// upload. A complete scan that no longer sees the key verifies it gone.
func (s *Server) leakCheckAgain(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.leakAllowed(w, r, id, auth.RoleEngineer, "checking a leaked key again") {
		return
	}
	l, err := s.Store.GetLeak(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, created, err := s.startCheck(r, store.CheckRequest{AssetID: l.AssetID, Cooldown: true})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "leak.check_again", "leak", itoa(id), map[string]any{"asset_id": l.AssetID,
		"check_id": c.ID})
	writeJSON(w, map[bool]int{true: 201, false: 200}[created], c)
}
