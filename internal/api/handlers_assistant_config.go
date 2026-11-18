package api

// Risky settings in AI coding assistants' configuration files
// (store/assistant_config.go): hooks, MCP servers and tasks collectors
// found that run on their own and download or run code.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
)

// FeatureAssistantConfig, in GET /meta's features, says that POST /ingest
// stores a batch's assistant_config. Collectors send it only to servers
// that say so.
const FeatureAssistantConfig = "assistant_config"

func assistantFilter(r *http.Request) (store.AssistantFilter, error) {
	q := r.URL.Query()
	f := store.AssistantFilter{Status: q.Get("status"), Severity: q.Get("severity"), Page: page(r)}
	switch f.Status {
	case "", "open", "resolved", "all":
	default:
		return f, badRequest("status must be open, resolved or all")
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

// listAssistantFindings: GET /assistant-findings.
func (s *Server) listAssistantFindings(w http.ResponseWriter, r *http.Request) {
	f, err := assistantFilter(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, total, err := s.Store.ListAssistantFindings(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// How many assets were checked at all, so an empty list can say
	// whether that means none found or nothing checked yet.
	scanned, err := s.Store.AssistantScannedAssets(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, struct {
		list[store.AssistantFinding]
		ScannedAssets int64 `json:"scanned_assets"`
	}{paged(items, total, f.Page), scanned})
}

// assetAssistantFindings: GET /assets/{id}/assistant-findings, with the
// asset's last scans: none means it was never checked, which is not the
// same as clean.
func (s *Server) assetAssistantFindings(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.Store.GetAsset(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	f, err := assistantFilter(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f.AssetID = id
	items, total, err := s.Store.ListAssistantFindings(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	scans, err := s.Store.AssistantScans(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if scans == nil {
		scans = []store.AssistantScan{}
	}
	writeJSON(w, 200, struct {
		list[store.AssistantFinding]
		Scans []store.AssistantScan `json:"scans"`
	}{paged(items, total, f.Page), scans})
}

// dismissAssistantFinding and undismissAssistantFinding: POST
// /assistant-findings/{id}/dismiss and /undismiss.
func (s *Server) dismissAssistantFinding(w http.ResponseWriter, r *http.Request) {
	s.assistantAction(w, r, true)
}
func (s *Server) undismissAssistantFinding(w http.ResponseWriter, r *http.Request) {
	s.assistantAction(w, r, false)
}

func (s *Server) assistantAction(w http.ResponseWriter, r *http.Request, dismiss bool) {
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
	if !s.assistantAllowed(w, r, id, auth.RoleSecurity, "dismissing an AI assistant finding") {
		return
	}
	var f *store.AssistantFinding
	action := "assistant_finding.dismiss"
	if dismiss {
		var by *int64
		if u := userID(p); u > 0 {
			by = &u
		}
		f, err = s.Store.DismissAssistantFinding(r.Context(), id, by, req.Note)
	} else {
		action = "assistant_finding.undismiss"
		f, err = s.Store.UndismissAssistantFinding(r.Context(), id)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), action, "assistant_finding", itoa(id), map[string]any{"asset_id": f.AssetID,
		"path": f.Path, "rule": f.Rule, "setting": f.Setting, "note": req.Note})
	writeJSON(w, 200, f)
}

// assistantAllowed checks the caller has role, organisation-wide or from a
// project grant on the finding's asset; a finding the caller cannot see is
// not found.
func (s *Server) assistantAllowed(w http.ResponseWriter, r *http.Request, id int64, role auth.Role, what string) bool {
	p := principal(r)
	if !auth.Higher(p.Role, p.ProjectRole).AtLeast(role) {
		writeError(w, 403, "forbidden", what+" requires the "+string(role)+" role")
		return false
	}
	if p.Role.AtLeast(role) {
		return true
	}
	assets, err := s.Store.AssistantFindingAssets(r.Context(), id)
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
