package api

// Config findings (store/config_findings.go): risky settings collectors
// found in an asset's files, such as AI agent hooks that download and run
// code, SSH keys with an unrestricted root shell and unpinned GitHub
// Actions. Reading them is for anyone who can see the asset; dismissing
// one, like ignoring a finding, is for the security role. They are part of
// the free edition.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
)

func configFilter(r *http.Request) (store.ConfigFindingFilter, error) {
	q := r.URL.Query()
	f := store.ConfigFindingFilter{Status: q.Get("status"), Severity: q.Get("severity"), Category: q.Get("category"), Page: page(r)}
	if v := q.Get("asset_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id <= 0 {
			return f, badRequest("asset_id must be a number")
		}
		f.AssetID = id
	}
	return f, nil
}

// listConfigFindings: GET /config-findings, and GET
// /assets/{id}/config-findings with the asset's last config checks (none
// means it was never checked).
func (s *Server) listConfigFindings(w http.ResponseWriter, r *http.Request) {
	f, err := configFilter(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var scans *[]store.ConfigScan // only on an asset's list, where none means never checked
	if chi.URLParam(r, "id") != "" {
		if f.AssetID, err = idParam(r, "id"); err == nil {
			_, err = s.Store.GetAsset(r.Context(), f.AssetID)
		}
		var got []store.ConfigScan
		if err == nil {
			got, err = s.Store.ConfigScans(r.Context(), f.AssetID)
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if got == nil {
			got = []store.ConfigScan{}
		}
		scans = &got
	}
	items, total, err := s.Store.ListConfigFindings(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, struct {
		list[store.ConfigFinding]
		Scans *[]store.ConfigScan `json:"scans,omitempty"`
	}{paged(items, total, f.Page), scans})
}

// configSummary: GET /config-findings/summary, open findings by severity
// and category, and how many assets were checked at all.
func (s *Server) configSummary(w http.ResponseWriter, r *http.Request) {
	f, err := configFilter(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sum, err := s.Store.SummariseConfigFindings(r.Context(), f.AssetID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, sum)
}

// dismissConfigFinding and undismissConfigFinding: POST
// /config-findings/{id}/dismiss and /undismiss.
func (s *Server) dismissConfigFinding(w http.ResponseWriter, r *http.Request) {
	s.configAction(w, r, true)
}

func (s *Server) undismissConfigFinding(w http.ResponseWriter, r *http.Request) {
	s.configAction(w, r, false)
}

func (s *Server) configAction(w http.ResponseWriter, r *http.Request, dismiss bool) {
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
	if !s.configAllowed(w, r, id) {
		return
	}
	p := principal(r)
	var c *store.ConfigFinding
	action := "config_finding.dismiss"
	if dismiss {
		var by *int64
		if u := userID(p); u > 0 {
			by = &u
		}
		c, err = s.Store.DismissConfigFinding(r.Context(), id, by, req.Note)
	} else {
		action = "config_finding.undismiss"
		c, err = s.Store.UndismissConfigFinding(r.Context(), id)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), action, "config_finding", itoa(id), map[string]any{"asset_id": c.AssetID,
		"path": c.Path, "rule": c.Rule, "note": req.Note})
	writeJSON(w, 200, c)
}

// configAllowed checks the caller has the security role, organisation-wide
// or from a project grant on the finding's asset.
func (s *Server) configAllowed(w http.ResponseWriter, r *http.Request, id int64) bool {
	p := principal(r)
	if !auth.Higher(p.Role, p.ProjectRole).AtLeast(auth.RoleSecurity) {
		writeError(w, 403, "forbidden", "dismissing a config finding requires the "+string(auth.RoleSecurity)+" role")
		return false
	}
	if p.Role.AtLeast(auth.RoleSecurity) {
		return true
	}
	assets, err := s.Store.ConfigFindingAssets(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	if len(assets) == 0 {
		s.fail(w, r, store.ErrNotFound)
		return false
	}
	return s.requireOn(w, r, auth.RoleSecurity, assets...)
}
