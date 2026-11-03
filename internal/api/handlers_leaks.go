package api

// Leaked keys (store/leaks.go): keys, tokens and passwords collectors found
// written in an asset's files. Reading them is for anyone who can see the
// asset; dismissing one, like ignoring a finding, is for the security role.

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
	f := store.LeakFilter{Status: q.Get("status"), Severity: q.Get("severity"), Page: page(r)}
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
	writeJSON(w, 200, paged(items, total, f.Page))
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
	if !auth.Higher(p.Role, p.ProjectRole).AtLeast(auth.RoleSecurity) {
		writeError(w, 403, "forbidden", "dismissing a leaked key requires the security role")
		return
	}
	// With the role from project grants only, it must be on the leak's
	// asset; a leak the caller cannot see is not found.
	if !p.Role.AtLeast(auth.RoleSecurity) {
		assets, err := s.Store.LeakAssets(r.Context(), id)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if len(assets) == 0 {
			s.fail(w, r, store.ErrNotFound)
			return
		}
		if !s.requireOn(w, r, auth.RoleSecurity, assets...) {
			return
		}
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
