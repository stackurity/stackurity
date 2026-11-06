package api

import (
	"net/http"
	"slices"
	"strings"

	"github.com/stackurity/stackurity/internal/store"
)

// Saved views: a person's own named filters on a dashboard page (the
// Fixes page's Views menu). Each is the page's query string; nobody else
// lists or deletes them.

// savedViewOwner is the signed-in person in an organisation, or 403.
func savedViewOwner(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	p := principal(r)
	if p == nil || p.User == nil || p.Workspace <= 0 {
		writeError(w, 403, "forbidden", "saved views belong to a signed-in person in an organisation")
		return nil, false
	}
	return p, true
}

func savedViewPage(w http.ResponseWriter, r *http.Request, s *Server, page string) bool {
	if !slices.Contains(store.SavedViewPages, page) {
		s.fail(w, r, badRequest("page must be one of "+strings.Join(store.SavedViewPages, ", ")))
		return false
	}
	return true
}

// listSavedViews returns the caller's views on ?page= (default fixes).
func (s *Server) listSavedViews(w http.ResponseWriter, r *http.Request) {
	p, ok := savedViewOwner(w, r)
	if !ok {
		return
	}
	page := r.URL.Query().Get("page")
	if page == "" {
		page = "fixes"
	}
	if !savedViewPage(w, r, s, page) {
		return
	}
	vs, err := s.Store.ListSavedViews(r.Context(), p.User.ID, page)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(vs))
}

type saveViewRequest struct {
	Page  string `json:"page"`
	Name  string `json:"name"`
	Query string `json:"query"`
}

// saveView stores a view for the caller; the same name replaces its query.
func (s *Server) saveView(w http.ResponseWriter, r *http.Request) {
	p, ok := savedViewOwner(w, r)
	if !ok {
		return
	}
	var req saveViewRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Page == "" {
		req.Page = "fixes"
	}
	if !savedViewPage(w, r, s, req.Page) {
		return
	}
	v, err := s.Store.SaveView(r.Context(), p.User.ID, req.Page, req.Name, req.Query)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, v)
}

// deleteSavedView deletes one of the caller's views; another person's is
// not found.
func (s *Server) deleteSavedView(w http.ResponseWriter, r *http.Request) {
	p, ok := savedViewOwner(w, r)
	if !ok {
		return
	}
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.DeleteSavedView(r.Context(), p.User.ID, id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}
