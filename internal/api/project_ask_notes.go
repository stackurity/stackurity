package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/stackurity/stackurity/internal/ask"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// A project's notes for Ask Stackurity (store/project_ask_notes.go): a
// short text the project's admins write about it, which Ask reads as
// background when a question is about that project. Anyone who can see
// the project reads them (Ask shows them to the model on their behalf);
// admins of the project (an organisation-wide admin, or an admin grant on
// it) change them, in the dashboard only. Every change is in the audit
// log, with the old and new text.

// GET /projects/{id}/ask-notes
func (s *Server) getProjectAskNotes(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if p := principal(r); p.boundToProject() && id != *p.Assistant.ProjectID {
		writeError(w, 404, "not_found", "not found")
		return
	}
	n, err := s.Store.GetProjectAskNotes(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	role, err := s.scopeRole(r, &notifyScope{kind: "project", id: id})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"project_id": n.ProjectID, "notes": n.Notes, "updated_at": n.UpdatedAt,
		"max_chars": store.MaxProjectAskNotes, "can_edit": role.AtLeast(auth.RoleAdmin) && principal(r).Assistant == nil})
}

// PUT /projects/{id}/ask-notes {"notes"}
func (s *Server) putProjectAskNotes(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.Assistant != nil || p.Ask || p.ViaAsk {
		writeError(w, 403, "forbidden", "a project's notes for Ask are changed in the dashboard")
		return
	}
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		Notes *string `json:"notes"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Notes == nil {
		s.fail(w, r, badRequest("notes is required (an empty string clears them)"))
		return
	}
	// 404 for a project the caller cannot see, before the role check.
	if _, err := s.Store.GetProjectAskNotes(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	role, err := s.scopeRole(r, &notifyScope{kind: "project", id: id})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !role.AtLeast(auth.RoleAdmin) {
		writeError(w, 403, "forbidden", "requires role admin on this project")
		return
	}
	previous, err := s.Store.SetProjectAskNotes(r.Context(), id, *in.Notes)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	n, err := s.Store.GetProjectAskNotes(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if n.Notes != previous {
		_ = s.Store.Audit(r.Context(), p.Actor(r), "project.ask_notes_update", "project", itoa(id),
			map[string]any{"project": n.Name, "notes": n.Notes, "previous_notes": previous})
	}
	writeJSON(w, 200, map[string]any{"project_id": n.ProjectID, "notes": n.Notes, "updated_at": n.UpdatedAt,
		"max_chars": store.MaxProjectAskNotes, "can_edit": true})
}

// askProjectNotes returns the notes of the projects a question is about:
// the project chosen in the switcher; else, the projects of the asset the
// person has open; else, for a person with project access only, their
// projects. Read as the person, so they include only projects they can
// see. A failure leaves the notes out: Ask still answers.
func (s *Server) askProjectNotes(ctx context.Context, p *Principal, page *ask.PageRef) []ask.ProjectNote {
	var ids []int64
	switch {
	case p.Project > 0:
		ids = []int64{p.Project}
	case page != nil && page.Kind == "asset":
		assetID, err := strconv.ParseInt(page.ID, 10, 64)
		if err != nil || assetID <= 0 {
			return nil
		}
		pids, err := s.Store.AssetProjects(tenant.WithoutProject(ctx), assetID)
		if err != nil || len(pids) == 0 {
			return nil
		}
		ids = pids
	case p.Restricted:
		// Every project the person can see (row-level security).
	default:
		return nil
	}
	notes, err := s.Store.ProjectAskNotesFor(ctx, ids)
	if err != nil {
		s.Log.Warn("ask: reading project notes", "err", err)
		return nil
	}
	out := make([]ask.ProjectNote, 0, len(notes))
	for _, n := range notes {
		out = append(out, ask.ProjectNote{Project: n.Name, Text: n.Notes})
	}
	return out
}
