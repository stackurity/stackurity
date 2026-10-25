package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/secrets"
)

// Stored secrets: credentials a workspace keeps for its own integrations and
// channels, referenced as secret:NAME. Values can be written and replaced but
// never read back through the API.

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) {
	out, err := s.Store.ListSecrets(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": nonNil(out), "enabled": s.SecretBox != nil})
}

func (s *Server) putSecret(w http.ResponseWriter, r *http.Request) {
	if s.SecretBox == nil {
		writeError(w, 409, "conflict", secrets.ErrNoKey.Error())
		return
	}
	name := chi.URLParam(r, "name")
	if !secrets.ValidName(name) {
		s.fail(w, r, badRequest("names use letters, digits, dot, dash and underscore (max 64)"))
		return
	}
	var req struct {
		Value string `json:"value"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	req.Value = strings.TrimSpace(req.Value)
	if req.Value == "" || len(req.Value) > 16<<10 {
		s.fail(w, r, badRequest("value is required (max 16 KiB)"))
		return
	}
	p := principal(r)
	var by int64
	if p.User != nil {
		by = p.User.ID
	}
	if err := s.Store.PutSecret(r.Context(), s.SecretBox, name, req.Value, by); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "secret.put", "secret", name, nil)
	w.WriteHeader(204)
}

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := s.Store.DeleteSecret(r.Context(), name); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "secret.delete", "secret", name, nil)
	w.WriteHeader(204)
}

func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}
