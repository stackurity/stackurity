package api

import (
	"net/http"

	"github.com/stackurity/stackurity/internal/store"
)

// Owner rules (docs/design/owner-rules.md): who new issues are assigned to,
// by project, asset and tech stack. Organisation routes: members with
// project access only are refused.

func (s *Server) listOwnerRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.Store.ListOwnerRules(r.Context(), store.OwnerRuleFilter{AssetID: qInt(r, "asset_id"), ProjectID: qInt(r, "project_id")})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(rules))
}

func (s *Server) createOwnerRule(w http.ResponseWriter, r *http.Request) {
	s.saveOwnerRule(w, r, 0)
}

func (s *Server) updateOwnerRule(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.saveOwnerRule(w, r, id)
}

func (s *Server) saveOwnerRule(w http.ResponseWriter, r *http.Request, id int64) {
	var in store.OwnerRuleInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	p := principal(r)
	rule, err := s.Store.SaveOwnerRule(r.Context(), id, in, actorUserID(p))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	action, status := "owner_rule.update", 200
	if id == 0 {
		action, status = "owner_rule.create", 201
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), action, "owner_rule", itoa(rule.ID), rule)
	writeJSON(w, status, rule)
}

func (s *Server) deleteOwnerRule(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rule, err := s.Store.GetOwnerRule(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.DeleteOwnerRule(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "owner_rule.delete", "owner_rule", itoa(id), rule)
	w.WriteHeader(http.StatusNoContent)
}

// applyOwnerRules moves the open issues no person assigned to the owners
// the rules name today. dry_run=true (the default) only says what would
// move.
func (s *Server) applyOwnerRules(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DryRun *bool `json:"dry_run"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	dry := req.DryRun == nil || *req.DryRun
	plan, err := s.Store.ApplyOwnerRules(r.Context(), dry)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !dry {
		_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "owner_rule.apply", "owner_rule", "", map[string]any{"moved": plan.Total, "truncated": plan.Truncated})
	}
	writeJSON(w, 200, plan)
}
