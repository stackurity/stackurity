package api

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Policy gates (docs/design/policy-gates.md, docs/policy-gates.md): rules
// an organisation writes once and scopes like notifications. The
// organisation's policies are managed at /gate-policies (organisation-wide
// roles: security reads, admin changes); a project's or asset's at
// /projects/{id}/gate-policies and /assets/{id}/gate-policies, with the
// same roles on that project or asset (loadScopeFor), as notifications.
//
// Community edition: policies, scopes and violations. Enforce mode is
// stored here in every edition; the edition check for enforce comes with
// delivery step 4 (pro), which will refuse "enforce" without a licence in
// saveGatePolicy and ignore it in the check endpoint.

const gateScopeWhat = "policy gates"

// gatePolicyRequest is what a person sets on a policy. Its owner and the
// policy it copies are never taken from the request.
type gatePolicyRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Kind        string            `json:"kind"`
	Params      json.RawMessage   `json:"params"`
	Filters     store.GateFilters `json:"filters"`
	Mode        string            `json:"mode"`
}

// gatePolicyItem is a policy with where it is turned off: the design's
// "off for 2 projects".
type gatePolicyItem struct {
	store.GatePolicy
	OffProjects []int64 `json:"off_projects"`
	OffAssets   []int64 `json:"off_assets"`
}

func (s *Server) gatePolicyItems(r *http.Request, ps []store.GatePolicy) ([]gatePolicyItem, error) {
	ex, err := s.Store.GatePolicyExclusions(r.Context(), store.Owner{})
	if err != nil {
		return nil, err
	}
	out := make([]gatePolicyItem, 0, len(ps))
	for _, p := range ps {
		it := gatePolicyItem{GatePolicy: p, OffProjects: []int64{}, OffAssets: []int64{}}
		for _, e := range ex {
			if e.PolicyID != p.ID {
				continue
			}
			if e.ProjectID != nil {
				it.OffProjects = append(it.OffProjects, *e.ProjectID)
			} else if e.AssetID != nil {
				it.OffAssets = append(it.OffAssets, *e.AssetID)
			}
		}
		out = append(out, it)
	}
	return out, nil
}

func (s *Server) listGatePolicies(w http.ResponseWriter, r *http.Request) {
	ps, err := s.Store.ListGatePolicies(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := s.gatePolicyItems(r, ps)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": len(items), "kinds": store.GateKinds, "modes": store.GateModes})
}

func (s *Server) getGatePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p, err := s.Store.GetGatePolicy(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := s.gatePolicyItems(r, []store.GatePolicy{*p})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, items[0])
}

// listGateViolations: the violations of every policy that is not off,
// computed now, narrowed by policy_id, asset_id and project_id.
func (s *Server) listGateViolations(w http.ResponseWriter, r *http.Request) {
	f := store.GateViolationFilter{PolicyID: qInt(r, "policy_id"), AssetID: qInt(r, "asset_id"), ProjectID: qInt(r, "project_id")}
	vs, err := s.Store.GateViolations(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(vs))
}

func (s *Server) createGatePolicy(w http.ResponseWriter, r *http.Request) {
	s.saveGatePolicy(w, r, 0, nil)
}

func (s *Server) updateGatePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.saveGatePolicy(w, r, id, nil)
}

func (s *Server) deleteGatePolicy(w http.ResponseWriter, r *http.Request) {
	s.deleteGatePolicyAs(w, r, nil)
}

// saveGatePolicy creates (id 0) or replaces a policy of the organisation
// (sc nil) or of a project or asset. On a change, a mode left out keeps
// the policy's mode; a new policy starts in warn.
func (s *Server) saveGatePolicy(w http.ResponseWriter, r *http.Request, id int64, sc *notifyScope) {
	var req gatePolicyRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := r.Context()
	if sc != nil {
		ctx = tenant.WithoutProject(ctx)
	}
	p := store.GatePolicy{ID: id, Name: req.Name, Description: req.Description, Kind: req.Kind, Params: req.Params, Filters: req.Filters, Mode: req.Mode}
	// Enforce is accepted in every edition for now; delivery step 4 (pro)
	// makes it a paid mode (docs/design/policy-gates.md, section 7).
	actor := principal(r).Actor(r)
	if id == 0 {
		if sc != nil {
			p.OwnerProjectID, p.OwnerAssetID = sc.owner.ProjectID, sc.owner.AssetID
		}
		out, err := s.Store.CreateGatePolicy(ctx, p, actor)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		writeJSON(w, 201, out)
		return
	}
	cur, err := s.Store.GetGatePolicy(ctx, id)
	if err == nil && sc != nil && !cur.Owner().Same(sc.owner) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if p.Mode == "" {
		p.Mode = cur.Mode
	}
	out, err := s.Store.UpdateGatePolicy(ctx, p, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) deleteGatePolicyAs(w http.ResponseWriter, r *http.Request, sc *notifyScope) {
	param, ctx := "id", r.Context()
	if sc != nil {
		param, ctx = "pid", tenant.WithoutProject(ctx)
	}
	id, err := idParam(r, param)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if sc != nil {
		cur, err := s.Store.GetGatePolicy(ctx, id)
		if err == nil && !cur.Owner().Same(sc.owner) {
			err = store.ErrNotFound
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if err := s.Store.DeleteGatePolicy(ctx, id, principal(r).Actor(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}

// inheritedGatePolicy is a policy a project or asset inherits, and what it
// did with it here: on, off (turned off) or edit (replaced by CopyID).
type inheritedGatePolicy struct {
	store.GatePolicy
	// From: "organisation", or "project" (an asset's project, OwnerProjectID).
	From   string `json:"from"`
	State  string `json:"state"`
	CopyID *int64 `json:"copy_id,omitempty"`
}

// inheritedGatePolicies lists the policies the scope inherits: the
// organisation's, and for an asset its active projects' too.
func inheritedGatePolicies(sc *notifyScope, ps []store.GatePolicy) []store.GatePolicy {
	var out []store.GatePolicy
	for _, p := range ps {
		switch {
		case p.Owner().Org():
		case sc.kind == "asset" && p.OwnerProjectID != nil && slices.Contains(sc.projects, *p.OwnerProjectID):
		default:
			continue
		}
		out = append(out, p)
	}
	return out
}

func (s *Server) getScopeGatePolicies(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.loadScopeFor(w, r, false, gateScopeWhat)
	if !ok {
		return
	}
	s.writeScopeGatePolicies(w, r, sc, 200)
}

func (s *Server) writeScopeGatePolicies(w http.ResponseWriter, r *http.Request, sc *notifyScope, status int) {
	ctx := tenant.WithoutProject(r.Context())
	ps, err := s.Store.ListGatePolicies(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	excl, err := s.Store.GatePolicyExclusions(ctx, sc.owner)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	off := map[int64]bool{}
	for _, e := range excl {
		off[e.PolicyID] = true
	}
	mine := []store.GatePolicy{}
	copies := map[int64]int64{}
	for _, p := range ps {
		if p.Owner().Same(sc.owner) {
			mine = append(mine, p)
			if p.InheritsPolicyID != nil {
				copies[*p.InheritsPolicyID] = p.ID
			}
		}
	}
	inh := []inheritedGatePolicy{}
	for _, p := range inheritedGatePolicies(sc, ps) {
		ip := inheritedGatePolicy{GatePolicy: p, From: "organisation", State: "on"}
		if p.OwnerProjectID != nil {
			ip.From = "project"
		}
		if id, ok := copies[p.ID]; ok {
			ip.State, ip.CopyID = "edit", &id
		} else if off[p.ID] {
			ip.State = "off"
		}
		inh = append(inh, ip)
	}
	writeJSON(w, status, map[string]any{
		"scope":      map[string]any{"kind": sc.kind, "id": sc.id, "name": sc.name, "project_ids": sc.projects},
		"can_manage": sc.manage,
		"inherited":  inh,
		"policies":   mine,
	})
}

func (s *Server) createScopeGatePolicy(w http.ResponseWriter, r *http.Request) {
	if sc, ok := s.loadScopeFor(w, r, true, gateScopeWhat); ok {
		s.saveGatePolicy(w, r, 0, sc)
	}
}

func (s *Server) updateScopeGatePolicy(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.loadScopeFor(w, r, true, gateScopeWhat)
	if !ok {
		return
	}
	id, err := idParam(r, "pid")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.saveGatePolicy(w, r, id, sc)
}

func (s *Server) deleteScopeGatePolicy(w http.ResponseWriter, r *http.Request) {
	if sc, ok := s.loadScopeFor(w, r, true, gateScopeWhat); ok {
		s.deleteGatePolicyAs(w, r, sc)
	}
}

// setInheritedGatePolicy turns an inherited policy on or off for the
// project or asset, or replaces it with the project's or asset's own copy
// ("edit"). Turning it on again removes the copy. Every change is audited
// by the store.
func (s *Server) setInheritedGatePolicy(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.loadScopeFor(w, r, true, gateScopeWhat)
	if !ok {
		return
	}
	pid, err := idParam(r, "pid")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		State string `json:"state"` // on, off or edit
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := tenant.WithoutProject(r.Context())
	ps, err := s.Store.ListGatePolicies(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var p *store.GatePolicy
	for _, x := range inheritedGatePolicies(sc, ps) {
		if x.ID == pid {
			p = &x
			break
		}
	}
	if p == nil {
		s.fail(w, r, store.ErrNotFound)
		return
	}
	var copyID int64
	for _, x := range ps {
		if x.InheritsPolicyID != nil && *x.InheritsPolicyID == pid && x.Owner().Same(sc.owner) {
			copyID = x.ID
		}
	}
	actor := principal(r).Actor(r)
	switch req.State {
	case "off":
		if copyID > 0 {
			s.fail(w, r, badRequest("this policy was edited here: delete the edited copy, or turn it back on, first"))
			return
		}
		err = s.Store.SetGatePolicyExcluded(ctx, pid, sc.owner, true, actor)
	case "on":
		if copyID > 0 {
			err = s.Store.DeleteGatePolicy(ctx, copyID, actor)
		} else {
			err = s.Store.SetGatePolicyExcluded(ctx, pid, sc.owner, false, actor)
		}
	case "edit":
		if copyID > 0 {
			break
		}
		cp := *p
		cp.ID, cp.OwnerProjectID, cp.OwnerAssetID, cp.InheritsPolicyID = 0, sc.owner.ProjectID, sc.owner.AssetID, &pid
		_, err = s.Store.CustomiseGatePolicy(ctx, cp, actor)
	default:
		err = badRequest("state must be on, off or edit")
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeScopeGatePolicies(w, r, sc, 200)
}
