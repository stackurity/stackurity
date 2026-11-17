package api

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
)

// Exceptions to policy gates (docs/design/policy-gates.md, section 6;
// docs/policy-gates.md, "Exceptions"): anyone who can see an asset may ask
// for a policy not to count against it (or one component, finding or
// leaked key on it) until a date; a security or admin user of the asset
// approves or declines, and may end an approved exception early. Roles
// follow ignore requests (canDecide). Every step is audited as
// policy_exception.request, .approve, .decline and .end.
//
// The Community edition has the basic workflow: one approver, who may be
// the person who asked. The licensed build adds the workflow extras
// (section 7) by replacing gateExceptionPolicy.

// gateExceptionRules are the exception workflow's extra rules.
type gateExceptionRules struct {
	// SecondApprover: the person who asked may not decide their own
	// request.
	SecondApprover bool
	// MayDecide, when set, is asked after the role checks whether the
	// caller may decide this request (approver groups); a non-nil error
	// is the answer (an *apiError for 403).
	MayDecide func(r *http.Request, x *store.GateException) error
}

// gateExceptionPolicy returns the exception workflow's rules for the
// workspace in ctx. The Community edition has none: one approver with
// security or admin on the asset decides. The licensed build replaces it
// (a second approver, approver groups); it also runs expiry reminders on
// its own.
var gateExceptionPolicy = func(ctx context.Context) gateExceptionRules { return gateExceptionRules{} }

type gateExceptionBody struct {
	PolicyID     int64      `json:"policy_id"`
	AssetID      int64      `json:"asset_id"`
	TargetKind   string     `json:"target_kind"`
	FindingID    *int64     `json:"finding_id"`
	LeakID       *int64     `json:"leak_id"`
	ComponentKey string     `json:"component_key"`
	Reason       string     `json:"reason"`
	Note         string     `json:"note"`
	ExpiresAt    *time.Time `json:"expires_at"`
}

// listGateExceptions: status (pending, approved, declined, ended or all,
// the default), policy_id and asset_id. Rows are narrowed to the assets
// the caller can see.
func (s *Server) listGateExceptions(w http.ResponseWriter, r *http.Request) {
	f := store.GateExceptionFilter{Status: r.URL.Query().Get("status"), PolicyID: qInt(r, "policy_id"), AssetID: qInt(r, "asset_id"), Page: page(r)}
	if f.Status == "all" {
		f.Status = ""
	}
	if f.Status != "" && !slices.Contains(store.GateExceptionStatuses, f.Status) {
		s.fail(w, r, badRequest("status must be pending, approved, declined, ended or all"))
		return
	}
	items, total, err := s.Store.ListGateExceptions(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := paged(items, total, f.Page)
	writeJSON(w, 200, map[string]any{"items": p.Items, "total": p.Total, "limit": p.Limit, "offset": p.Offset, "can_decide": canDecide(r),
		"second_approver": gateExceptionPolicy(r.Context()).SecondApprover})
}

func (s *Server) getGateException(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	x, err := s.Store.GetGateException(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, x)
}

// requestGateException: anyone who can see the asset may ask.
func (s *Server) requestGateException(w http.ResponseWriter, r *http.Request) {
	var b gateExceptionBody
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	if b.PolicyID <= 0 || b.AssetID <= 0 {
		s.fail(w, r, badRequest("policy_id and asset_id are required"))
		return
	}
	if !s.requireOn(w, r, auth.RoleViewer, b.AssetID) {
		return
	}
	maxDays, err := s.exceptionMaxDays(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	actor := principal(r).Actor(r)
	x, err := s.Store.RequestGateException(r.Context(), store.GateExceptionRequest{PolicyID: b.PolicyID, AssetID: b.AssetID,
		TargetKind: b.TargetKind, FindingID: b.FindingID, LeakID: b.LeakID, ComponentKey: b.ComponentKey, Reason: b.Reason,
		Note: b.Note, ExpiresAt: b.ExpiresAt}, maxDays, actor)
	if err != nil {
		s.failAction(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), actor, "policy_exception.request", "policy_exception", itoa(x.ID), map[string]any{
		"policy_id": x.PolicyID, "policy": x.PolicyName, "asset_id": x.AssetID, "target_kind": x.TargetKind, "target": x.TargetLabel,
		"reason": x.Reason, "note": x.Note, "requested_expires_at": x.RequestedExpiresAt})
	writeJSON(w, 201, x)
}

// gateExceptionDecider loads an exception and checks that the caller may
// decide or end it: security or admin on its asset (canDecide), and the
// workflow's extra rules.
func (s *Server) gateExceptionDecider(w http.ResponseWriter, r *http.Request, deciding bool) (*store.GateException, bool) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	x, err := s.Store.GetGateException(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	if !s.requireOn(w, r, auth.RoleSecurity, x.AssetID) {
		return nil, false
	}
	if !deciding {
		return x, true
	}
	rules := gateExceptionPolicy(r.Context())
	if p := principal(r); rules.SecondApprover && p.User != nil && x.RequestedBy != nil && *x.RequestedBy == p.User.ID {
		writeError(w, 403, "second_approver_required", "someone other than the person who asked must decide this request")
		return nil, false
	}
	if rules.MayDecide != nil {
		if err := rules.MayDecide(r, x); err != nil {
			s.fail(w, r, err)
			return nil, false
		}
	}
	return x, true
}

// decideGateException: {"decision": "approve"|"decline", "note",
// "expires_at"}. A decline needs a note; an approval ends at expires_at,
// else at the date asked for, else at the risk policy's limit, and never
// later than the limit.
func (s *Server) decideGateException(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Decision  string     `json:"decision"`
		Note      string     `json:"note"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	if b.Decision != "approve" && b.Decision != "decline" {
		s.fail(w, r, badRequest("decision must be approve or decline"))
		return
	}
	cur, ok := s.gateExceptionDecider(w, r, true)
	if !ok {
		return
	}
	maxDays, err := s.exceptionMaxDays(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	actor := principal(r).Actor(r)
	x, err := s.Store.DecideGateException(r.Context(), cur.ID, b.Decision == "approve", b.Note, b.ExpiresAt, maxDays, actor)
	if err != nil {
		s.failAction(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), actor, "policy_exception."+b.Decision, "policy_exception", itoa(x.ID), map[string]any{
		"policy_id": x.PolicyID, "policy": x.PolicyName, "asset_id": x.AssetID, "target": x.TargetLabel, "note": x.DecisionNote,
		"requested_by": x.RequestedByName, "requested_expires_at": x.RequestedExpiresAt, "expires_at": x.ExpiresAt})
	writeJSON(w, 200, x)
}

// endGateException ends an approved exception early: {"note"}.
func (s *Server) endGateException(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Note string `json:"note"`
	}
	if r.ContentLength != 0 {
		if err := decode(r, &b); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	cur, ok := s.gateExceptionDecider(w, r, false)
	if !ok {
		return
	}
	actor := principal(r).Actor(r)
	x, err := s.Store.EndGateException(r.Context(), cur.ID, strings.TrimSpace(b.Note), actor)
	if err != nil {
		s.failAction(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), actor, "policy_exception.end", "policy_exception", itoa(x.ID), map[string]any{
		"policy_id": x.PolicyID, "policy": x.PolicyName, "asset_id": x.AssetID, "target": x.TargetLabel, "note": x.EndNote,
		"expires_at": x.ExpiresAt})
	writeJSON(w, 200, x)
}
