package api_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

func init() {
	// Exceptions to policy gates (gate_exceptions.go): rows narrowed to the
	// caller's assets; asking needs viewer on the asset, deciding and
	// ending security on it.
	for r, rule := range map[string]routeRule{
		"GET /api/v1/gate-policies/exceptions":      {class: "list", query: "?status=all"},
		"GET /api/v1/gate-policies/exceptions/{id}": {class: "object", obj: id("gateexception")},
		"POST /api/v1/gate-policies/exceptions": {class: "create", body: func(a *tenantFx) any {
			return map[string]any{"policy_id": a.int("gatepolicy"), "asset_id": a.int("asset"), "target_kind": "asset",
				"reason": "mitigated", "note": "sweep"}
		}},
		"POST /api/v1/gate-policies/exceptions/{id}/decision": {class: "object", obj: id("gateexception"),
			body: func(*tenantFx) any { return map[string]any{"decision": "approve"} }},
		"POST /api/v1/gate-policies/exceptions/{id}/end": {class: "object", obj: id("gateexception"),
			body: func(*tenantFx) any { return map[string]any{"note": "sweep"} }},
	} {
		routeRules[r] = rule
	}
	for r, sc := range map[string]string{
		"GET /api/v1/gate-policies/exceptions":                "scoped",
		"GET /api/v1/gate-policies/exceptions/{id}":           "scoped",
		"POST /api/v1/gate-policies/exceptions":               "scoped-write",
		"POST /api/v1/gate-policies/exceptions/{id}/decision": "scoped-write",
		"POST /api/v1/gate-policies/exceptions/{id}/end":      "scoped-write",
	} {
		projectScopes[r] = sc
	}
}

type gateExceptionList struct {
	Items     []store.GateException `json:"items"`
	Total     int64                 `json:"total"`
	CanDecide bool                  `json:"can_decide"`
}

func TestGateExceptionsAPI(t *testing.T) {
	o := newOrg(t)
	e := o.e
	ws := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	// alpha-finding (CVE-2099-0001 on host-alpha) is known to be exploited.
	if _, err := e.st.Pool.Exec(ws, `UPDATE findings SET evidence = evidence || '{"known_exploited": true}' WHERE id = $1`, o.id("alpha-finding")); err != nil {
		t.Fatal(err)
	}
	var kev store.GatePolicy
	if code := o.admin.do("POST", "/api/v1/gate-policies", map[string]any{"name": "No KEV", "kind": "known_exploited"}, &kev); code != 201 {
		t.Fatalf("policy: %d", code)
	}
	violations := func() int {
		t.Helper()
		var vs gateViolations
		if code := o.admin.do("GET", "/api/v1/gate-policies/violations", nil, &vs); code != 200 {
			t.Fatalf("violations: %d", code)
		}
		return len(vs.Items)
	}
	if n := violations(); n != 1 {
		t.Fatalf("violations before: %d", n)
	}

	o.grant(t, "exc-viewer@x.io", o.id("alpha-project"), 0, auth.RoleViewer)
	o.grant(t, "exc-security@x.io", o.id("alpha-project"), 0, auth.RoleSecurity)
	pv, ps := e.signIn("exc-viewer@x.io"), e.signIn("exc-security@x.io")
	ask := map[string]any{"policy_id": kev.ID, "asset_id": o.id("alpha-asset"), "target_kind": "finding", "finding_id": o.id("alpha-finding"),
		"reason": "mitigated", "note": "A WAF rule blocks the exploit", "expires_at": time.Now().AddDate(0, 0, 20)}

	// A viewer on Alpha asks; not about Beta's asset; bad input is 400.
	beta := map[string]any{"policy_id": kev.ID, "asset_id": o.id("beta-asset"), "target_kind": "asset", "reason": "mitigated", "note": "x"}
	if code := pv.do("POST", "/api/v1/gate-policies/exceptions", beta, nil); code != 403 {
		t.Errorf("alpha viewer asks about beta: %d", code)
	}
	if code := pv.do("POST", "/api/v1/gate-policies/exceptions", map[string]any{"policy_id": kev.ID, "asset_id": o.id("alpha-asset"),
		"target_kind": "asset", "reason": "mitigated"}, nil); code != 400 {
		t.Errorf("no note: %d", code)
	}
	var x store.GateException
	if code := pv.do("POST", "/api/v1/gate-policies/exceptions", ask, &x); code != 201 || x.Status != "pending" || x.RequestedByName == "" {
		t.Fatalf("ask: %d %+v", code, x)
	}
	if code := pv.do("POST", "/api/v1/gate-policies/exceptions", ask, nil); code != 409 {
		t.Errorf("ask twice: %d", code)
	}
	if n := violations(); n != 1 {
		t.Errorf("a pending request takes the violation out: %d", n)
	}

	// The viewer sees it but cannot decide; Alpha's security decides.
	var list gateExceptionList
	if code := pv.do("GET", "/api/v1/gate-policies/exceptions", nil, &list); code != 200 || list.Total != 1 || list.CanDecide {
		t.Errorf("viewer's list: %d %+v", code, list)
	}
	if code := pv.do("POST", fmt.Sprintf("/api/v1/gate-policies/exceptions/%d/decision", x.ID), map[string]any{"decision": "approve"}, nil); code != 403 {
		t.Errorf("viewer decides: %d", code)
	}
	if code := ps.do("GET", "/api/v1/gate-policies/exceptions?status=pending", nil, &list); code != 200 || list.Total != 1 || !list.CanDecide {
		t.Errorf("security's inbox: %d %+v", code, list)
	}
	if code := ps.do("GET", "/api/v1/gate-policies/exceptions?status=maybe", nil, nil); code != 400 {
		t.Errorf("bad status: %d", code)
	}
	if code := ps.do("POST", fmt.Sprintf("/api/v1/gate-policies/exceptions/%d/decision", x.ID), map[string]any{"decision": "maybe"}, nil); code != 400 {
		t.Errorf("bad decision: %d", code)
	}
	if code := ps.do("POST", fmt.Sprintf("/api/v1/gate-policies/exceptions/%d/decision", x.ID), map[string]any{"decision": "approve", "note": "ok"}, &x); code != 200 ||
		x.Status != "approved" || x.ExpiresAt == nil {
		t.Fatalf("approve: %d %+v", code, x)
	}
	if n := violations(); n != 0 {
		t.Errorf("the approved exception leaves %d violations", n)
	}
	// The check honours it too.
	var check struct {
		Result string `json:"result"`
	}
	if code := o.admin.do("POST", "/api/v1/gate-policies/check", map[string]any{"asset_id": o.id("alpha-asset"), "dry_run": false}, &check); code != 200 || check.Result != "pass" {
		t.Errorf("check with the exception: %d %+v", code, check)
	}

	// End early: the violation returns.
	if code := pv.do("POST", fmt.Sprintf("/api/v1/gate-policies/exceptions/%d/end", x.ID), map[string]any{}, nil); code != 403 {
		t.Errorf("viewer ends: %d", code)
	}
	if code := ps.do("POST", fmt.Sprintf("/api/v1/gate-policies/exceptions/%d/end", x.ID), map[string]any{"note": "the WAF rule was removed"}, &x); code != 200 ||
		x.Status != "ended" || x.EndReason != "revoked" {
		t.Fatalf("end: %d %+v", code, x)
	}
	if n := violations(); n != 1 {
		t.Errorf("after the end: %d violations", n)
	}

	// Ask again and decline (a reason is required).
	var y store.GateException
	if code := pv.do("POST", "/api/v1/gate-policies/exceptions", ask, &y); code != 201 {
		t.Fatalf("ask again: %d", code)
	}
	if code := ps.do("POST", fmt.Sprintf("/api/v1/gate-policies/exceptions/%d/decision", y.ID), map[string]any{"decision": "decline"}, nil); code != 400 {
		t.Errorf("decline without a reason: %d", code)
	}
	if code := ps.do("POST", fmt.Sprintf("/api/v1/gate-policies/exceptions/%d/decision", y.ID), map[string]any{"decision": "decline", "note": "patch it"}, &y); code != 200 ||
		y.Status != "declined" {
		t.Fatalf("decline: %d %+v", code, y)
	}

	// An exception on Beta's asset, asked by the organisation's admin: not
	// seen, decided or ended by Alpha's members.
	var b store.GateException
	if code := o.admin.do("POST", "/api/v1/gate-policies/exceptions", beta, &b); code != 201 {
		t.Fatalf("beta exception: %d", code)
	}
	if code := ps.do("GET", fmt.Sprintf("/api/v1/gate-policies/exceptions/%d", b.ID), nil, nil); code != 404 {
		t.Errorf("alpha security reads beta's: %d", code)
	}
	if code := ps.do("POST", fmt.Sprintf("/api/v1/gate-policies/exceptions/%d/decision", b.ID), map[string]any{"decision": "approve"}, nil); code != 404 {
		t.Errorf("alpha security decides beta's: %d", code)
	}
	if code := ps.do("GET", "/api/v1/gate-policies/exceptions?status=all", nil, &list); code != 200 || list.Total != 2 {
		t.Errorf("alpha security's list: %d %+v", code, list)
	}
	if code := o.admin.do("GET", "/api/v1/gate-policies/exceptions?status=all&asset_id="+o.s("beta-asset"), nil, &list); code != 200 || list.Total != 1 {
		t.Errorf("admin's list for beta: %d %+v", code, list)
	}
	// One approver is enough, even the person who asked.
	if code := o.admin.do("POST", fmt.Sprintf("/api/v1/gate-policies/exceptions/%d/decision", b.ID), map[string]any{"decision": "approve"}, &b); code != 200 ||
		b.Status != "approved" {
		t.Errorf("admin approves their own request: %d %+v", code, b)
	}

	// Every step is in the audit log.
	var audit struct {
		Items []store.AuditEvent `json:"items"`
	}
	if code := o.admin.do("GET", "/api/v1/audit?limit=200", nil, &audit); code != 200 {
		t.Fatalf("audit: %d", code)
	}
	seen := map[string]bool{}
	for _, ev := range audit.Items {
		if strings.HasPrefix(ev.Action, "policy_exception.") {
			seen[ev.Action] = true
		}
	}
	for _, a := range []string{"policy_exception.request", "policy_exception.approve", "policy_exception.decline", "policy_exception.end"} {
		if !seen[a] {
			t.Errorf("no %s in the audit log (%v)", a, seen)
		}
	}
}
