package api_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

func init() {
	// Policy gates (gate_policies.go): the organisation's policies and
	// violations (organisation roles only), and a project's or asset's
	// policies (security on it reads, admin on it changes).
	scope := func(kind string) map[string]string { return map[string]string{"id": kind, "pid": "gatepolicy"} }
	body := func(*tenantFx) any { return map[string]any{"name": "sweep", "kind": "known_exploited"} }
	for r, rule := range map[string]routeRule{
		"GET /api/v1/gate-policies":                               {class: "list"},
		"GET /api/v1/gate-policies/violations":                    {class: "list"},
		"POST /api/v1/gate-policies":                              {class: "create", body: body},
		"GET /api/v1/gate-policies/{id}":                          {class: "object", obj: id("gatepolicy")},
		"PUT /api/v1/gate-policies/{id}":                          {class: "object", obj: id("gatepolicy"), body: body},
		"DELETE /api/v1/gate-policies/{id}":                       {class: "object", obj: id("gatepolicy")},
		"GET /api/v1/projects/{id}/gate-policies":                 {class: "object", obj: id("project")},
		"POST /api/v1/projects/{id}/gate-policies":                {class: "object", obj: id("project"), body: body},
		"PUT /api/v1/projects/{id}/gate-policies/{pid}":           {class: "object", obj: scope("project"), body: body},
		"DELETE /api/v1/projects/{id}/gate-policies/{pid}":        {class: "object", obj: scope("project")},
		"PUT /api/v1/projects/{id}/gate-policies/inherited/{pid}": {class: "object", obj: scope("project"), body: func(*tenantFx) any { return map[string]any{"state": "off"} }},
		"GET /api/v1/assets/{id}/gate-policies":                   {class: "object", obj: id("asset")},
		"POST /api/v1/assets/{id}/gate-policies":                  {class: "object", obj: id("asset"), body: body},
		"PUT /api/v1/assets/{id}/gate-policies/{pid}":             {class: "object", obj: scope("asset"), body: body},
		"DELETE /api/v1/assets/{id}/gate-policies/{pid}":          {class: "object", obj: scope("asset")},
		"PUT /api/v1/assets/{id}/gate-policies/inherited/{pid}":   {class: "object", obj: scope("asset"), body: func(*tenantFx) any { return map[string]any{"state": "off"} }},
	} {
		routeRules[r] = rule
	}
	for r, sc := range map[string]string{
		"GET /api/v1/gate-policies":                               "org",
		"GET /api/v1/gate-policies/violations":                    "org",
		"POST /api/v1/gate-policies":                              "org",
		"GET /api/v1/gate-policies/{id}":                          "org",
		"PUT /api/v1/gate-policies/{id}":                          "org",
		"DELETE /api/v1/gate-policies/{id}":                       "org",
		"GET /api/v1/projects/{id}/gate-policies":                 "scoped",
		"POST /api/v1/projects/{id}/gate-policies":                "scoped-write",
		"PUT /api/v1/projects/{id}/gate-policies/{pid}":           "scoped-write",
		"DELETE /api/v1/projects/{id}/gate-policies/{pid}":        "scoped-write",
		"PUT /api/v1/projects/{id}/gate-policies/inherited/{pid}": "scoped-write",
		"GET /api/v1/assets/{id}/gate-policies":                   "scoped",
		"POST /api/v1/assets/{id}/gate-policies":                  "scoped-write",
		"PUT /api/v1/assets/{id}/gate-policies/{pid}":             "scoped-write",
		"DELETE /api/v1/assets/{id}/gate-policies/{pid}":          "scoped-write",
		"PUT /api/v1/assets/{id}/gate-policies/inherited/{pid}":   "scoped-write",
	} {
		projectScopes[r] = sc
	}
}

type gateScopeView struct {
	CanManage bool `json:"can_manage"`
	Inherited []struct {
		ID     int64  `json:"id"`
		From   string `json:"from"`
		State  string `json:"state"`
		CopyID *int64 `json:"copy_id"`
	} `json:"inherited"`
	Policies []store.GatePolicy `json:"policies"`
}

func (v gateScopeView) state(id int64) string {
	for _, p := range v.Inherited {
		if p.ID == id {
			return p.State
		}
	}
	return "absent"
}

type gateViolations struct {
	Items []store.GateViolation `json:"items"`
}

func TestGatePoliciesAPI(t *testing.T) {
	o := newOrg(t)
	e := o.e
	ws := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	alpha := o.s("alpha-project")
	base := "/api/v1/projects/" + alpha + "/gate-policies"

	// alpha-finding (CVE-2099-0001 on host-alpha) is known to be exploited.
	if _, err := e.st.Pool.Exec(ws, `UPDATE findings SET evidence = evidence || '{"known_exploited": true}' WHERE id = $1`, o.id("alpha-finding")); err != nil {
		t.Fatal(err)
	}

	// The organisation's policy: validation, a new policy starts in warn.
	for _, bad := range []map[string]any{
		{"name": "x", "kind": "nope"},
		{"name": "x", "kind": "finding_age", "params": map[string]any{"min_severity": "high"}},
		{"name": "x", "kind": "known_exploited", "mode": "block"},
		{"name": "x", "kind": "known_exploited", "owner_project_id": 1},
	} {
		if code := o.admin.do("POST", "/api/v1/gate-policies", bad, nil); code != 400 {
			t.Errorf("create %v: %d, want 400", bad, code)
		}
	}
	var kev store.GatePolicy
	if code := o.admin.do("POST", "/api/v1/gate-policies", map[string]any{"name": "No KEV", "kind": "known_exploited"}, &kev); code != 201 ||
		kev.Mode != "warn" || kev.OwnerProjectID != nil {
		t.Fatalf("create: %d %+v", code, kev)
	}
	if code := o.admin.do("POST", "/api/v1/gate-policies", map[string]any{"name": "No KEV", "kind": "known_exploited"}, nil); code != 409 {
		t.Errorf("same name: %d", code)
	}
	var vs gateViolations
	if code := o.admin.do("GET", "/api/v1/gate-policies/violations", nil, &vs); code != 200 {
		t.Fatalf("violations: %d", code)
	}
	if len(vs.Items) != 1 || vs.Items[0].AssetID != o.id("alpha-asset") || vs.Items[0].PolicyID != kev.ID ||
		!strings.HasPrefix(vs.Items[0].Reason, "CVE-2099-0001 in alpha-private-lib 1.0.0 is known to be exploited") {
		t.Fatalf("violations: %+v", vs.Items)
	}
	if code := o.admin.do("GET", fmt.Sprintf("/api/v1/gate-policies/violations?project_id=%s", o.s("beta-project")), nil, &vs); code != 200 || len(vs.Items) != 0 {
		t.Errorf("beta's violations: %d %+v", code, vs.Items)
	}
	// Enforce is accepted (the edition gate comes in step 4); a PUT that
	// leaves the mode out keeps it.
	if code := o.admin.do("PUT", fmt.Sprintf("/api/v1/gate-policies/%d", kev.ID), map[string]any{"name": "No KEV", "kind": "known_exploited", "mode": "enforce"}, &kev); code != 200 || kev.Mode != "enforce" {
		t.Fatalf("enforce: %d %+v", code, kev)
	}
	if code := o.admin.do("PUT", fmt.Sprintf("/api/v1/gate-policies/%d", kev.ID), map[string]any{"name": "No known exploited", "kind": "known_exploited"}, &kev); code != 200 ||
		kev.Mode != "enforce" || kev.Name != "No known exploited" {
		t.Fatalf("rename: %d %+v", code, kev)
	}

	// Who may read and change Alpha's policy gates.
	o.grant(t, "gate-admin@x.io", o.id("alpha-project"), 0, auth.RoleAdmin)
	o.grant(t, "gate-security@x.io", o.id("alpha-project"), 0, auth.RoleSecurity)
	o.grant(t, "gate-engineer@x.io", o.id("alpha-project"), 0, auth.RoleEngineer)
	pa, ps, pe := e.signIn("gate-admin@x.io"), e.signIn("gate-security@x.io"), e.signIn("gate-engineer@x.io")
	var view gateScopeView
	if code := pa.do("GET", base, nil, &view); code != 200 || !view.CanManage || view.state(kev.ID) != "on" {
		t.Fatalf("alpha admin reads: %d %+v", code, view)
	}
	if code := ps.do("GET", base, nil, &view); code != 200 || view.CanManage {
		t.Fatalf("alpha security reads: %d %+v", code, view)
	}
	if code := pe.do("GET", base, nil, nil); code != 403 {
		t.Errorf("alpha engineer reads: %d", code)
	}
	if code := ps.do("PUT", base+fmt.Sprintf("/inherited/%d", kev.ID), map[string]string{"state": "off"}, nil); code != 403 {
		t.Errorf("security turns off: %d", code)
	}
	for _, s := range []*session{pa, ps} {
		if code := s.do("GET", "/api/v1/gate-policies", nil, nil); code != 403 {
			t.Errorf("project member on the organisation's policies: %d", code)
		}
		if code := s.do("GET", "/api/v1/gate-policies/violations", nil, nil); code != 403 {
			t.Errorf("project member on the organisation's violations: %d", code)
		}
	}
	if code := pa.do("PUT", base+fmt.Sprintf("/%d", kev.ID), map[string]any{"name": "hacked", "kind": "known_exploited"}, nil); code != 404 {
		t.Errorf("alpha admin edits the organisation's policy as alpha's: %d", code)
	}
	if code := pa.do("GET", "/api/v1/projects/"+o.s("beta-project")+"/gate-policies", nil, nil); code != 404 {
		t.Errorf("alpha admin reads beta: %d", code)
	}

	// Off for Alpha: host-alpha is only in Alpha, so its violation goes.
	if code := pa.do("PUT", base+fmt.Sprintf("/inherited/%d", kev.ID), map[string]string{"state": "off"}, &view); code != 200 || view.state(kev.ID) != "off" {
		t.Fatalf("off: %d %+v", code, view)
	}
	if code := o.admin.do("GET", "/api/v1/gate-policies/violations", nil, &vs); code != 200 || len(vs.Items) != 0 {
		t.Errorf("violations after off: %+v", vs.Items)
	}
	var item struct {
		OffProjects []int64 `json:"off_projects"`
	}
	if code := o.admin.do("GET", fmt.Sprintf("/api/v1/gate-policies/%d", kev.ID), nil, &item); code != 200 || len(item.OffProjects) != 1 {
		t.Errorf("off for: %d %+v", code, item)
	}
	// Edit: a copy owned by Alpha, back in force there.
	if code := pa.do("PUT", base+fmt.Sprintf("/inherited/%d", kev.ID), map[string]string{"state": "on"}, &view); code != 200 || view.state(kev.ID) != "on" {
		t.Fatalf("on: %d %+v", code, view)
	}
	if code := pa.do("PUT", base+fmt.Sprintf("/inherited/%d", kev.ID), map[string]string{"state": "edit"}, &view); code != 200 ||
		view.state(kev.ID) != "edit" || len(view.Policies) != 1 {
		t.Fatalf("edit: %d %+v", code, view)
	}
	cp := view.Policies[0]
	if cp.OwnerProjectID == nil || cp.InheritsPolicyID == nil || *cp.InheritsPolicyID != kev.ID {
		t.Fatalf("copy: %+v", cp)
	}
	if code := pa.do("PUT", base+fmt.Sprintf("/%d", cp.ID), map[string]any{"name": "Alpha KEV", "kind": "known_exploited", "mode": "off"}, nil); code != 200 {
		t.Fatalf("alpha edits its copy: %d", code)
	}
	if code := o.admin.do("GET", "/api/v1/gate-policies/violations", nil, &vs); code != 200 || len(vs.Items) != 0 {
		t.Errorf("violations with alpha's copy off: %+v", vs.Items)
	}
	// Its own policy, on the asset.
	asset := "/api/v1/assets/" + o.s("alpha-asset") + "/gate-policies"
	var own store.GatePolicy
	if code := pa.do("POST", asset, map[string]any{"name": "host age", "kind": "finding_age",
		"params": map[string]any{"min_severity": "critical", "max_days": 1}}, &own); code != 201 || own.OwnerAssetID == nil {
		t.Fatalf("asset policy: %d %+v", code, own)
	}
	if code := pa.do("GET", asset, nil, &view); code != 200 || view.state(cp.ID) != "on" || len(view.Policies) != 1 {
		t.Errorf("asset view: %d %+v", code, view)
	}
	if code := pa.do("DELETE", asset+fmt.Sprintf("/%d", own.ID), nil, nil); code != 204 {
		t.Errorf("delete asset policy: %d", code)
	}
	// Back on: the copy goes.
	if code := pa.do("PUT", base+fmt.Sprintf("/inherited/%d", kev.ID), map[string]string{"state": "on"}, &view); code != 200 || len(view.Policies) != 0 {
		t.Fatalf("on again: %d %+v", code, view)
	}
	if code := o.admin.do("DELETE", fmt.Sprintf("/api/v1/gate-policies/%d", kev.ID), nil, nil); code != 204 {
		t.Errorf("delete: %d", code)
	}

	// Every change is in the audit log.
	var audit struct {
		Items []store.AuditEvent `json:"items"`
	}
	if code := o.admin.do("GET", "/api/v1/audit?limit=200", nil, &audit); code != 200 {
		t.Fatalf("audit: %d", code)
	}
	seen := map[string]bool{}
	for _, ev := range audit.Items {
		if strings.HasPrefix(ev.Action, "gate_policy.") {
			seen[ev.Action] = true
		}
	}
	for _, a := range []string{"gate_policy.create", "gate_policy.mode", "gate_policy.update", "gate_policy.exclude", "gate_policy.include",
		"gate_policy.customise", "gate_policy.delete"} {
		if !seen[a] {
			t.Errorf("no %s in the audit log (%v)", a, seen)
		}
	}
}
