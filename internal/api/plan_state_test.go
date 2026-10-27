package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// TestProjectLimitAPI: unset by default; an instance admin sets it; at the
// limit creating (or unarchiving) a project answers 402 project_limit, and
// existing projects stay; Usage and the workspace list show it.
func TestProjectLimitAPI(t *testing.T) {
	e := newEnv(t)
	e.user("owner@x.io", auth.RoleAdmin)
	e.instanceAdmin("owner@x.io")
	e.user("admin@x.io", auth.RoleAdmin)
	owner, admin := e.login("owner@x.io"), e.login("admin@x.io")

	var p1, p2 store.Project
	if code := admin.do("POST", "/api/v1/projects", map[string]any{"name": "one"}, &p1); code != 201 {
		t.Fatalf("project without a limit: %d", code)
	}
	if code := admin.do("POST", "/api/v1/projects", map[string]any{"name": "two"}, &p2); code != 201 {
		t.Fatalf("second project: %d", code)
	}
	if code := admin.do("PATCH", "/api/v1/admin/workspaces/1", map[string]any{"project_limit": 1}, nil); code != 403 {
		t.Errorf("workspace admin set the project limit: %d", code)
	}
	var ws store.Workspace
	if code := owner.do("PATCH", "/api/v1/admin/workspaces/1", map[string]any{"project_limit": 1}, &ws); code != 200 ||
		ws.ProjectLimit == nil || *ws.ProjectLimit != 1 || ws.Projects != 2 {
		t.Fatalf("set project limit: %d %+v", code, ws)
	}
	if code := owner.do("PATCH", "/api/v1/admin/workspaces/1", map[string]any{"project_limit": -2}, nil); code != 400 {
		t.Errorf("project limit -2: %d", code)
	}
	resp := admin.req("POST", "/api/v1/projects", strings.NewReader(`{"name":"three"}`),
		map[string]string{"X-Stackurity-CSRF": "1", "Content-Type": "application/json"})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 402 || !strings.Contains(string(body), `"project_limit"`) || !strings.Contains(string(body), "2 of 1 projects") {
		t.Errorf("project over the limit: %d %s", resp.StatusCode, body)
	}
	var ps struct{ Items []store.Project }
	if code := admin.do("GET", "/api/v1/projects", nil, &ps); code != 200 || len(ps.Items) != 2 {
		t.Errorf("existing projects after a lower limit: %d %d", code, len(ps.Items))
	}
	var usage store.AssetUsage
	if code := admin.do("GET", "/api/v1/usage", nil, &usage); code != 200 || usage.Projects != 2 || usage.ProjectLimit == nil || !usage.ProjectsAtLimit {
		t.Errorf("usage: %d %+v", code, usage)
	}
	// Archive both, make one, and the archived ones cannot come back.
	for _, id := range []int64{p1.ID, p2.ID} {
		if code := admin.do("PATCH", fmt.Sprintf("/api/v1/projects/%d", id), map[string]any{"archived": true}, nil); code != 200 {
			t.Fatalf("archive: %d", code)
		}
	}
	if code := admin.do("POST", "/api/v1/projects", map[string]any{"name": "three"}, nil); code != 201 {
		t.Errorf("project with room: %d", code)
	}
	if code := admin.do("PATCH", fmt.Sprintf("/api/v1/projects/%d", p1.ID), map[string]any{"archived": false}, nil); code != 402 {
		t.Errorf("unarchive at the limit: %d", code)
	}
	if code := owner.do("PATCH", "/api/v1/admin/workspaces/1", map[string]any{"project_limit": -1}, &ws); code != 200 || ws.ProjectLimit != nil {
		t.Errorf("remove project limit: %d %+v", code, ws)
	}
}

// TestReadOnlyAPI: unset by default. While read-only, every way of
// collecting something new or sending a notification answers 402
// read_only with the reason, signing in and viewing work, and every member
// sees the state. Clearing it brings everything back.
func TestReadOnlyAPI(t *testing.T) {
	e := newEnv(t)
	e.user("owner@x.io", auth.RoleAdmin)
	e.instanceAdmin("owner@x.io")
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("viewer@x.io", auth.RoleViewer)
	owner, admin, viewer := e.login("owner@x.io"), e.login("admin@x.io"), e.login("viewer@x.io")

	var tok struct{ Secret string }
	if code := admin.do("POST", "/api/v1/tokens", map[string]any{"name": "collector", "role": "collector"}, &tok); code != 201 {
		t.Fatalf("token: %d", code)
	}
	ingest := func(name string) (int, string) {
		return bearerBody(e, tok.Secret, "POST", "/api/v1/ingest", hostBatch(model.AssetHost, name, "machine-id"))
	}
	if code, body := ingest("web-1"); code != 201 {
		t.Fatalf("ingest: %d %s", code, body)
	}
	var enr struct{ Code string }
	if code := admin.do("POST", "/api/v1/enrollments", map[string]any{"label": "later"}, &enr); code != 201 {
		t.Fatalf("enrollment: %d", code)
	}
	var me struct {
		Workspace struct {
			ReadOnly   *store.ReadOnlyState `json:"read_only"`
			ReportMode string               `json:"report_mode"`
		}
	}
	if viewer.do("GET", "/api/v1/auth/me", nil, &me); me.Workspace.ReadOnly != nil || me.Workspace.ReportMode != "full" {
		t.Fatalf("me by default: %+v", me.Workspace)
	}

	var ws store.Workspace
	if code := owner.do("PATCH", "/api/v1/admin/workspaces/1", map[string]any{"read_only": true, "read_only_reason": "The trial ended."}, &ws); code != 200 ||
		ws.ReadOnlyAt == nil || ws.ReadOnlyReason != "The trial ended." {
		t.Fatalf("set read-only: %d %+v", code, ws)
	}
	var assets struct{ Items []store.Asset }
	if code := viewer.do("GET", "/api/v1/assets", nil, &assets); code != 200 || len(assets.Items) != 1 {
		t.Fatalf("viewing while read-only: %d %+v", code, assets)
	}
	if viewer.do("GET", "/api/v1/auth/me", nil, &me); me.Workspace.ReadOnly == nil || me.Workspace.ReadOnly.Reason != "The trial ended." {
		t.Errorf("me while read-only: %+v", me.Workspace)
	}
	var usage store.AssetUsage
	if admin.do("GET", "/api/v1/usage", nil, &usage); usage.ReadOnly == nil {
		t.Errorf("usage while read-only: %+v", usage)
	}
	asset := assets.Items[0].ID
	try := map[string]func() (int, string){
		"agent ingest (existing host)": func() (int, string) { return ingest("web-1") },
		"agent ingest (new host)":      func() (int, string) { return ingest("web-2") },
		"SBOM import": func() (int, string) {
			return bearerBody(e, tok.Secret, "POST", "/api/v1/sbom/import?asset_name=shop", []byte(cdx))
		},
		"redeem a code": func() (int, string) {
			var out map[string]any
			code := e.anon().do("POST", "/api/v1/enroll", map[string]string{"code": enr.Code, "hostname": "web-9"}, &out)
			b, _ := json.Marshal(out)
			return code, string(b)
		},
	}
	for name, path := range map[string]string{
		"new enrollment code": "/api/v1/enrollments",
		"new integration":     "/api/v1/integrations",
		"evaluate":            "/api/v1/evaluate",
		"check an asset":      fmt.Sprintf("/api/v1/assets/%d/check", asset),
		"test a channel":      "/api/v1/channels/1/test",
		"retry a delivery":    "/api/v1/deliveries/1/retry",
		"run an integration":  "/api/v1/integrations/1/run",
	} {
		try[name] = func() (int, string) {
			var out map[string]any
			code := admin.do("POST", path, map[string]any{"label": "x", "kind": "git_repository",
				"config": map[string]string{"url": "https://github.com/x/new"}}, &out)
			b, _ := json.Marshal(out)
			return code, string(b)
		}
	}
	for name, f := range try {
		code, body := f()
		if code != 402 || !strings.Contains(body, `"read_only"`) || !strings.Contains(body, "The trial ended") {
			t.Errorf("%s while read-only: %d %s", name, code, body)
		}
	}
	// Settings still work: an admin can tidy up, make a project.
	if code := admin.do("POST", "/api/v1/projects", map[string]any{"name": "kept"}, nil); code != 201 {
		t.Errorf("project while read-only: %d", code)
	}
	if code := owner.do("PATCH", "/api/v1/admin/workspaces/1", map[string]any{"read_only": false}, &ws); code != 200 || ws.ReadOnlyAt != nil || ws.ReadOnlyReason != "" {
		t.Fatalf("clear read-only: %d %+v", code, ws)
	}
	if code, body := ingest("web-2"); code != 201 {
		t.Errorf("ingest when writable: %d %s", code, body)
	}
	var out map[string]any
	if code := e.anon().do("POST", "/api/v1/enroll", map[string]string{"code": enr.Code, "hostname": "web-9"}, &out); code != 200 {
		t.Errorf("the code after read-only: %d %v", code, out)
	}
}

// TestReportTrialAPI: in trial mode the SBOM export lists the first rows
// only, says how many more there are and carries the watermark, and the
// outcomes report carries the trial marker; in full mode neither changes.
func TestReportTrialAPI(t *testing.T) {
	e := newEnv(t)
	e.user("owner@x.io", auth.RoleAdmin)
	e.instanceAdmin("owner@x.io")
	owner := e.login("owner@x.io")
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	b := model.NewBatch(model.Collector{ID: "agent", Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: "web-1", Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "web-1"}}})
	for i := 0; i < 15; i++ {
		b.Observations = append(b.Observations, model.Observation{Purl: fmt.Sprintf("pkg:npm/lib-%02d@1.0.0", i), Confidence: model.ConfidenceConfirmed})
	}
	b.Complete = true
	res, err := e.st.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	export := func() (string, string) {
		resp := owner.req("GET", fmt.Sprintf("/api/v1/assets/%d/sbom", res.AssetID), nil, nil)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("export: %d %s", resp.StatusCode, body)
		}
		return string(body), resp.Header.Get("X-Stackurity-Report-Mode")
	}
	var doc struct {
		Components []struct{ Name string } `json:"components"`
		Metadata   struct {
			Properties []struct{ Name, Value string } `json:"properties"`
		} `json:"metadata"`
	}
	full, mode := export()
	_ = json.Unmarshal([]byte(full), &doc)
	if len(doc.Components) != 15 || len(doc.Metadata.Properties) != 0 || mode != "" || strings.Contains(full, "not for distribution") {
		t.Fatalf("full export: %d components, %+v, %q", len(doc.Components), doc.Metadata.Properties, mode)
	}
	var out struct {
		Trial *struct{ Watermark string } `json:"trial"`
	}
	if code := owner.do("GET", "/api/v1/reports/outcomes", nil, &out); code != 200 || out.Trial != nil {
		t.Fatalf("full outcomes: %d %+v", code, out.Trial)
	}

	var ws store.Workspace
	if code := owner.do("PATCH", "/api/v1/admin/workspaces/1", map[string]any{"report_mode": "half"}, nil); code != 400 {
		t.Errorf("report mode half: %d", code)
	}
	if code := owner.do("PATCH", "/api/v1/admin/workspaces/1", map[string]any{"report_mode": "trial"}, &ws); code != 200 || ws.ReportMode != "trial" {
		t.Fatalf("trial mode: %d %+v", code, ws)
	}
	trial, mode := export()
	doc.Components, doc.Metadata.Properties = nil, nil
	_ = json.Unmarshal([]byte(trial), &doc)
	props := map[string]string{}
	for _, p := range doc.Metadata.Properties {
		props[p.Name] = p.Value
	}
	if len(doc.Components) != 10 || mode != "trial" || props["stackurity:report_mode"] != "trial" ||
		!strings.Contains(props["stackurity:watermark"], "not for distribution") || props["stackurity:trial_note"] != "components: trial: 5 more not shown" {
		t.Errorf("trial export: %d components, %v, %q", len(doc.Components), props, mode)
	}
	var outcomes struct {
		Trial *struct {
			Watermark   string         `json:"watermark"`
			RowsPerList int            `json:"rows_per_list"`
			Omitted     map[string]int `json:"omitted"`
		} `json:"trial"`
	}
	if code := owner.do("GET", "/api/v1/reports/outcomes", nil, &outcomes); code != 200 || outcomes.Trial == nil ||
		!strings.Contains(outcomes.Trial.Watermark, "not for distribution") || outcomes.Trial.RowsPerList != 10 {
		t.Errorf("trial outcomes: %d %+v", code, outcomes.Trial)
	}
	// The mode is the organisation's own: another workspace reports in full.
	other, _, err := e.st.CreateWorkspace(context.Background(), "Other", "", "other@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := e.st.ReportMode(tenant.WithWorkspace(context.Background(), other.ID)); m != "full" {
		t.Errorf("other workspace: %q", m)
	}
}
