package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
)

// bearerBody is bearer returning the response body too.
func bearerBody(e *env, token, method, path string, body []byte) (int, string) {
	req, _ := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func hostBatch(kind model.AssetKind, name, scheme string) []byte {
	b := model.NewBatch(model.Collector{ID: "agent", Method: "agent"},
		model.AssetRef{Kind: kind, Name: name, Identifiers: []model.Identifier{{Scheme: scheme, Value: name}}})
	b.Observations = []model.Observation{{Purl: "pkg:deb/debian/bash@5.2", Confidence: model.ConfidenceConfirmed}}
	b.Complete = true
	raw, _ := json.Marshal(b)
	return raw
}

const cdx = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"left-pad","version":"1.0.0","purl":"pkg:npm/left-pad@1.0.0"}]}`

// TestAssetLimitAPI: with a limit set by an instance admin, every way of
// adding an asset (agent and collector ingest, CI uploads, SBOM import,
// enrollment codes, new integrations) refuses a new asset with a clear 402,
// while assets already monitored keep reporting. Usage shows the numbers.
func TestAssetLimitAPI(t *testing.T) {
	e := newEnv(t)
	e.user("owner@x.io", auth.RoleAdmin)
	e.instanceAdmin("owner@x.io")
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("viewer@x.io", auth.RoleViewer)
	owner, admin, viewer := e.login("owner@x.io"), e.login("admin@x.io"), e.login("viewer@x.io")

	var usage store.AssetUsage
	if code := viewer.do("GET", "/api/v1/usage", nil, &usage); code != 200 || usage.Limit != nil || usage.AtLimit {
		t.Fatalf("usage without a limit: %d %+v", code, usage)
	}
	// Only instance admins set limits.
	if code := admin.do("PATCH", "/api/v1/admin/workspaces/1", map[string]any{"asset_limit": 100}, nil); code != 403 {
		t.Errorf("workspace admin set the limit: %d", code)
	}
	var ws store.Workspace
	if code := owner.do("PATCH", "/api/v1/admin/workspaces/1", map[string]any{"asset_limit": 3}, &ws); code != 200 || ws.AssetLimit == nil || *ws.AssetLimit != 3 {
		t.Fatalf("set limit: %d %+v", code, ws)
	}
	if code := owner.do("PATCH", "/api/v1/admin/workspaces/1", map[string]any{"asset_limit": -5}, nil); code != 400 {
		t.Errorf("limit -5: %d", code)
	}

	var tok struct{ Secret string }
	if code := admin.do("POST", "/api/v1/tokens", map[string]any{"name": "collector", "role": "collector"}, &tok); code != 201 {
		t.Fatalf("token: %d", code)
	}
	ingest := func(kind model.AssetKind, name, scheme string) (int, string) {
		return bearerBody(e, tok.Secret, "POST", "/api/v1/ingest", hostBatch(kind, name, scheme))
	}
	sbom := func(name string) (int, string) {
		return bearerBody(e, tok.Secret, "POST", "/api/v1/sbom/import?asset_name="+name, []byte(cdx))
	}
	if code, body := ingest(model.AssetHost, "web-1", "machine-id"); code != 201 {
		t.Fatalf("first host: %d %s", code, body)
	}
	if code, body := sbom("shop"); code != 201 {
		t.Fatalf("first SBOM: %d %s", code, body)
	}
	// An enrollment code made with room left.
	var enr struct {
		Enrollment store.Enrollment
		Code       string
	}
	if code := admin.do("POST", "/api/v1/enrollments", map[string]any{"label": "later"}, &enr); code != 201 {
		t.Fatalf("enrollment: %d", code)
	}
	if code, body := ingest(model.AssetHost, "web-2", "machine-id"); code != 201 {
		t.Fatalf("third asset: %d %s", code, body)
	}

	// Three of three: new assets are refused on every path, clearly.
	for name, try := range map[string]func() (int, string){
		"agent ingest":      func() (int, string) { return ingest(model.AssetHost, "web-3", "machine-id") },
		"CI repository":     func() (int, string) { return ingest(model.AssetRepository, "github.com/x/app", "git-url") },
		"image scan upload": func() (int, string) { return ingest(model.AssetImage, "docker.io/x/app:1", "image-ref") },
		"kubernetes":        func() (int, string) { return ingest(model.AssetCluster, "prod", "k8s-cluster") },
		"SBOM import":       func() (int, string) { return sbom("billing") },
	} {
		code, body := try()
		if code != 402 || !strings.Contains(body, `"asset_limit"`) || !strings.Contains(body, "3 of 3 assets") ||
			!strings.Contains(body, "keep being checked") {
			t.Errorf("%s at the limit: %d %s", name, code, body)
		}
	}
	// Assets already monitored keep reporting.
	if code, body := ingest(model.AssetHost, "web-1", "machine-id"); code != 201 {
		t.Errorf("existing host at the limit: %d %s", code, body)
	}
	if code, body := sbom("shop"); code != 201 {
		t.Errorf("existing SBOM asset at the limit: %d %s", code, body)
	}
	// No new enrollment codes or integrations: they could add nothing.
	if code := admin.do("POST", "/api/v1/enrollments", map[string]any{"label": "full"}, nil); code != 402 {
		t.Errorf("enrollment at the limit: %d", code)
	}
	if code := admin.do("POST", "/api/v1/integrations", map[string]any{"kind": "git_repository",
		"config": map[string]string{"url": "https://github.com/x/new"}}, nil); code != 402 {
		t.Errorf("integration at the limit: %d", code)
	}
	// A code made earlier cannot be redeemed, and is not used up.
	var out map[string]any
	if code := e.anon().do("POST", "/api/v1/enroll", map[string]string{"code": enr.Code, "hostname": "web-9"}, &out); code != 402 {
		t.Errorf("redeem at the limit: %d %v", code, out)
	}
	var enrs struct{ Items []store.Enrollment }
	admin.do("GET", "/api/v1/enrollments", nil, &enrs)
	if len(enrs.Items) != 1 || enrs.Items[0].UsesLeft != 1 {
		t.Errorf("code after a refused redeem: %+v", enrs.Items)
	}

	if code := viewer.do("GET", "/api/v1/usage", nil, &usage); code != 200 || !usage.AtLimit || usage.Monitored != 3 ||
		usage.ByKind["host"] != 2 || usage.ByKind["application"] != 1 || len(usage.Refused) != 5 {
		t.Errorf("usage at the limit: %d %+v", code, usage)
	}
	var list struct{ Items []store.Workspace }
	owner.do("GET", "/api/v1/admin/workspaces/", nil, &list)
	if len(list.Items) != 1 || list.Items[0].Monitored != 3 || list.Items[0].AssetLimit == nil {
		t.Errorf("admin list: %+v", list.Items)
	}

	// Deleting an asset makes room: the old code works now.
	var assets struct{ Items []store.Asset }
	admin.do("GET", "/api/v1/assets?q=web-2", nil, &assets)
	if len(assets.Items) != 1 {
		t.Fatalf("assets: %+v", assets.Items)
	}
	if code := admin.do("DELETE", fmt.Sprintf("/api/v1/assets/%d", assets.Items[0].ID), nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code := e.anon().do("POST", "/api/v1/enroll", map[string]string{"code": enr.Code, "hostname": "web-9"}, &out); code != 200 {
		t.Errorf("redeem with room: %d %v", code, out)
	}
	// Removing the limit.
	if code := owner.do("PATCH", "/api/v1/admin/workspaces/1", map[string]any{"asset_limit": -1}, &ws); code != 200 || ws.AssetLimit != nil {
		t.Errorf("remove limit: %d %+v", code, ws)
	}
	if code, body := ingest(model.AssetHost, "web-4", "machine-id"); code != 201 {
		t.Errorf("without a limit: %d %s", code, body)
	}
}
