package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// uploadAs posts a host batch named name to /ingest (query appended) with a
// bearer token and returns the status and result.
func uploadAs(t *testing.T, e *env, token, name, query string, hdr map[string]string) (int, store.IngestResult, string) {
	t.Helper()
	b := model.NewBatch(model.Collector{ID: "agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: name,
		Identifiers: []model.Identifier{{Scheme: "machine-id", Value: name + "-id"}}})
	b.Observations = []model.Observation{{Purl: "pkg:deb/debian/bash@5.2", Confidence: model.ConfidenceConfirmed}}
	raw, _ := json.Marshal(b)
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/ingest"+query, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	var res store.IngestResult
	_ = json.Unmarshal(buf.Bytes(), &res)
	return resp.StatusCode, res, buf.String()
}

// POST /ingest?project_id= (stackurity scan / agent --project): an admin
// files any asset; a collector token made for the project may name only
// it and files only what it creates; nobody else may file assets, and a
// project must exist, be active and be in the caller's workspace.
func TestIngestProject(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	wctx := tenant.WithWorkspace(ctx, tenant.DefaultWorkspace)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	admin := e.login("admin@x.io")
	var shop, blog, old store.Project
	admin.do("POST", "/api/v1/projects", map[string]any{"name": "Shop"}, &shop)
	admin.do("POST", "/api/v1/projects", map[string]any{"name": "Blog"}, &blog)
	admin.do("POST", "/api/v1/projects", map[string]any{"name": "Old"}, &old)
	if _, err := e.st.Pool.Exec(tenant.System(ctx), `UPDATE projects SET archived_at = now() WHERE id = $1`, old.ID); err != nil {
		t.Fatal(err)
	}
	beta, _, err := e.st.CreateWorkspace(ctx, "Beta", "", "boss@beta.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	other, err := e.st.CreateProject(tenant.WithWorkspace(ctx, beta.ID), "Other", "")
	if err != nil {
		t.Fatal(err)
	}

	token := func(s *session, body map[string]any) string {
		t.Helper()
		var out struct{ Secret string }
		if code := s.do("POST", "/api/v1/tokens", body, &out); code != 201 {
			t.Fatalf("token %v: %d", body, code)
		}
		return out.Secret
	}
	adminTok := token(admin, map[string]any{"name": "a", "role": "admin"})
	engTok := token(e.login("eng@x.io"), map[string]any{"name": "e", "role": "engineer"})
	shopTok := token(admin, map[string]any{"name": "ci-shop", "role": "collector", "project_id": shop.ID})
	_, plainTok, err := e.st.CreateToken(wctx, "ci", auth.RoleCollector, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	q := func(id int64) string { return fmt.Sprintf("?project_id=%d", id) }

	// Refusals change nothing: no asset is created.
	for _, tc := range []struct {
		name, tok, query string
		want             int
		msg              string
	}{
		{"engineer", engTok, q(shop.ID), 403, "needs the admin role"},
		{"collector token without a project", plainTok, q(shop.ID), 403, "collector token made for the project"},
		{"collector token for another project", shopTok, q(blog.ID), 403, fmt.Sprintf("adds the assets it creates to project %d", shop.ID)},
		{"unknown project", adminTok, q(999999), 404, "no such project"},
		{"archived project", adminTok, q(old.ID), 404, "no such project"},
		{"another workspace's project", adminTok, q(other.ID), 404, "no such project"},
		{"not a number", adminTok, "?project_id=shop", 400, "project_id"},
	} {
		code, _, body := uploadAs(t, e, tc.tok, "refused-"+strings.ReplaceAll(tc.name, " ", "-"), tc.query, nil)
		if code != tc.want || !strings.Contains(body, tc.msg) {
			t.Errorf("%s: %d %s, want %d %q", tc.name, code, body, tc.want, tc.msg)
		}
	}
	var n int
	if err := e.st.Pool.QueryRow(wctx, `SELECT count(*) FROM assets WHERE name LIKE 'refused-%'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("refused uploads created %d assets (%v)", n, err)
	}

	// A collector token for Shop naming Shop: new assets land in it.
	code, res, body := uploadAs(t, e, shopTok, "ci-new", q(shop.ID), nil)
	if code != 201 || res.ProjectID != shop.ID || res.InProject == nil || !*res.InProject {
		t.Fatalf("collector token, its project: %d %s", code, body)
	}
	// An asset that already exists is not moved by a collector token.
	if code, _, _ := uploadAs(t, e, plainTok, "existing", "", nil); code != 201 {
		t.Fatal(code)
	}
	code, res, body = uploadAs(t, e, shopTok, "existing", q(shop.ID), nil)
	if code != 201 || res.ProjectID != shop.ID || res.InProject == nil || *res.InProject {
		t.Errorf("collector token, existing asset: %d %s", code, body)
	}
	// Without project_id nothing changes: the header alone is ignored for
	// anyone but an admin, as for SBOM uploads from the dashboard.
	code, res, body = uploadAs(t, e, engTok, "eng-header", "", map[string]string{"X-Stackurity-Project": fmt.Sprint(shop.ID)})
	if code != 201 || res.ProjectID != 0 || res.InProject != nil {
		t.Errorf("engineer with the header only: %d %s", code, body)
	}

	// An admin files any asset, new or existing, and it is audited.
	code, res, body = uploadAs(t, e, adminTok, "existing", q(blog.ID), nil)
	if code != 201 || res.ProjectID != blog.ID || res.InProject == nil || !*res.InProject {
		t.Errorf("admin, existing asset: %d %s", code, body)
	}
	code, _, body = uploadAs(t, e, adminTok, "admin-header", "", map[string]string{"X-Stackurity-Project": fmt.Sprint(blog.ID)})
	if code != 201 || !strings.Contains(body, fmt.Sprintf(`"project_id":%d`, blog.ID)) {
		t.Errorf("admin with the header: %d %s", code, body)
	}
	if got := projectAssets(t, admin, shop.ID); strings.Join(got, ",") != "ci-new" {
		t.Errorf("Shop: %v", got)
	}
	if got := projectAssets(t, admin, blog.ID); strings.Join(got, ",") != "admin-header,existing" {
		t.Errorf("Blog: %v", got)
	}
	var audit struct{ Items []store.AuditEvent }
	admin.do("GET", fmt.Sprintf("/api/v1/audit?object_type=project&object_id=%d", blog.ID), nil, &audit)
	if len(audit.Items) == 0 || audit.Items[0].Action != "project.assets_add" {
		t.Errorf("filing by upload not audited: %+v", audit.Items)
	}

	// A member with project access only, even as the project's admin,
	// cannot upload at all: ingest is an organisation route.
	if code := admin.do("POST", "/api/v1/access-grants", map[string]any{"email": "padmin@x.io", "password": pw, "role": "admin", "project_id": shop.ID}, nil); code != 201 {
		t.Fatalf("grant: %d", code)
	}
	memberTok := token(e.login("padmin@x.io"), map[string]any{"name": "m", "role": "admin"})
	if code, _, body := uploadAs(t, e, memberTok, "member-upload", q(shop.ID), nil); code != 403 {
		t.Errorf("project-only member uploads: %d %s", code, body)
	}

	// GET /meta tells clients that uploads honour project_id.
	var meta struct{ Features []string }
	e.anon().do("GET", "/api/v1/meta", nil, &meta)
	if !slices.Contains(meta.Features, "upload_project") || !slices.Contains(meta.Features, "app_list") {
		t.Errorf("meta features: %v", meta.Features)
	}
}

// SBOM uploads follow the same rules: a collector token made for the
// project may now name it, other collector tokens may not.
func TestSBOMImportProjectToken(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	var shop, blog store.Project
	admin.do("POST", "/api/v1/projects", map[string]any{"name": "Shop"}, &shop)
	admin.do("POST", "/api/v1/projects", map[string]any{"name": "Blog"}, &blog)
	var tok struct{ Secret string }
	if code := admin.do("POST", "/api/v1/tokens", map[string]any{"name": "ci", "role": "collector", "project_id": shop.ID}, &tok); code != 201 {
		t.Fatal(code)
	}
	sb := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"lodash","version":"4.17.15","purl":"pkg:npm/lodash@4.17.15"}]}`)
	hdr := map[string]string{"Content-Type": "application/json"}
	if code := bearer(e, tok.Secret, "POST", fmt.Sprintf("/api/v1/sbom/import?asset_name=a&project_id=%d", blog.ID), sb, hdr); code != 403 {
		t.Errorf("another project: %d", code)
	}
	if code := bearer(e, tok.Secret, "POST", fmt.Sprintf("/api/v1/sbom/import?asset_name=a&project_id=%d", shop.ID), sb, hdr); code != 201 {
		t.Errorf("its own project: %d", code)
	}
	if got := projectAssets(t, admin, shop.ID); strings.Join(got, ",") != "a" {
		t.Errorf("Shop: %v", got)
	}
}

// stackurity enroll --project: the code must add hosts to that project, or
// nothing is redeemed and the code keeps its use.
func TestEnrollProjectCheck(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	var shop, blog store.Project
	admin.do("POST", "/api/v1/projects", map[string]any{"name": "Shop"}, &shop)
	admin.do("POST", "/api/v1/projects", map[string]any{"name": "Blog"}, &blog)
	code := func(project *int64) string {
		var enr struct{ Code string }
		body := map[string]any{"label": "web"}
		if project != nil {
			body["project_id"] = *project
		}
		if c := admin.do("POST", "/api/v1/enrollments", body, &enr); c != 201 {
			t.Fatalf("enrollment: %d", c)
		}
		return enr.Code
	}
	shopCode, plainCode := code(&shop.ID), code(nil)
	anon := e.anon()
	redeem := func(c string, project any) (int, map[string]any) {
		var out map[string]any
		body := map[string]any{"code": c, "hostname": "web-1"}
		if project != nil {
			body["project_id"] = project
		}
		return anon.do("POST", "/api/v1/enroll", body, &out), out
	}
	if c, _ := redeem(shopCode, blog.ID); c != 403 {
		t.Errorf("another project: %d", c)
	}
	if c, _ := redeem(plainCode, shop.ID); c != 403 {
		t.Errorf("a code without a project: %d", c)
	}
	if c, _ := redeem(shopCode, -1); c != 400 {
		t.Errorf("negative project: %d", c)
	}
	// The refusals did not use the single-use codes up.
	if c, out := redeem(shopCode, shop.ID); c != 200 || out["token"] == "" || out["project_id"] != float64(shop.ID) {
		t.Errorf("its project: %d %v", c, out)
	}
	if c, out := redeem(plainCode, nil); c != 200 || out["project_id"] != nil {
		t.Errorf("no project asked: %d %v", c, out)
	}
}
