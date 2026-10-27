package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/client"
)

// fakeServer answers the calls --project makes: GET /meta, GET /projects,
// GET /projects/{id}, POST /ingest, POST /sbom/import and POST /enroll.
type fakeServer struct {
	t *testing.T
	// collector: the token cannot read projects (403), as a collector
	// token cannot.
	collector bool
	// old: a server before 0.10: no features, uploads ignore project_id,
	// enroll refuses unknown fields.
	old      bool
	projects []map[string]any

	mu   sync.Mutex
	reqs []*http.Request
}

func (f *fakeServer) start() *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reqs = append(f.reqs, r.Clone(context.Background()))
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		reply := func(code int, v any) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		fail := func(code int, msg string) {
			reply(code, map[string]any{"error": map[string]string{"code": "x", "message": msg}})
		}
		switch {
		case r.URL.Path == "/api/v1/meta":
			m := map[string]any{"version": "0.10.0"}
			if f.old {
				m["version"] = "0.9.0"
			} else {
				m["features"] = []string{"upload_project"}
			}
			reply(200, m)
		case r.URL.Path == "/api/v1/projects" && f.collector:
			fail(403, "forbidden")
		case r.URL.Path == "/api/v1/projects":
			reply(200, map[string]any{"items": f.projects})
		case strings.HasPrefix(r.URL.Path, "/api/v1/projects/"):
			if f.collector {
				fail(403, "forbidden")
				return
			}
			id := strings.TrimPrefix(r.URL.Path, "/api/v1/projects/")
			for _, p := range f.projects {
				if jsonID(p["id"]) == id {
					reply(200, map[string]any{"project": p})
					return
				}
			}
			fail(404, "not found")
		case r.URL.Path == "/api/v1/ingest" || r.URL.Path == "/api/v1/sbom/import":
			_, _ = io.Copy(io.Discard, r.Body)
			res := map[string]any{"asset_id": 5, "collection_id": 9, "observations": 1, "new_asset": true}
			if pid := r.URL.Query().Get("project_id"); pid != "" && !f.old {
				res["project_id"] = json.Number(pid)
				res["in_project"] = true
			}
			reply(201, res)
		case r.URL.Path == "/api/v1/enroll":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if _, ok := body["project_id"]; ok && f.old {
				fail(400, `invalid JSON body: json: unknown field "project_id"`)
				return
			}
			if p, ok := body["project_id"]; ok && jsonID(p) != "3" {
				fail(403, "this enrollment code does not add hosts to the project you asked for")
				return
			}
			reply(200, map[string]any{"token": "stk_x", "environment": "production", "app_dirs": []string{}, "project_id": 3})
		default:
			fail(404, "no route "+r.URL.Path)
		}
	}))
	f.t.Cleanup(srv.Close)
	return srv
}

func jsonID(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (f *fakeServer) requests(path string) []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*http.Request
	for _, r := range f.reqs {
		if r.URL.Path == path {
			out = append(out, r)
		}
	}
	return out
}

var someProjects = []map[string]any{
	{"id": 3, "name": "Shop"},
	{"id": 4, "name": "Blog"},
	{"id": 5, "name": "blog"},
	{"id": 6, "name": "Payments"},
	{"id": 7, "name": "Old", "archived_at": "2026-01-01T00:00:00Z"},
}

func TestResolveProject(t *testing.T) {
	ctx := context.Background()
	f := &fakeServer{t: t, projects: someProjects}
	cl, err := client.New(f.start().URL, "t", "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		in      string
		want    int64
		wantErr string
	}{
		{in: "3", want: 3},
		{in: " 6 ", want: 6},
		{in: "Shop", want: 3},
		{in: "shop", want: 3},     // case does not matter
		{in: "PAYMENTS", want: 6}, // nor here
		{in: "Blog", want: 4},     // an exact match wins over one that ignores case
		{in: "BLOG", wantErr: "2 projects are named"},
		{in: "Nope", wantErr: `no project named "Nope"; projects this token can see: Blog, Payments, Shop, blog`},
		{in: "Old", wantErr: "no project named"}, // archived projects are not offered
		{in: "7", wantErr: "archived"},
		{in: "99", wantErr: "no project 99"},
		{in: "0", wantErr: "not a project id"},
		{in: "-2", wantErr: "not a project id"},
	} {
		got, _, err := resolveProject(ctx, cl, tc.in)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%q: %d, %v; want error %q", tc.in, got, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q: %d, %v; want %d", tc.in, got, err, tc.want)
		}
	}
	// None of the lookups was scoped to a project.
	for _, r := range f.reqs {
		if r.Header.Get("X-Stackurity-Project") != "" {
			t.Errorf("%s sent the project header during resolution", r.URL)
		}
	}

	// A collector token cannot read projects: an id is passed on for the
	// server to check, a name cannot be looked up.
	fc := &fakeServer{t: t, collector: true, projects: someProjects}
	cl, _ = client.New(fc.start().URL, "t", "test")
	if id, name, err := resolveProject(ctx, cl, "3"); err != nil || id != 3 || name != "" {
		t.Errorf("collector token, id: %d %q %v", id, name, err)
	}
	if _, _, err := resolveProject(ctx, cl, "Shop"); err == nil || !strings.Contains(err.Error(), "pass the project's id instead") {
		t.Errorf("collector token, name: %v", err)
	}
}

func TestConnectScopesClient(t *testing.T) {
	ctx := context.Background()
	f := &fakeServer{t: t, projects: someProjects}
	srv := f.start()
	t.Setenv("STACKURITY_TOKEN", "stk_test")

	// Reads: the header on every request after resolution.
	c := conn{server: srv.URL, project: "shop"}
	cl, err := c.connect(ctx, false)
	if err != nil || cl.Project != 3 {
		t.Fatalf("connect: %+v %v", cl, err)
	}
	if err := cl.Do(ctx, "GET", "/api/v1/projects", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	reqs := f.requests("/api/v1/projects")
	if last := reqs[len(reqs)-1]; last.Header.Get("X-Stackurity-Project") != "3" {
		t.Errorf("read without the project header: %v", last.Header)
	}
	if len(f.requests("/api/v1/meta")) != 0 {
		t.Error("a read-only command asked for upload support")
	}

	// Uploads: project_id on the upload, and the answer must confirm it.
	cl, err = c.connect(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cl.ImportSBOM(ctx, strings.NewReader("{}"), "", "", "")
	if err != nil || res.ProjectID != 3 {
		t.Fatalf("sbom import: %+v %v", res, err)
	}
	if q := f.requests("/api/v1/sbom/import")[0].URL.Query().Get("project_id"); q != "3" {
		t.Errorf("sbom import project_id = %q", q)
	}

	// No project: nothing is sent and nothing is checked.
	n := len(f.reqs)
	cl, err = (&conn{server: srv.URL}).connect(ctx, true)
	if err != nil || cl.Project != 0 || len(f.reqs) != n {
		t.Errorf("without --project: %+v %v, %d requests", cl, err, len(f.reqs)-n)
	}
}

// An older server ignores project_id on uploads: the command must refuse
// before uploading, and an answer without the project is an error.
func TestProjectOnOlderServer(t *testing.T) {
	ctx := context.Background()
	f := &fakeServer{t: t, old: true, projects: someProjects}
	srv := f.start()
	t.Setenv("STACKURITY_TOKEN", "stk_test")
	_, err := (&conn{server: srv.URL, project: "3"}).connect(ctx, true)
	if err == nil || !strings.Contains(err.Error(), "0.10 or later") || !strings.Contains(err.Error(), "Nothing was uploaded") {
		t.Fatalf("connect to an older server: %v", err)
	}
	// Belt and braces: an upload whose answer does not confirm the project.
	cl, _ := client.New(srv.URL, "t", "test")
	cl.Project = 3
	if _, err := cl.ImportSBOM(ctx, strings.NewReader("{}"), "", "", ""); !errors.Is(err, client.ErrProjectIgnored) {
		t.Errorf("sbom import on an older server: %v", err)
	}
}

// stackurity scan --project end to end: flag and environment variable, the
// project_id on the upload, and refusal with --output.
func TestScanProjectFlag(t *testing.T) {
	f := &fakeServer{t: t, projects: someProjects}
	srv := f.start()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STACKURITY_TOKEN", "stk_test")
	t.Setenv("STACKURITY_SERVER", srv.URL)
	run := func(args ...string) error {
		cmd := scanCmd()
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		return cmd.Execute()
	}

	if err := run(dir, "--no-packs", "--project", "Payments"); err != nil {
		t.Fatal(err)
	}
	ing := f.requests("/api/v1/ingest")
	if len(ing) != 1 || ing[0].URL.Query().Get("project_id") != "6" || ing[0].Header.Get("X-Stackurity-Project") != "6" {
		t.Fatalf("ingest requests: %v", ing)
	}

	// STACKURITY_PROJECT is the default, for CI.
	t.Setenv("STACKURITY_PROJECT", "shop")
	if err := run(dir, "--no-packs"); err != nil {
		t.Fatal(err)
	}
	if ing := f.requests("/api/v1/ingest"); len(ing) != 2 || ing[1].URL.Query().Get("project_id") != "3" {
		t.Fatalf("ingest with STACKURITY_PROJECT: %v", ing)
	}
	// ... and the flag wins over it.
	if err := run(dir, "--no-packs", "--project", "4"); err != nil {
		t.Fatal(err)
	}
	if ing := f.requests("/api/v1/ingest"); ing[2].URL.Query().Get("project_id") != "4" {
		t.Errorf("flag over environment: %v", ing[2].URL)
	}

	// An unknown project fails before anything is uploaded.
	if err := run(dir, "--no-packs", "--project", "Nope"); err == nil || !strings.Contains(err.Error(), "--project: no project named") {
		t.Errorf("unknown project: %v", err)
	}
	if n := len(f.requests("/api/v1/ingest")); n != 3 {
		t.Errorf("%d uploads after an unknown project, want 3", n)
	}

	// --output writes a file: an explicit --project makes no sense there,
	// the environment variable alone is ignored.
	out := filepath.Join(t.TempDir(), "b.json")
	if err := run(dir, "--project", "3", "-o", out); err == nil || !strings.Contains(err.Error(), "--output") {
		t.Errorf("--project with --output: %v", err)
	}
	if err := run(dir, "-o", out); err != nil {
		t.Errorf("STACKURITY_PROJECT with --output: %v", err)
	}
}

// Every command that talks to the server with a token takes --project.
func TestProjectFlagOnCommands(t *testing.T) {
	t.Setenv("STACKURITY_PROJECT", "Shop")
	sb := sbomCmd()
	imp, _, _ := sb.Find([]string{"import"})
	exp, _, _ := sb.Find([]string{"export"})
	cmds := map[string]*cobra.Command{"agent": agentCmd(), "scan": scanCmd(), "sbom import": imp, "sbom export": exp,
		"diagnostics": diagnosticsCmd(), "mcp": mcpCmd(), "enroll": enrollCmd()}
	for name, cmd := range cmds {
		f := cmd.Flags().Lookup("project")
		if f == nil {
			t.Errorf("%s has no --project", name)
			continue
		}
		if f.DefValue != "Shop" {
			t.Errorf("%s --project default %q, want STACKURITY_PROJECT", name, f.DefValue)
		}
		if !strings.Contains(f.Usage, "STACKURITY_PROJECT") {
			t.Errorf("%s --project help does not name STACKURITY_PROJECT: %q", name, f.Usage)
		}
	}
}

func TestEnrollProject(t *testing.T) {
	for in, want := range map[string]int64{"": 0, "3": 3, " 12 ": 12} {
		if got, err := enrollProject(in); err != nil || got != want {
			t.Errorf("enrollProject(%q) = %d, %v", in, got, err)
		}
	}
	for _, in := range []string{"Shop", "0", "-1"} {
		if _, err := enrollProject(in); err == nil || !strings.Contains(err.Error(), "id") {
			t.Errorf("enrollProject(%q): %v", in, err)
		}
	}

	run := func(f *fakeServer, project string) (string, error) {
		srv := f.start()
		dir := t.TempDir()
		t.Setenv("STACKURITY_ENROLL_CODE", "enr_x")
		cmd := enrollCmd()
		cmd.SetArgs([]string{"--server", srv.URL, "--dir", dir, "--project", project})
		err := cmd.Execute()
		return dir, err
	}
	// The code is for project 3.
	f := &fakeServer{t: t}
	dir, err := run(f, "3")
	if err != nil {
		t.Fatal(err)
	}
	if reqs := f.requests("/api/v1/enroll"); len(reqs) != 1 {
		t.Fatalf("enroll requests: %d", len(reqs))
	}
	if _, err := os.Stat(filepath.Join(dir, "token")); err != nil {
		t.Errorf("token not written: %v", err)
	}
	// Another project: refused, nothing written.
	dir, err = run(&fakeServer{t: t}, "4")
	if err == nil || !strings.Contains(err.Error(), "does not add hosts to the project") {
		t.Errorf("wrong project: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "token")); err == nil {
		t.Error("token written after a refusal")
	}
	// An older server refuses the field: a clear message.
	if _, err := run(&fakeServer{t: t, old: true}, "3"); err == nil || !strings.Contains(err.Error(), "0.10 or later") {
		t.Errorf("older server: %v", err)
	}
}

// The feature name the CLI looks for is the one the server announces.
func TestUploadProjectFeatureName(t *testing.T) {
	if client.FeatureUploadProject != api.FeatureUploadProject {
		t.Errorf("client %q, server %q", client.FeatureUploadProject, api.FeatureUploadProject)
	}
}
