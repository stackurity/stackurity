package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// stackurity import code-findings checks the report locally, checks the
// server takes code findings, and uploads the file as it is with the asset,
// format, model and completeness in the query.
func TestImportCodeFindings(t *testing.T) {
	var got url.Values
	var body []byte
	features := []string{"code_findings"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/meta":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "0.21.0", "features": features})
		case "/api/v1/code-findings/import":
			got = r.URL.Query()
			body, _ = io.ReadAll(r.Body)
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"asset_id":7,"complete":true,"sources":[{"source":"deepsec","found":4,"open":3,"closed":1,"new":4,"gone":0}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("STACKURITY_SERVER", srv.URL)
	t.Setenv("STACKURITY_TOKEN", "stk_test")
	t.Setenv("STACKURITY_PROJECT", "")
	t.Setenv("STACKURITY_GIT_URL", "")
	run := func(args ...string) (string, error) {
		c := importCmd()
		var out bytes.Buffer
		c.SetOut(&out)
		c.SetErr(io.Discard)
		c.SetArgs(append([]string{"code-findings"}, args...))
		err := c.Execute()
		return out.String(), err
	}
	fixture := "../../internal/codefindings/testdata/deepsec-export.json"

	out, err := run(fixture, "--format", "deepsec", "--asset", "https://github.com/acme/shop", "--model", "claude-opus-4-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Get("format") != "deepsec" || got.Get("git_url") != "https://github.com/acme/shop" || got.Get("model") != "claude-opus-4-1" ||
		got.Has("complete") || got.Has("asset_id") {
		t.Errorf("query: %v", got)
	}
	if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
		t.Errorf("body: %.40s", body)
	}
	if !strings.Contains(out, "asset 7, deepsec: 4 findings (3 open, 1 closed by the source's verdict, 4 new), 0 resolved as gone") {
		t.Errorf("output: %q", out)
	}

	if _, err := run(fixture, "--format", "deepsec", "--asset", "7", "--partial"); err != nil || got.Get("asset_id") != "7" ||
		got.Get("complete") != "false" {
		t.Errorf("by id, partial: %v %v", got, err)
	}

	// Checked here first: a SARIF log given as deepsec is not uploaded.
	got = nil
	if _, err := run("../../internal/codefindings/testdata/semgrep.sarif", "--format", "deepsec", "--asset", "7"); err == nil || got != nil {
		t.Errorf("wrong format: %v, uploaded %v", err, got)
	}
	if _, err := run(fixture, "--format", "deepsec"); err == nil || !strings.Contains(err.Error(), "--asset") {
		t.Errorf("no asset: %v", err)
	}
	features = nil
	if _, err := run(fixture, "--format", "deepsec", "--asset", "7"); err == nil || !strings.Contains(err.Error(), "upgrade") {
		t.Errorf("old server: %v", err)
	}
}
