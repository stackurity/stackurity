package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Code findings over the API: a deepsec export imported for a repository
// by its URL, listed for anyone who sees the asset, dismissed only by the
// security role; uploads are checked, limited and bound to what the token
// may report.
func TestCodeFindingsAPI(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	e.user("viewer@x.io", auth.RoleViewer)
	admin := e.login("admin@x.io")
	eng := e.login("eng@x.io")
	viewer := e.login("viewer@x.io")
	_, collector, _ := e.st.CreateToken(ctx, "c", auth.RoleCollector, nil, 0, 0)

	var meta struct{ Features []string }
	if code := admin.do("GET", "/api/v1/meta", nil, &meta); code != 200 || !slices.Contains(meta.Features, api.FeatureCodeFindings) {
		t.Errorf("meta features: %d %v", code, meta.Features)
	}

	ingest := func(b *model.ObservationBatch) int64 {
		t.Helper()
		b.Complete = true
		res, err := e.st.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		return res.AssetID
	}
	repo := ingest(func() *model.ObservationBatch {
		b := model.NewBatch(model.Collector{ID: "repo-scan", Method: "scan"}, model.AssetRef{Kind: model.AssetRepository, Name: "acme/shop",
			Identifiers: []model.Identifier{{Scheme: "git-url", Value: "https://github.com/acme/shop"}}})
		b.Observations = []model.Observation{{Purl: "pkg:npm/express@4.18.0", Confidence: model.ConfidenceConfirmed}}
		return b
	}())
	host := ingest(func() *model.ObservationBatch {
		b := model.NewBatch(model.Collector{ID: "linux-agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "web-1",
			Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "web-1"}}})
		b.Observations = []model.Observation{{Purl: "pkg:deb/debian/bash@5.2", Confidence: model.ConfidenceConfirmed}}
		return b
	}())

	doc, err := os.ReadFile("../codefindings/testdata/deepsec-export.json")
	if err != nil {
		t.Fatal(err)
	}
	post := func(token, query string, body []byte) (int, string) {
		t.Helper()
		return bearerBody(e, token, "POST", "/api/v1/code-findings/import?"+query, body)
	}

	// Refused: no asset, a host, an unknown repository, a bad format, a
	// SARIF log sent as deepsec, a viewer.
	for name, c := range map[string]struct {
		query string
		body  []byte
		code  int
	}{
		"no asset":         {"format=deepsec", doc, 400},
		"both":             {"format=deepsec&asset_id=1&git_url=https://github.com/acme/shop", doc, 400},
		"host":             {"format=deepsec&asset_id=" + itoa(host), doc, 400},
		"unknown repo":     {"format=deepsec&git_url=https://github.com/acme/other", doc, 404},
		"format":           {"format=csv&asset_id=" + itoa(repo), doc, 400},
		"wrong document":   {"format=deepsec&asset_id=" + itoa(repo), []byte(`{"version":"2.1.0","runs":[]}`), 400},
		"not json":         {"format=sarif&asset_id=" + itoa(repo), []byte(`<html>`), 400},
		"model too long":   {"format=deepsec&asset_id=" + itoa(repo) + "&model=" + strings.Repeat("m", 129), doc, 400},
		"complete not set": {"format=deepsec&asset_id=" + itoa(repo) + "&complete=maybe", doc, 400},
	} {
		if code, body := post(collector, c.query, c.body); code != c.code {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	if code := viewer.do("POST", "/api/v1/code-findings/import?format=deepsec&asset_id="+itoa(repo), json.RawMessage(doc), nil); code != 403 {
		t.Errorf("viewer import: %d", code)
	}
	// Over the size limit: refused before it is parsed.
	big := append([]byte("["), bytes.Repeat([]byte(" "), 17<<20)...)
	if code, body := post(collector, "format=deepsec&asset_id="+itoa(repo), append(big, ']')); code != 413 && code != 400 {
		t.Errorf("oversized: %d %s", code, body)
	}

	code, body := post(collector, "format=deepsec&git_url=https://github.com/acme/shop.git&model=claude-opus-4-1", doc)
	if code != 201 {
		t.Fatalf("import: %d %s", code, body)
	}
	var res store.CodeImportResult
	_ = json.Unmarshal([]byte(body), &res)
	if res.AssetID != repo || len(res.Sources) != 1 || res.Sources[0].Found != 4 || res.Sources[0].Closed != 1 {
		t.Errorf("import result: %s", body)
	}

	type listed struct {
		Items   []store.CodeFinding       `json:"items"`
		Total   int64                     `json:"total"`
		Imports *[]store.CodeImportRecord `json:"imports"`
	}
	var all listed
	if code := eng.do("GET", "/api/v1/code-findings?severity=critical,high", nil, &all); code != 200 || all.Total != 2 || all.Imports != nil {
		t.Fatalf("list: %d %+v", code, all)
	}
	for _, f := range all.Items {
		if strings.Contains(f.Description+f.Recommendation+f.VerdictNote, "@acme.example") {
			t.Errorf("an owner's address was stored: %+v", f)
		}
	}
	var asset listed
	if code := viewer.do("GET", "/api/v1/assets/"+itoa(repo)+"/code-findings?status=all", nil, &asset); code != 200 || asset.Total != 4 ||
		asset.Imports == nil || len(*asset.Imports) != 1 || (*asset.Imports)[0].Model != "claude-opus-4-1" {
		t.Errorf("asset list: %d %+v", code, asset)
	}
	var none listed
	if code := viewer.do("GET", "/api/v1/assets/"+itoa(host)+"/code-findings", nil, &none); code != 200 || none.Imports == nil || len(*none.Imports) != 0 {
		t.Errorf("never imported: %d %+v", code, none)
	}
	var sum store.CodeSummary
	if code := viewer.do("GET", "/api/v1/code-findings/summary?asset_id="+itoa(repo), nil, &sum); code != 200 || sum.BySeverity["critical"] != 1 {
		t.Errorf("summary: %d %+v", code, sum)
	}
	if code := viewer.do("GET", "/api/v1/code-findings?category=nope", nil, nil); code != 400 {
		t.Errorf("bad category: %d", code)
	}

	// Dismissing is for the security role.
	id := itoa(all.Items[0].ID)
	if code := eng.do("POST", "/api/v1/code-findings/"+id+"/dismiss", map[string]string{"note": "n"}, nil); code != 403 {
		t.Errorf("engineer dismiss: %d", code)
	}
	var c store.CodeFinding
	if code := admin.do("POST", "/api/v1/code-findings/"+id+"/dismiss", map[string]string{"note": "tracked in JIRA-1"}, &c); code != 200 ||
		c.Resolution != "dismissed" {
		t.Errorf("dismiss: %d %+v", code, c)
	}
	if code := admin.do("POST", "/api/v1/code-findings/"+id+"/undismiss", nil, &c); code != 200 || c.Status != "open" {
		t.Errorf("undismiss: %d %+v", code, c)
	}

	// A CI job's token imports only for its own repository.
	trust, err := e.st.CreateCITrust(ctx, store.CITrust{Name: "ci", Provider: "github", Issuer: "https://token.actions.githubusercontent.com",
		Repository: "acme/shop"})
	if err != nil {
		t.Fatal(err)
	}
	_, ci, err := e.st.IssueCIToken(context.Background(), *trust, store.CIToken{Name: "job", RepositoryURL: "https://github.com/acme/shop",
		TTL: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if code, body := post(ci, "format=deepsec&asset_id="+itoa(repo), doc); code != 403 {
		t.Errorf("CI token by asset id: %d %s", code, body)
	}
	if code, body := post(ci, "format=deepsec&git_url=https://github.com/acme/other", doc); code != 403 {
		t.Errorf("CI token for another repository: %d %s", code, body)
	}
	if code, body := post(ci, "format=deepsec&complete=false&git_url=https://github.com/acme/shop", doc); code != 201 {
		t.Errorf("CI token for its repository: %d %s", code, body)
	}

	var audit struct {
		Items []struct{ Action string } `json:"items"`
	}
	admin.do("GET", "/api/v1/audit?object_type=asset&object_id="+itoa(repo), nil, &audit)
	if !slices.ContainsFunc(audit.Items, func(a struct{ Action string }) bool { return a.Action == "code_findings.import" }) {
		t.Errorf("import not audited: %+v", audit)
	}
}
