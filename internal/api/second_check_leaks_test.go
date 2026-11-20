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

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/secondcheck"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// The second check of leaked keys and risky settings over the API: each
// has its latest verdict, lists filter by it, and the history of verdicts
// is readable by anyone who sees the asset.
func TestSecondCheckOfLeaksAPI(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	_, collector, _ := e.st.CreateToken(ctx, "c", auth.RoleCollector, nil, 0, 0)

	var meta struct{ Features []string }
	if code := admin.do("GET", "/api/v1/meta", nil, &meta); code != 200 || !slices.Contains(meta.Features, api.FeatureLeakValueChecks) {
		t.Errorf("meta features: %d %v", code, meta.Features)
	}
	b := model.NewBatch(model.Collector{ID: "linux-agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "web-1",
		Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "web-1"}}})
	b.Observations = []model.Observation{{Purl: "pkg:deb/debian/bash@5.2", Confidence: model.ConfidenceConfirmed}}
	b.Complete = true
	b.Leaks = &model.LeakScan{Complete: true, Found: []model.Leak{
		{Rule: "github-token", Title: "GitHub token", Severity: "critical", Path: "/srv/app/run.sh", Line: 3,
			Fingerprint: strings.Repeat("1a", 16), ValueCheck: &model.LeakValueCheck{Checker: "value/1", Signals: []string{"checksum_valid"}}},
		{Rule: "github-token", Title: "GitHub token", Severity: "critical", Path: "/srv/app/deploy.sh", Line: 3,
			Fingerprint: strings.Repeat("2b", 16), ValueCheck: &model.LeakValueCheck{Checker: "value/1", Signals: []string{"checksum_invalid"}}},
	}}
	b.ConfigFindings = &model.ConfigScan{Complete: true, Found: []model.ConfigFinding{{Rule: "ssh-permit-root-login",
		Category: model.ConfigSSH, Title: "Root login", Severity: "medium", Path: "/etc/ssh/sshd_config", Line: 30,
		Subject: "PermitRootLogin yes", Why: "w", Fix: "f", Fingerprint: strings.Repeat("3c", 16)}}}
	raw, _ := json.Marshal(b)
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/ingest", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+collector)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("ingest: %d", resp.StatusCode)
	}

	type leaks struct{ Items []store.Leak }
	var unchecked leaks
	if code := admin.do("GET", "/api/v1/leaks?second_check=unchecked", nil, &unchecked); code != 200 || len(unchecked.Items) != 2 ||
		unchecked.Items[0].SecondCheck != nil {
		t.Fatalf("before the check: %d %+v", code, unchecked)
	}
	if _, err := (&secondcheck.Runner{Store: e.st}).Recheck(ctx, 0); err != nil {
		t.Fatal(err)
	}
	var lfp leaks
	if code := admin.do("GET", "/api/v1/leaks?second_check=likely_false_positive", nil, &lfp); code != 200 || len(lfp.Items) != 1 ||
		lfp.Items[0].Path != "/srv/app/deploy.sh" || lfp.Items[0].SecondCheck.Checker != store.LeakCheckRules ||
		!strings.Contains(lfp.Items[0].SecondCheck.Reason, "checksum") {
		t.Fatalf("likely false positives: %d %+v", code, lfp)
	}
	if code := admin.do("GET", "/api/v1/leaks?second_check=perhaps", nil, nil); code != 400 {
		t.Errorf("unknown verdict: %d", code)
	}
	var hist struct {
		SecondCheck *store.RecheckVerdict `json:"second_check"`
		Items       []store.RecheckVerdict
	}
	if code := admin.do("GET", fmt.Sprintf("/api/v1/leaks/%d/second-checks", lfp.Items[0].ID), nil, &hist); code != 200 ||
		len(hist.Items) != 1 || hist.SecondCheck == nil || hist.Items[0].Verdict != store.VerdictLikelyFalsePositive {
		t.Fatalf("history: %d %+v", code, hist)
	}
	if code := admin.do("GET", "/api/v1/leaks/999999/second-checks", nil, nil); code != 404 {
		t.Errorf("unknown leak: %d", code)
	}
	var cfg struct{ Items []store.ConfigFinding }
	if code := admin.do("GET", "/api/v1/config-findings?second_check=confirmed", nil, &cfg); code != 200 || len(cfg.Items) != 1 ||
		!strings.Contains(cfg.Items[0].SecondCheck.Reason, "PermitRootLogin yes") {
		t.Fatalf("config findings: %d %+v", code, cfg)
	}
	if code := admin.do("GET", fmt.Sprintf("/api/v1/config-findings/%d/second-checks", cfg.Items[0].ID), nil, &hist); code != 200 ||
		len(hist.Items) != 1 || hist.Items[0].Verdict != store.VerdictConfirmed {
		t.Fatalf("config history: %d %+v", code, hist)
	}
}
