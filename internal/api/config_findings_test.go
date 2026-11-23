package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/collect/confcheck"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Config findings over the API: listed for anyone who sees the asset, an
// asset's list says whether it was checked, and only the security role
// dismisses one.
func TestConfigFindingsAPI(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	admin := e.login("admin@x.io")
	eng := e.login("eng@x.io")
	_, collector, _ := e.st.CreateToken(ctx, "c", auth.RoleCollector, nil, 0, 0)

	var meta struct{ Features []string }
	if code := admin.do("GET", "/api/v1/meta", nil, &meta); code != 200 || !slices.Contains(meta.Features, api.FeatureConfigFindings) {
		t.Errorf("meta features: %d %v", code, meta.Features)
	}
	send := func(name string, found ...model.ConfigFinding) store.IngestResult {
		t.Helper()
		b := model.NewBatch(model.Collector{ID: "linux-agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: name,
			Identifiers: []model.Identifier{{Scheme: "machine-id", Value: name}}})
		b.Observations = []model.Observation{{Purl: "pkg:deb/debian/bash@5.2", Confidence: model.ConfidenceConfirmed}}
		b.Complete = true
		if found != nil {
			b.ConfigFindings = &model.ConfigScan{Found: found, Complete: true}
		}
		raw, _ := json.Marshal(b)
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/ingest", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+collector)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var res store.IngestResult
		if resp.StatusCode != 201 || json.NewDecoder(resp.Body).Decode(&res) != nil {
			t.Fatalf("ingest %s: %d", name, resp.StatusCode)
		}
		return res
	}
	hook := model.ConfigFinding{Rule: "agent-hook-remote-exec", Category: model.ConfigAgentHook, Title: "Claude Code hook downloads and runs code",
		Severity: "high", Path: "/root/.claude/settings.json", Line: 4, Subject: "SessionStart: x", Why: "why", Fix: "fix",
		Fingerprint: strings.Repeat("3a", 16)}
	one := send("web-1", hook)
	if one.ConfigFound != 1 {
		t.Errorf("ingest: %+v", one)
	}
	unchecked := send("web-2")

	type listed struct {
		Items []store.ConfigFinding `json:"items"`
		Scans *[]store.ConfigScan   `json:"scans"`
	}
	var all listed
	if code := eng.do("GET", "/api/v1/config-findings?severity=high", nil, &all); code != 200 || len(all.Items) != 1 || all.Scans != nil {
		t.Fatalf("list: %d %+v", code, all)
	}
	var asset listed
	if code := eng.do("GET", "/api/v1/assets/"+itoa(unchecked.AssetID)+"/config-findings", nil, &asset); code != 200 || asset.Scans == nil ||
		len(*asset.Scans) != 0 {
		t.Errorf("unchecked asset: %d %+v", code, asset)
	}
	if code := eng.do("GET", "/api/v1/config-findings?severity=critical", nil, nil); code != 400 {
		t.Errorf("bad severity: %d", code)
	}
	id := itoa(all.Items[0].ID)
	if code := eng.do("POST", "/api/v1/config-findings/"+id+"/dismiss", map[string]any{"note": "x"}, nil); code != 403 {
		t.Errorf("engineer dismisses: %d", code)
	}
	var got store.ConfigFinding
	if code := admin.do("POST", "/api/v1/config-findings/"+id+"/dismiss", map[string]any{"note": "meant to be there"}, &got); code != 200 ||
		got.Resolution != "dismissed" {
		t.Errorf("dismiss: %d %+v", code, got)
	}
	if code := admin.do("POST", "/api/v1/config-findings/"+id+"/undismiss", nil, &got); code != 200 || got.Status != "open" {
		t.Errorf("undismiss: %d %+v", code, got)
	}

	// Attack tools: a category of their own, with a doc link.
	if !slices.Contains(meta.Features, api.FeatureConfigAttackTools) {
		t.Errorf("meta features lack %s: %v", api.FeatureConfigAttackTools, meta.Features)
	}
	if r := send("ci-runner", confcheck.ImageAttackTools("tomicdd/artex:latest")...); r.ConfigFound != 1 {
		t.Errorf("ingest attack tool: %+v", r)
	}
	var tools listed
	if code := eng.do("GET", "/api/v1/config-findings?category=attack_tool", nil, &tools); code != 200 || len(tools.Items) != 1 ||
		tools.Items[0].Rule != confcheck.RuleAttackToolArtexBackdoor || tools.Items[0].DocURL != confcheck.AttackToolsDoc {
		t.Errorf("attack tools: %d %+v", code, tools)
	}

	// Kernel modules (SCTP, nginx2root): a category of their own too.
	if !slices.Contains(meta.Features, api.FeatureConfigKernel) {
		t.Errorf("meta features lack %s: %v", api.FeatureConfigKernel, meta.Features)
	}
	sctp := model.ConfigFinding{Rule: confcheck.RuleKernelSCTP, Category: model.ConfigKernel, Title: "SCTP kernel module can be used to become root",
		Severity: "low", Path: "/lib/modules/6.8.0-49-generic/kernel/net/sctp/sctp.ko.zst", Subject: "sctp loadable in kernel 6.8.0-49-generic",
		Why: "loadable", Fix: "install sctp /bin/false",
		Fingerprint: confcheck.Fingerprint(confcheck.RuleKernelSCTP, "/lib/modules/6.8.0-49-generic/kernel/net/sctp/sctp.ko.zst", "sctp loadable in kernel 6.8.0-49-generic")}
	if r := send("web-1", sctp); r.ConfigFound != 1 {
		t.Errorf("ingest kernel: %+v", r)
	}
	var kern listed
	if code := eng.do("GET", "/api/v1/config-findings?category=kernel", nil, &kern); code != 200 || len(kern.Items) != 1 ||
		kern.Items[0].Rule != confcheck.RuleKernelSCTP || kern.Items[0].DocURL != confcheck.KernelModulesDoc {
		t.Errorf("kernel: %d %+v", code, kern)
	}
}
