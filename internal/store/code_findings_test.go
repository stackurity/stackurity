package store_test

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/codefindings"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func deepsecReport(t *testing.T, edit func(string) string) *codefindings.Report {
	t.Helper()
	raw, err := os.ReadFile("../codefindings/testdata/deepsec-export.json")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	if edit != nil {
		doc = edit(doc)
	}
	rep, err := codefindings.Parse(codefindings.FormatDeepsec, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func codeIncident(t *testing.T, s *store.Store, ctx context.Context, assetID int64) *store.SystemIncident {
	t.Helper()
	sys, err := s.DetectSystemProblems(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range sys {
		if sys[i].Kind == "code" && sys[i].Key == "asset:"+strconv.FormatInt(assetID, 10) {
			return &sys[i]
		}
	}
	return nil
}

// A deepsec export imported, imported again, and imported after a fix:
// updated in place, the false positive never open, gone when the export no
// longer has it, dismissed stays dismissed.
func TestCodeFindingImport(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	r, err := s.Ingest(ctx, batch(mid, true, "pkg:npm/express@4.18.0"), 0)
	if err != nil {
		t.Fatal(err)
	}
	asset := r.AssetID

	res, err := s.ImportCodeFindings(ctx, asset, deepsecReport(t, nil), "claude-opus-4-1", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sources) != 1 {
		t.Fatalf("result: %+v", res)
	}
	if got := res.Sources[0]; got.Source != "deepsec" || got.Found != 4 || got.Open != 3 || got.Closed != 1 || got.New != 4 || got.Gone != 0 {
		t.Errorf("first import: %+v", got)
	}
	open, total, err := s.ListCodeFindings(ctx, store.CodeFindingFilter{AssetID: asset})
	if err != nil || total != 3 {
		t.Fatalf("open: %d %v", total, err)
	}
	// Security first, most severe first; bugs after.
	if open[0].Severity != "critical" || open[0].Rule != "sql-injection" || open[2].Category != "bug" {
		t.Errorf("order: %s %s, %s", open[0].Severity, open[0].Rule, open[2].Category)
	}
	if open[0].Model != "claude-opus-4-1" || open[0].Tool != "deepsec" || open[0].RunID != "20261118101530-c3d4" ||
		open[0].Verdict != "true-positive" || open[0].StartLine != 41 || open[0].EndLine != 48 {
		t.Errorf("provenance: %+v", open[0])
	}
	all, _, _ := s.ListCodeFindings(ctx, store.CodeFindingFilter{AssetID: asset, Status: "resolved"})
	if len(all) != 1 || all[0].Verdict != "false-positive" || all[0].Resolution != "verdict" || all[0].ResolvedAt == nil {
		t.Errorf("false positive: %+v", all)
	}
	sum, err := s.SummariseCodeFindings(ctx, asset)
	if err != nil || sum.BySeverity["critical"] != 1 || sum.BySeverity["high"] != 1 || sum.ByCategory["bug"] != 1 || sum.ImportedAssets != 1 {
		t.Errorf("summary: %+v %v", sum, err)
	}
	imports, err := s.CodeImports(ctx, asset)
	if err != nil || len(imports) != 1 || imports[0].Found != 4 || !imports[0].Complete || imports[0].Model != "claude-opus-4-1" {
		t.Errorf("imports: %+v %v", imports, err)
	}

	// One incident for the asset, P1 for the critical; the false positive
	// and the bug are not in it.
	inc := codeIncident(t, s, ctx, asset)
	if inc == nil || inc.Priority != "P1" || inc.Detail["count"] != 2 {
		t.Fatalf("incident: %+v", inc)
	}
	if titles := strings.Join(inc.Detail["titles"].([]string), "|"); strings.Contains(titles, "redirect") || strings.Contains(titles, "Refund") {
		t.Errorf("incident lists a closed or non-security finding: %s", titles)
	}

	// Imported again, with the lines moved: the same rows, nothing new.
	again, err := s.ImportCodeFindings(ctx, asset, deepsecReport(t, func(d string) string {
		return strings.Replace(d, "[41, 44, 48]", "[52, 55]", 1)
	}), "", true)
	if err != nil || again.Sources[0].New != 0 || again.Sources[0].Gone != 0 {
		t.Fatalf("again: %+v %v", again, err)
	}
	moved, _ := s.GetCodeFinding(ctx, open[0].ID)
	if moved.StartLine != 52 || moved.EndLine != 55 || moved.FirstSeen != open[0].FirstSeen {
		t.Errorf("moved: %+v", moved)
	}

	// Dismiss the bug; a later import keeps it dismissed.
	bug := open[2]
	if _, err := s.DismissCodeFinding(ctx, bug.ID, nil, "known"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportCodeFindings(ctx, asset, deepsecReport(t, nil), "", true); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.GetCodeFinding(ctx, bug.ID); b.Resolution != "dismissed" || b.ResolutionNote != "known" {
		t.Errorf("dismissed bug after import: %+v", b)
	}

	// The SQL injection is fixed: deepsec's default export leaves it out,
	// and the import resolves it as gone. A partial import resolves nothing.
	without := func(d string) string {
		i := strings.Index(d, "\n  {\n    \"title\": \"[HIGH] ")
		return "[" + d[i:]
	}
	if res, err := s.ImportCodeFindings(ctx, asset, deepsecReport(t, without), "", false); err != nil || res.Sources[0].Gone != 0 {
		t.Fatalf("partial: %+v %v", res, err)
	}
	if res, err := s.ImportCodeFindings(ctx, asset, deepsecReport(t, without), "", true); err != nil || res.Sources[0].Gone != 1 {
		t.Fatalf("complete: %+v %v", res, err)
	}
	if f, _ := s.GetCodeFinding(ctx, open[0].ID); f.Status != "resolved" || f.Resolution != "gone" {
		t.Errorf("fixed: %+v", f)
	}
	if inc := codeIncident(t, s, ctx, asset); inc == nil || inc.Priority != "P2" {
		t.Errorf("incident after the fix: %+v", inc)
	}

	// Revalidated as a false positive: resolved by the verdict, no incident.
	if _, err := s.ImportCodeFindings(ctx, asset, deepsecReport(t, func(d string) string {
		return strings.Replace(without(d), `"confidence": "medium",
      "discoveredAt": "2026-11-18T09:14:02.551Z",`, `"confidence": "medium",
      "discoveredAt": "2026-11-18T09:14:02.551Z",
      "revalidation": {"verdict": "false-positive", "reasoning": "middleware checks the customer"},`, 1)
	}), "", true); err != nil {
		t.Fatal(err)
	}
	if inc := codeIncident(t, s, ctx, asset); inc != nil {
		t.Errorf("incident for a false positive: %+v", inc)
	}
	if _, err := s.UndismissCodeFinding(ctx, open[0].ID); !errors.Is(err, store.ErrConflict) {
		t.Errorf("undismiss a gone finding: %v", err)
	}
	if b, err := s.UndismissCodeFinding(ctx, bug.ID); err != nil || b.Status != "open" {
		t.Errorf("undismiss: %+v %v", b, err)
	}

	// Another workspace sees none of it.
	other, _, err := s.CreateWorkspace(ctx, "Other", "other", "admin@other.example", "Admin", "A-long-Password-123!")
	if err != nil {
		t.Fatal(err)
	}
	octx := tenant.WithWorkspace(context.Background(), other.ID)
	if items, n, err := s.ListCodeFindings(octx, store.CodeFindingFilter{Status: "all"}); err != nil || n != 0 || len(items) != 0 {
		t.Errorf("other workspace: %d %v", n, err)
	}
	if _, err := s.GetCodeFinding(octx, bug.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("other workspace get: %v", err)
	}
}

// A SARIF log with two tools is two sources; importing one tool's report
// leaves the other's findings alone.
func TestCodeFindingSources(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	r, err := s.Ingest(ctx, batch(mid, true, "pkg:npm/express@4.18.0"), 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile("../codefindings/testdata/semgrep.sarif")
	rep, err := codefindings.Parse(codefindings.FormatSARIF, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportCodeFindings(ctx, r.AssetID, rep, "", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportCodeFindings(ctx, r.AssetID, deepsecReport(t, nil), "", true); err != nil {
		t.Fatal(err)
	}
	semgrep, n, _ := s.ListCodeFindings(ctx, store.CodeFindingFilter{AssetID: r.AssetID, Source: "sarif:semgrep-oss", Status: "all"})
	if n != 3 || semgrep[0].ToolVersion != "1.95.0" {
		t.Errorf("semgrep after deepsec import: %d %+v", n, semgrep)
	}
	sup, _, _ := s.ListCodeFindings(ctx, store.CodeFindingFilter{AssetID: r.AssetID, Source: "sarif:semgrep-oss", Status: "resolved"})
	if len(sup) != 1 || sup[0].Verdict != "suppressed" {
		t.Errorf("suppressed: %+v", sup)
	}
	if _, _, err := s.ListCodeFindings(ctx, store.CodeFindingFilter{Severity: "severe"}); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("bad severity: %v", err)
	}
}
