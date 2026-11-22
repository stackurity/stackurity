package codefindings

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDeepsecExport(t *testing.T) {
	rep, err := Parse(FormatDeepsec, read(t, "deepsec-export.json"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Format != FormatDeepsec || len(rep.Runs) != 1 || rep.Runs[0].Source != "deepsec" || rep.Runs[0].Tool != "deepsec" {
		t.Fatalf("report: %+v", rep)
	}
	run := rep.Runs[0]
	if run.RunID != "20261118101530-c3d4" {
		t.Errorf("run id: the latest of the findings' runs, got %q", run.RunID)
	}
	if len(run.Findings) != 4 {
		t.Fatalf("findings: %d", len(run.Findings))
	}
	sqli := run.Findings[0]
	want := Finding{Rule: "sql-injection", Category: CategorySecurity, Severity: "critical", Path: "src/api/orders/search.ts",
		StartLine: 41, EndLine: 48, Confidence: "high", Verdict: VerdictTruePositive,
		Title: "SQL injection in order search via unescaped sort column"}
	if sqli.Rule != want.Rule || sqli.Category != want.Category || sqli.Severity != want.Severity || sqli.Path != want.Path ||
		sqli.StartLine != want.StartLine || sqli.EndLine != want.EndLine || sqli.Confidence != want.Confidence ||
		sqli.Verdict != want.Verdict || sqli.Title != want.Title {
		t.Errorf("sql injection:\n got %+v\nwant %+v", sqli, want)
	}
	if !strings.HasPrefix(sqli.Description, "The `sort` query parameter") || strings.Contains(sqli.Description, "Recommendation") {
		t.Errorf("description is the Finding section only: %q", sqli.Description)
	}
	if sqli.Recommendation != "Map `sort` to an allowlist of column names and pass values as bound parameters." {
		t.Errorf("recommendation: %q", sqli.Recommendation)
	}
	if !strings.Contains(sqli.VerdictNote, "reachable without authentication") {
		t.Errorf("verdict note: %q", sqli.VerdictNote)
	}
	// People named in the export (owners, on-call, committers) are never
	// kept.
	for _, f := range run.Findings {
		all := f.Title + f.Description + f.Recommendation + f.VerdictNote
		for _, p := range []string{"@acme.example", "Dana", "Sam Dev", "Checkout"} {
			if strings.Contains(all, p) {
				t.Errorf("%s keeps %q: %+v", f.Rule, p, f)
			}
		}
	}

	authz := run.Findings[1]
	if strings.ContainsRune(authz.Description, '\u202e') {
		t.Errorf("bidirectional override kept: %q", authz.Description)
	}
	if authz.Title != "Missing authorization check on invoice download <script>alert(1)</script>" {
		t.Errorf("title kept as text (shown escaped): %q", authz.Title)
	}
	if fp := run.Findings[2]; fp.Verdict != VerdictFalsePositive || !Closed(fp.Verdict) {
		t.Errorf("false positive: %+v", fp)
	}
	bug := run.Findings[3]
	if bug.Category != CategoryBug || bug.Severity != "low" || bug.Path != "src/jobs/refund.ts" || bug.StartLine != 77 || bug.EndLine != 90 {
		t.Errorf("HIGH_BUG: %+v", bug)
	}

	// The same finding imported again has the same fingerprint, whatever
	// its lines; another title in the same file and rule does not.
	again, _ := Parse(FormatDeepsec, []byte(strings.ReplaceAll(string(read(t, "deepsec-export.json")), "[41, 44, 48]", "[52]")))
	if again.Runs[0].Findings[0].Fingerprint != sqli.Fingerprint {
		t.Error("fingerprint changed with the line numbers")
	}
	if sqli.Fingerprint == authz.Fingerprint || len(sqli.Fingerprint) != 32 {
		t.Errorf("fingerprints: %q %q", sqli.Fingerprint, authz.Fingerprint)
	}
}

func TestSARIF(t *testing.T) {
	rep, err := Parse(FormatSARIF, read(t, "semgrep.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Runs) != 1 {
		t.Fatalf("runs: %+v", rep.Runs)
	}
	run := rep.Runs[0]
	if run.Source != "sarif:semgrep-oss" || run.Tool != "Semgrep OSS" || run.ToolVersion != "1.95.0" || run.RunID != "semgrep/ci/2026-11-20" ||
		run.Skipped != 1 || len(run.Findings) != 3 {
		t.Fatalf("run: %+v", run)
	}
	xss := run.Findings[0]
	if xss.Severity != "high" || xss.Category != CategorySecurity || xss.Title != "Untrusted input written directly to the response" ||
		xss.Path != "src/routes/hello.js" || xss.StartLine != 14 || xss.EndLine != 15 ||
		xss.Recommendation != "Render through a template engine that escapes output." || xss.Description != "req.query.name reaches res.send()" {
		t.Errorf("xss: %+v", xss)
	}
	lint := run.Findings[1]
	if lint.Severity != "low" || lint.Category != CategoryOther || lint.Path != "src/util.js" || lint.StartLine != 3 || lint.EndLine != 3 {
		t.Errorf("lint: %+v", lint)
	}
	if s := run.Findings[2]; s.Verdict != VerdictSuppressed || s.VerdictNote != "escaped by sanitizeBio()" {
		t.Errorf("suppressed: %+v", s)
	}
}

func TestRejects(t *testing.T) {
	big := "[" + strings.Repeat(`{"metadata":{"vulnSlug":"x","filePath":"a","severity":"LOW","projectId":"p"}},`, MaxFindings) +
		`{"metadata":{"vulnSlug":"x","filePath":"a","severity":"LOW","projectId":"p"}}]`
	for name, c := range map[string]struct{ format, doc string }{
		"sarif given as deepsec":  {FormatDeepsec, `{"version":"2.1.0","runs":[]}`},
		"deepsec given as sarif":  {FormatSARIF, `[]`},
		"not json":                {FormatDeepsec, `[{`},
		"no slug":                 {FormatDeepsec, `[{"title":"x","metadata":{"filePath":"a","severity":"LOW"}}]`},
		"unknown severity":        {FormatDeepsec, `[{"metadata":{"vulnSlug":"x","filePath":"a","severity":"SEVERE"}}]`},
		"unknown verdict":         {FormatDeepsec, `[{"metadata":{"vulnSlug":"x","filePath":"a","severity":"LOW","revalidation":{"verdict":"maybe"}}}]`},
		"two projects":            {FormatDeepsec, `[{"metadata":{"vulnSlug":"x","filePath":"a","severity":"LOW","projectId":"p"}},{"metadata":{"vulnSlug":"x","filePath":"a","severity":"LOW","projectId":"q"}}]`},
		"line out of range":       {FormatDeepsec, `[{"metadata":{"vulnSlug":"x","filePath":"a","severity":"LOW","lineNumbers":[-1]}}]`},
		"too many findings":       {FormatDeepsec, big},
		"sarif 2.0":               {FormatSARIF, `{"version":"2.0.0","runs":[{"tool":{"driver":{"name":"x"}}}]}`},
		"sarif without tool name": {FormatSARIF, `{"version":"2.1.0","runs":[{"tool":{"driver":{}},"results":[]}]}`},
		"sarif without rule":      {FormatSARIF, `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"message":{"text":"m"}}]}]}`},
		"not utf-8":               {FormatDeepsec, "[\"\xff\"]"},
		"unknown format":          {"csv", `[]`},
	} {
		if _, err := Parse(c.format, []byte(c.doc)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Parse(FormatDeepsec, make([]byte, MaxDocumentSize+1)); !errors.Is(err, ErrInvalid) {
		t.Errorf("oversized: %v", err)
	}
	// An empty export is valid: there is nothing open any more.
	if rep, err := Parse(FormatDeepsec, []byte(" []\n")); err != nil || rep.Count() != 0 || len(rep.Runs) != 1 {
		t.Errorf("empty export: %+v %v", rep, err)
	}
}

func TestClean(t *testing.T) {
	long := strings.Repeat("é", 400)
	if got := clean(long, maxTitle, false); len(got) > maxTitle || !strings.HasSuffix(got, "…") {
		t.Errorf("cut: %d %q", len(got), got[len(got)-8:])
	}
	if got := clean("a\x00b\x1b[31mc\u2066d\r\ne", 100, true); got != "ab[31mcd\ne" {
		t.Errorf("multiline: %q", got)
	}
	if got := clean("  a\n\tb  ", 100, false); got != "a b" {
		t.Errorf("one line: %q", got)
	}
	if got := sourceName("../../Weird Tool™"); got != "sarif:weird-tool" {
		t.Errorf("source: %q", got)
	}
}
