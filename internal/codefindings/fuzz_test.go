package codefindings

import (
	"os"
	"regexp"
	"testing"
	"unicode/utf8"
)

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

// FuzzParse feeds arbitrary documents to both readers. They must never
// panic, and whatever they accept must fit the database's limits
// (migration 0121's CHECK constraints).
func FuzzParse(f *testing.F) {
	for _, name := range []string{"deepsec-export.json", "semgrep.sarif"} {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	for _, s := range []string{`[]`, `{}`, `[{"metadata":{}}]`, `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"r","ruleIndex":9}]}]}`,
		`[{"metadata":{"vulnSlug":"x","filePath":"a","severity":"LOW","lineNumbers":[9999999999]}}]`, "\x00\xff", `null`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, format := range []string{FormatDeepsec, FormatSARIF} {
			rep, err := Parse(format, data)
			if err != nil {
				continue
			}
			if rep.Count() > MaxFindings {
				t.Fatalf("%s: %d findings", format, rep.Count())
			}
			for _, run := range rep.Runs {
				if !regexp.MustCompile(`^[a-z0-9][a-z0-9:._-]{0,79}$`).MatchString(run.Source) || len(run.Tool) > maxTool ||
					len(run.ToolVersion) > maxToolVersion || len(run.RunID) > maxRunID {
					t.Fatalf("%s run: %+v", format, run)
				}
				for _, x := range run.Findings {
					if x.Rule == "" || len(x.Rule) > maxRule || len(x.Title) > maxTitle || len(x.Path) > maxPath ||
						len(x.Description) > maxDescription || len(x.Recommendation) > maxRecommendation ||
						len(x.VerdictNote) > maxVerdictNote || !ValidSeverity(x.Severity) || !ValidVerdict(x.Verdict) ||
						!hex32.MatchString(x.Fingerprint) || x.StartLine < 0 || x.EndLine < x.StartLine ||
						!utf8.ValidString(x.Title+x.Description+x.Path) {
						t.Fatalf("%s finding: %+v", format, x)
					}
				}
			}
		}
	})
}
