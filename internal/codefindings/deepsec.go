package codefindings

import (
	"bytes"
	"encoding/json"
	"strings"
)

// deepsecFinding is one element of `deepsec export --format json`
// (ExportedFinding in packages/deepsec/src/commands/export.ts). Fields
// that name people (assignee, metadata.owners) are deliberately absent, so
// they are never decoded.
type deepsecFinding struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Metadata    *struct {
		ProjectID    string `json:"projectId"`
		FilePath     string `json:"filePath"`
		LineNumbers  []int  `json:"lineNumbers"`
		Severity     string `json:"severity"`
		VulnSlug     string `json:"vulnSlug"`
		Confidence   string `json:"confidence"`
		DiscoveredAt string `json:"discoveredAt"`
		RunID        string `json:"runId"`
		Revalidation *struct {
			Verdict   string `json:"verdict"`
			Reasoning string `json:"reasoning"`
		} `json:"revalidation"`
	} `json:"metadata"`
}

// deepsecSeverity maps deepsec's severities to Stackurity's scale and a
// category: HIGH_BUG and BUG are non-security bugs, listed only.
var deepsecSeverity = map[string][2]string{
	"CRITICAL": {"critical", CategorySecurity},
	"HIGH":     {"high", CategorySecurity},
	"MEDIUM":   {"medium", CategorySecurity},
	"LOW":      {"low", CategorySecurity},
	"HIGH_BUG": {"low", CategoryBug},
	"BUG":      {"info", CategoryBug},
}

// The headings export.ts's buildDescription writes. The finding's own text
// is under "## Finding", the fix under "## Recommendation"; the owner
// sections (with people's names and email addresses) are not read.
var deepsecSections = []string{"\n## Owners\n", "\n## Finding\n", "\n## Recommendation\n", "\n## Revalidation\n",
	"\n## Top contributors\n", "\n## Recent committers"}

// deepsecSection returns the text under one of export.ts's "## " headings,
// up to the next of them.
func deepsecSection(md, heading string) string {
	md = "\n" + strings.ReplaceAll(md, "\r\n", "\n")
	h := "\n## " + heading + "\n"
	i := strings.Index(md, h)
	if i < 0 {
		return ""
	}
	rest := md[i+len(h):]
	end := len(rest)
	for _, next := range deepsecSections {
		if next == h {
			continue
		}
		if j := strings.Index(rest, next); j >= 0 && j < end {
			end = j
		}
	}
	return rest[:end]
}

func parseDeepsec(data []byte) (*Report, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '[' {
		return nil, invalid("not a deepsec export: expected the JSON array that `deepsec export --format json` writes")
	}
	var in []deepsecFinding
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, invalid("not a deepsec export: %v", err)
	}
	if len(in) > MaxFindings {
		return nil, invalid("%d findings; at most %d can be imported at once", len(in), MaxFindings)
	}
	run := Run{Source: FormatDeepsec, Tool: "deepsec", Findings: make([]Finding, 0, len(in))}
	project := ""
	for i, d := range in {
		m := d.Metadata
		if m == nil || strings.TrimSpace(m.VulnSlug) == "" || strings.TrimSpace(m.FilePath) == "" {
			return nil, invalid("finding %d: not a deepsec finding (metadata.vulnSlug and metadata.filePath are required)", i+1)
		}
		if project == "" {
			project = m.ProjectID
		} else if m.ProjectID != project {
			return nil, invalid("the export holds more than one deepsec project (%q and %q): export one at a time with --project-id, "+
				"and import each into its own repository", clean(project, 64, false), clean(m.ProjectID, 64, false))
		}
		sev := m.Severity
		if sev == "" {
			sev = d.Severity
		}
		mapped, ok := deepsecSeverity[sev]
		if !ok {
			return nil, invalid("finding %d: unknown severity %q", i+1, clean(sev, 32, false))
		}
		start, end, err := lines(m.LineNumbers)
		if err != nil {
			return nil, invalid("finding %d: %v", i+1, err)
		}
		conf := strings.ToLower(m.Confidence)
		switch conf {
		case "high", "medium", "low", "":
		default:
			conf = ""
		}
		f := Finding{
			Rule:           clean(m.VulnSlug, maxRule, false),
			Category:       mapped[1],
			Severity:       mapped[0],
			Path:           cleanPath(m.FilePath),
			StartLine:      start,
			EndLine:        end,
			Description:    clean(deepsecSection(d.Description, "Finding"), maxDescription, true),
			Recommendation: clean(deepsecSection(d.Description, "Recommendation"), maxRecommendation, true),
			Confidence:     conf,
		}
		if f.Rule == "" {
			return nil, invalid("finding %d: metadata.vulnSlug is empty", i+1)
		}
		// export.ts prefixes the title with "[SEVERITY] ".
		f.Title = clean(strings.TrimPrefix(d.Title, "["+d.Severity+"] "), maxTitle, false)
		if f.Title == "" {
			f.Title = f.Rule
		}
		if rv := m.Revalidation; rv != nil {
			v := strings.ToLower(strings.TrimSpace(rv.Verdict))
			if !ValidVerdict(v) || v == VerdictSuppressed {
				return nil, invalid("finding %d: unknown revalidation verdict %q", i+1, clean(v, 32, false))
			}
			f.Verdict = v
			f.VerdictNote = clean(rv.Reasoning, maxVerdictNote, true)
		}
		f.Fingerprint = fingerprint(run.Source, f.Rule, f.Path, f.Title)
		if m.RunID > run.RunID { // deepsec run ids sort by time
			run.RunID = clean(m.RunID, maxRunID, false)
		}
		run.Findings = append(run.Findings, f)
	}
	return &Report{Format: FormatDeepsec, Runs: []Run{run}}, nil
}
