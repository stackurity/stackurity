package codefindings

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// SARIF 2.1.0 (OASIS): the parts a code finding needs. Unknown properties
// are ignored.

type sarifMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

func (m *sarifMessage) text() string {
	if m == nil {
		return ""
	}
	if m.Text != "" {
		return m.Text
	}
	return m.Markdown
}

type sarifRule struct {
	ID                   string        `json:"id"`
	Name                 string        `json:"name"`
	ShortDescription     *sarifMessage `json:"shortDescription"`
	FullDescription      *sarifMessage `json:"fullDescription"`
	Help                 *sarifMessage `json:"help"`
	DefaultConfiguration *struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties map[string]any `json:"properties"`
}

type sarifResult struct {
	RuleID    string `json:"ruleId"`
	RuleIndex *int   `json:"ruleIndex"`
	Rule      *struct {
		ID    string `json:"id"`
		Index *int   `json:"index"`
	} `json:"rule"`
	Kind      string       `json:"kind"`
	Level     string       `json:"level"`
	Message   sarifMessage `json:"message"`
	Locations []struct {
		PhysicalLocation *struct {
			ArtifactLocation *struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region *struct {
				StartLine int `json:"startLine"`
				EndLine   int `json:"endLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
	Fingerprints        map[string]string `json:"fingerprints"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Suppressions        []struct {
		Kind          string `json:"kind"`
		Status        string `json:"status"`
		Justification string `json:"justification"`
	} `json:"suppressions"`
	BaselineState string         `json:"baselineState"`
	Properties    map[string]any `json:"properties"`
}

type sarifLog struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name            string      `json:"name"`
				Version         string      `json:"version"`
				SemanticVersion string      `json:"semanticVersion"`
				Rules           []sarifRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		AutomationDetails *struct {
			ID   string `json:"id"`
			GUID string `json:"guid"`
		} `json:"automationDetails"`
		Results []sarifResult `json:"results"`
	} `json:"runs"`
}

// sarifSeverity is the finding's severity: GitHub's security-severity
// property (a CVSS-like score on the rule or result) when there is one,
// otherwise the SARIF level (error high, warning medium, note low, none
// info).
func sarifSeverity(level string, props ...map[string]any) string {
	for _, p := range props {
		if score, ok := securitySeverity(p); ok {
			switch {
			case score >= 9:
				return "critical"
			case score >= 7:
				return "high"
			case score >= 4:
				return "medium"
			case score > 0:
				return "low"
			default:
				return "info"
			}
		}
	}
	switch level {
	case "error":
		return "high"
	case "note":
		return "low"
	case "none":
		return "info"
	}
	return "medium" // "warning", SARIF's default
}

func securitySeverity(p map[string]any) (float64, bool) {
	v, ok := p["security-severity"]
	if !ok {
		return 0, false
	}
	var f float64
	switch x := v.(type) {
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		if err != nil {
			return 0, false
		}
		f = n
	case float64:
		f = x
	default:
		return 0, false
	}
	return f, f >= 0 && f <= 10
}

// sarifCategory: security when the rule says so (a security-severity, or a
// "security" tag), otherwise other.
func sarifCategory(props ...map[string]any) string {
	for _, p := range props {
		if _, ok := securitySeverity(p); ok {
			return CategorySecurity
		}
		if tags, ok := p["tags"].([]any); ok {
			for _, t := range tags {
				if s, _ := t.(string); strings.EqualFold(s, "security") {
					return CategorySecurity
				}
			}
		}
	}
	return CategoryOther
}

func parseSARIF(data []byte) (*Report, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return nil, invalid("not a SARIF log: expected a JSON object")
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, invalid("not a SARIF log: %v", err)
	}
	if log.Version != "2.1.0" {
		return nil, invalid("SARIF version %q; only 2.1.0 is read", clean(log.Version, 16, false))
	}
	if len(log.Runs) == 0 {
		return nil, invalid("the SARIF log has no runs")
	}
	if len(log.Runs) > MaxRuns {
		return nil, invalid("%d SARIF runs; at most %d", len(log.Runs), MaxRuns)
	}
	total := 0
	for _, r := range log.Runs {
		total += len(r.Results)
	}
	if total > MaxFindings {
		return nil, invalid("%d results; at most %d can be imported at once", total, MaxFindings)
	}
	rep := &Report{Format: FormatSARIF}
	bySource := map[string]int{}
	for ri, r := range log.Runs {
		d := r.Tool.Driver
		tool := clean(d.Name, maxTool, false)
		if tool == "" {
			return nil, invalid("run %d: tool.driver.name is required", ri+1)
		}
		ver := d.SemanticVersion
		if ver == "" {
			ver = d.Version
		}
		run := Run{Source: sourceName(tool), Tool: tool, ToolVersion: clean(ver, maxToolVersion, false)}
		if a := r.AutomationDetails; a != nil {
			run.RunID = clean(a.ID, maxRunID, false)
			if run.RunID == "" {
				run.RunID = clean(a.GUID, maxRunID, false)
			}
		}
		rules := map[string]*sarifRule{}
		for i := range d.Rules {
			rules[d.Rules[i].ID] = &d.Rules[i]
		}
		for i, res := range r.Results {
			f, ok, err := sarifFinding(run.Source, d.Rules, rules, res)
			if err != nil {
				return nil, invalid("run %d, result %d: %v", ri+1, i+1, err)
			}
			if !ok {
				run.Skipped++
				continue
			}
			run.Findings = append(run.Findings, f)
		}
		// Two runs of the same tool in one log are one source.
		if at, ok := bySource[run.Source]; ok {
			prev := &rep.Runs[at]
			prev.Findings = append(prev.Findings, run.Findings...)
			prev.Skipped += run.Skipped
			continue
		}
		bySource[run.Source] = len(rep.Runs)
		rep.Runs = append(rep.Runs, run)
	}
	return rep, nil
}

// sarifFinding converts one result; ok is false for a result that is not
// imported (not a failure, or absent from the baseline).
func sarifFinding(source string, ruleList []sarifRule, rules map[string]*sarifRule, res sarifResult) (Finding, bool, error) {
	switch res.Kind {
	case "", "fail":
	default: // pass, open, review, informational, notApplicable
		return Finding{}, false, nil
	}
	if res.BaselineState == "absent" {
		return Finding{}, false, nil
	}
	rule, ruleID := sarifRuleOf(ruleList, rules, res)
	if ruleID == "" {
		return Finding{}, false, fmt.Errorf("ruleId is required")
	}
	f := Finding{Rule: clean(ruleID, maxRule, false), Description: clean(res.Message.text(), maxDescription, true)}
	if f.Rule == "" {
		return Finding{}, false, fmt.Errorf("ruleId is empty")
	}
	level := res.Level
	var ruleProps map[string]any
	if rule != nil {
		ruleProps = rule.Properties
		if level == "" && rule.DefaultConfiguration != nil {
			level = rule.DefaultConfiguration.Level
		}
		f.Title = rule.ShortDescription.text()
		if f.Title == "" {
			f.Title = rule.Name
		}
		f.Recommendation = clean(rule.Help.text(), maxRecommendation, true)
		if f.Description == "" {
			f.Description = clean(rule.FullDescription.text(), maxDescription, true)
		}
	}
	if f.Title == "" {
		f.Title = firstLine(res.Message.text())
	}
	f.Title = clean(f.Title, maxTitle, false)
	if f.Title == "" {
		f.Title = f.Rule
	}
	f.Severity = sarifSeverity(level, res.Properties, ruleProps)
	f.Category = sarifCategory(res.Properties, ruleProps)
	if len(res.Locations) > 0 && res.Locations[0].PhysicalLocation != nil {
		pl := res.Locations[0].PhysicalLocation
		if pl.ArtifactLocation != nil {
			f.Path = cleanPath(pl.ArtifactLocation.URI)
		}
		if rg := pl.Region; rg != nil {
			start, end, err := lines([]int{rg.StartLine, rg.EndLine})
			if err != nil {
				return Finding{}, false, err
			}
			f.StartLine, f.EndLine = start, end
		}
	}
	for _, s := range res.Suppressions {
		if s.Status == "" || s.Status == "accepted" {
			f.Verdict = VerdictSuppressed
			f.VerdictNote = clean(s.Justification, maxVerdictNote, true)
			break
		}
	}
	f.Fingerprint = fingerprint(source, f.Rule, f.Path, sarifKey(res))
	return f, true, nil
}

// sarifRuleOf finds a result's rule: by ruleIndex (or rule.index), else by
// id among the driver's rules. The id is the result's ruleId, rule.id, or
// the indexed rule's.
func sarifRuleOf(ruleList []sarifRule, rules map[string]*sarifRule, res sarifResult) (*sarifRule, string) {
	var rule *sarifRule
	idx := res.RuleIndex
	if res.Rule != nil && idx == nil {
		idx = res.Rule.Index
	}
	if idx != nil && *idx >= 0 && *idx < len(ruleList) {
		rule = &ruleList[*idx]
	}
	ruleID := res.RuleID
	if ruleID == "" && res.Rule != nil {
		ruleID = res.Rule.ID
	}
	if ruleID == "" && rule != nil {
		ruleID = rule.ID
	}
	if rule == nil {
		rule = rules[ruleID]
	}
	return rule, ruleID
}

// sarifKey tells apart results of one rule in one file: the scanner's own
// fingerprint when it gives one (stable across edits by design), otherwise
// the message text.
func sarifKey(res sarifResult) string {
	for _, m := range []map[string]string{res.Fingerprints, res.PartialFingerprints} {
		if len(m) == 0 {
			continue
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return fmt.Sprintf("fp:%s=%s", keys[0], m[keys[0]])
	}
	return "msg:" + res.Message.text()
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return s
}
