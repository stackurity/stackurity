package notify

import (
	"fmt"
	"strings"
)

// codeMessage fills a code-finding incident's summary and action: a
// repository with critical or high security findings that a code scanner
// (deepsec, or any tool writing SARIF) reported and whose own verdict did
// not close.
func (d *Dispatcher) codeMessage(m *Message, det map[string]any, list func(string) []string) {
	n, _ := det["count"].(float64)
	asset, _ := det["asset_name"].(string)
	what := "1 critical or high code finding"
	if n != 1 {
		what = fmt.Sprintf("%d critical or high code findings", int(n))
	}
	line := what + " in " + asset
	if s := list("sources"); len(s) > 0 {
		line += " (from " + strings.Join(s, ", ") + ")"
	}
	m.Summary = append(m.Summary, line)
	if t := list("titles"); len(t) > 0 {
		m.Summary = append(m.Summary, "Findings: "+strings.Join(t, "; "))
	}
	if f := list("files"); len(f) > 0 {
		m.Summary = append(m.Summary, "Files: "+strings.Join(f, ", "))
	}
	m.Action = "Open each finding for the file, lines and suggested fix; confirm it in the code, fix it, and import the scanner's next report"
	if d.BaseURL != "" {
		if id, ok := det["asset_id"].(float64); ok {
			m.Link = strings.TrimSuffix(d.BaseURL, "/") + fmt.Sprintf("/assets/%d?tab=code", int64(id))
		}
	}
}
