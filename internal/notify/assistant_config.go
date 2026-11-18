package notify

import (
	"fmt"
	"strings"
)

// assistantMessage fills the summary and action of an incident about risky
// AI assistant settings: which files, which kinds, and what to do.
func (d *Dispatcher) assistantMessage(m *Message, det map[string]any, list func(string) []string) {
	n, _ := det["count"].(float64)
	asset, _ := det["asset_name"].(string)
	what := "1 setting"
	if n != 1 {
		what = fmt.Sprintf("%d settings", int(n))
	}
	m.Summary = append(m.Summary, what+" in AI coding assistants' configuration on "+asset+
		" that run on their own and download or install code")
	if why, _ := det["why"].(string); why != "" {
		m.Summary = append(m.Summary, why)
	}
	if t := list("titles"); len(t) > 0 {
		m.Summary = append(m.Summary, "Kinds: "+strings.Join(t, ", "))
	}
	if f := list("files"); len(f) > 0 {
		m.Summary = append(m.Summary, "Files: "+strings.Join(f, ", "))
	}
	m.Action = "Check who changed these files and whether the team intended it. Remove anything unexpected, " +
		"and check the machines of developers who opened the project since"
	if d.BaseURL != "" {
		if id, ok := det["asset_id"].(float64); ok {
			m.Link = strings.TrimSuffix(d.BaseURL, "/") + fmt.Sprintf("/assets/%d?tab=assistant", int64(id))
		}
	}
}
