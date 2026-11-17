package notify

import (
	"fmt"
	"strings"
)

// configMessage fills a config-finding incident's summary and action: an
// asset with high-severity risky settings, such as an AI agent hook that
// downloads and runs code or a pull_request_target workflow that runs a
// pull request's code with the repository's secrets.
func (d *Dispatcher) configMessage(m *Message, det map[string]any, list func(string) []string) {
	n, _ := det["count"].(float64)
	asset, _ := det["asset_name"].(string)
	what := "1 high-severity risky setting"
	if n != 1 {
		what = fmt.Sprintf("%d high-severity risky settings", int(n))
	}
	m.Summary = append(m.Summary, what+" found on "+asset)
	if why, _ := det["why"].(string); why != "" {
		m.Summary = append(m.Summary, why)
	}
	if t := list("titles"); len(t) > 0 {
		m.Summary = append(m.Summary, "Kinds: "+strings.Join(t, ", "))
	}
	if f := list("files"); len(f) > 0 {
		m.Summary = append(m.Summary, "Files: "+strings.Join(f, ", "))
	}
	m.Action = "Open each finding for what to change in the file; remove a hook or step you do not recognise and check who changed it"
	if d.BaseURL != "" {
		if id, ok := det["asset_id"].(float64); ok {
			m.Link = strings.TrimSuffix(d.BaseURL, "/") + fmt.Sprintf("/assets/%d?tab=config", int64(id))
		}
	}
}
