package notify

import (
	"fmt"
	"strings"
)

// leakMessage fills a leaked-key incident's summary and action. It names
// the files and the kinds of key, never a value: the server never has one.
func (d *Dispatcher) leakMessage(m *Message, det map[string]any, list func(string) []string) {
	n, _ := det["count"].(float64)
	served, _ := det["served"].(float64)
	asset, _ := det["asset_name"].(string)
	what := "1 key, token or password"
	if n != 1 {
		what = fmt.Sprintf("%d keys, tokens or passwords", int(n))
	}
	m.Summary = append(m.Summary, what+" found written in files on "+asset)
	if served > 0 {
		m.Summary = append(m.Summary, fmt.Sprintf("%d in files the web server may send to anyone who asks for them", int(served)))
	}
	if t := list("titles"); len(t) > 0 {
		m.Summary = append(m.Summary, "Kinds: "+strings.Join(t, ", "))
	}
	if f := list("files"); len(f) > 0 {
		m.Summary = append(m.Summary, "Files: "+strings.Join(f, ", "))
	}
	m.Action = "Rotate each key: revoke it and issue a new one, as removing it from the file does not undo the leak. " +
		"Then keep it out of the file (an environment variable or a secret store)"
	if d.BaseURL != "" {
		if id, ok := det["asset_id"].(float64); ok {
			m.Link = strings.TrimSuffix(d.BaseURL, "/") + fmt.Sprintf("/assets/%d?tab=leaks", int64(id))
		}
	}
}
