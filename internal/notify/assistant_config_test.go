package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

func assistantIncident(priority string) store.Incident {
	det, _ := json.Marshal(map[string]any{"asset_id": 7, "asset_name": "github.com/acme/app", "count": 2, "critical": 1,
		"titles": []string{"Downloads and runs code", "MCP server installed from a Git repository or URL"},
		"files":  []string{".claude/settings.json:5", ".mcp.json:3"}, "environments": []string{"production"},
		"why": store.AssistantWhy("remote-code")})
	return store.Incident{ID: 4, Kind: "assistant", Key: "asset:7", Title: "2 risky AI assistant settings in github.com/acme/app",
		Priority: priority, Status: "open", Detail: det}
}

func TestAssistantMessage(t *testing.T) {
	d := &Dispatcher{BaseURL: "https://stackurity.example.com/"}
	m := d.message(assistantIncident("P1"), "opened")
	all := strings.Join(m.Summary, "\n")
	for _, want := range []string{"2 settings in AI coding assistants' configuration on github.com/acme/app", "Downloads and runs code",
		".claude/settings.json:5", "treat the repository as tampered with"} {
		if !strings.Contains(all, want) {
			t.Errorf("summary lacks %q:\n%s", want, all)
		}
	}
	if !strings.HasPrefix(m.Action, "Check who changed these files") || m.Link != "https://stackurity.example.com/assets/7?tab=assistant" {
		t.Errorf("action %q, link %q", m.Action, m.Link)
	}
	if r := d.message(assistantIncident("P1"), "resolved"); len(r.Summary) != 1 || !strings.Contains(r.Summary[0], "AI assistant settings") {
		t.Errorf("resolved: %+v", r.Summary)
	}
}

// Like a leaked key, a risky assistant setting goes where new issues go
// right away, and only to routes that cover its asset.
func TestAssistantUrgency(t *testing.T) {
	for _, tc := range []struct {
		name     string
		r        store.Route
		priority string
		want     bool
	}{
		{"urgent P1", store.Route{Enabled: true, Events: []string{store.EventUrgent}, MinPriority: "P1"}, "P1", true},
		{"urgent P1, a P2 finding", store.Route{Enabled: true, Events: []string{store.EventUrgent}, MinPriority: "P1"}, "P2", false},
		{"new issues", store.Route{Enabled: true, Events: []string{store.EventNewIssues}, NewMinPriority: "P2"}, "P2", true},
		{"problems only", store.Route{Enabled: true, Events: []string{store.EventProblems}, MinPriority: "P4"}, "P1", false},
		{"project without the asset", store.Route{Enabled: true, Events: []string{store.EventUrgent}, MinPriority: "P4", ProjectIDs: []int64{1},
			ProjectAssets: map[int64]bool{8: true}}, "P1", false},
		{"project with the asset", store.Route{Enabled: true, Events: []string{store.EventUrgent}, MinPriority: "P4", ProjectIDs: []int64{1},
			ProjectAssets: map[int64]bool{7: true}}, "P1", true},
	} {
		if got := urgentIncident(tc.r, assistantIncident(tc.priority)); got != tc.want {
			t.Errorf("%s: urgent = %v, want %v", tc.name, got, tc.want)
		}
	}
}
