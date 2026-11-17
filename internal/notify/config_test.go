package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

func configIncident() store.Incident {
	det, _ := json.Marshal(map[string]any{"asset_id": 7, "asset_name": "web-1", "count": 1,
		"titles": []string{"Claude Code hook downloads and runs code"}, "files": []string{"/root/.claude/settings.json:4"},
		"why": "SessionStart hook downloads code and pipes it to a shell from cdn.example.net."})
	return store.Incident{ID: 4, Kind: "config", Key: "asset:7", Title: "Claude Code hook downloads and runs code on web-1", Priority: "P2",
		Status: "open", Detail: det}
}

func TestConfigMessage(t *testing.T) {
	d := &Dispatcher{BaseURL: "https://stackurity.example.com"}
	m := d.message(configIncident(), "opened")
	all := strings.Join(m.Summary, "\n")
	for _, want := range []string{"1 high-severity risky setting found on web-1", "cdn.example.net", "/root/.claude/settings.json:4"} {
		if !strings.Contains(all, want) {
			t.Errorf("summary lacks %q:\n%s", want, all)
		}
	}
	if m.Link != "https://stackurity.example.com/assets/7?tab=config" || m.Action == "" {
		t.Errorf("action %q, link %q", m.Action, m.Link)
	}
	if r := d.message(configIncident(), "resolved"); len(r.Summary) != 1 || !strings.Contains(r.Summary[0], "No high-severity risky settings") {
		t.Errorf("resolved: %+v", r.Summary)
	}
	// Routed like a leaked key: with new issues, and to projects holding the asset.
	if !urgentIncident(store.Route{Enabled: true, Events: []string{store.EventNewIssues}, NewMinPriority: "P2"}, configIncident()) {
		t.Error("not sent with new issues")
	}
	if urgentIncident(store.Route{Enabled: true, Events: []string{store.EventProblems}, MinPriority: "P4"}, configIncident()) {
		t.Error("sent as a problem with Stackurity")
	}
	if !incidentInProjects(store.Route{ProjectIDs: []int64{1}, ProjectAssets: map[int64]bool{7: true}}, configIncident()) {
		t.Error("not in the asset's project")
	}
}
