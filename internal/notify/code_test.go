package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

func codeIncident() store.Incident {
	det, _ := json.Marshal(map[string]any{"asset_id": 9, "asset_name": "acme/shop", "count": 2, "critical": true,
		"titles": []string{"Missing authorization check on invoice download", "SQL injection in order search"},
		"files":  []string{"src/api/invoices/[id].ts:12", "src/api/orders/search.ts:41"}, "sources": []string{"deepsec"}})
	return store.Incident{ID: 5, Kind: "code", Key: "asset:9", Title: "2 code findings in acme/shop", Priority: "P1", Status: "open", Detail: det}
}

func TestCodeMessage(t *testing.T) {
	d := &Dispatcher{BaseURL: "https://stackurity.example.com/"}
	m := d.message(codeIncident(), "opened")
	all := strings.Join(m.Summary, "\n")
	for _, want := range []string{"2 critical or high code findings in acme/shop (from deepsec)", "SQL injection in order search",
		"src/api/orders/search.ts:41"} {
		if !strings.Contains(all, want) {
			t.Errorf("summary lacks %q:\n%s", want, all)
		}
	}
	if m.Link != "https://stackurity.example.com/assets/9?tab=code" || m.Action == "" {
		t.Errorf("action %q, link %q", m.Action, m.Link)
	}
	if r := d.message(codeIncident(), "resolved"); len(r.Summary) != 1 || !strings.Contains(r.Summary[0], "No critical or high code findings") {
		t.Errorf("resolved: %+v", r.Summary)
	}
	// Routed like a leaked key: with new issues, and to projects holding the asset.
	if !urgentIncident(store.Route{Enabled: true, Events: []string{store.EventNewIssues}, NewMinPriority: "P2"}, codeIncident()) {
		t.Error("not sent with new issues")
	}
	if urgentIncident(store.Route{Enabled: true, Events: []string{store.EventProblems}, MinPriority: "P4"}, codeIncident()) {
		t.Error("sent as a problem with Stackurity")
	}
	if !incidentInProjects(store.Route{ProjectIDs: []int64{1}, ProjectAssets: map[int64]bool{9: true}}, codeIncident()) {
		t.Error("not in the asset's project")
	}
	if incidentInProjects(store.Route{ProjectIDs: []int64{1}, ProjectAssets: map[int64]bool{7: true}}, codeIncident()) {
		t.Error("sent to a project without the asset")
	}
}
