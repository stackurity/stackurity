package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

func leakIncident(priority string) store.Incident {
	det, _ := json.Marshal(map[string]any{"asset_id": 7, "asset_name": "web-1", "count": 2, "critical": 1, "served": 1,
		"titles": []string{"Password or key in configuration", "Stripe live secret key"}, "files": []string{"/var/www/html/.env:4", "/srv/shop/billing.py:9"},
		"environments": []string{"production"},
		"why":          "The web server may send this file to anyone who asks for it (e.g. /.env). Rotate the key and move the file out of the document root."})
	return store.Incident{ID: 3, Kind: "leak", Key: "asset:7", Title: "2 leaked keys on web-1", Priority: priority, Status: "open", Detail: det}
}

func TestLeakMessage(t *testing.T) {
	d := &Dispatcher{BaseURL: "https://stackurity.example.com/"}
	m := d.message(leakIncident("P1"), "opened")
	all := strings.Join(m.Summary, "\n")
	for _, want := range []string{"2 keys, tokens or passwords found written in files on web-1", "1 in files the web server may send",
		"Stripe live secret key", "/var/www/html/.env:4", "The web server may send this file"} {
		if !strings.Contains(all, want) {
			t.Errorf("summary lacks %q:\n%s", want, all)
		}
	}
	if !strings.HasPrefix(m.Action, "Rotate each key") || m.Link != "https://stackurity.example.com/assets/7?tab=leaks" {
		t.Errorf("action %q, link %q", m.Action, m.Link)
	}
	if r := d.message(leakIncident("P1"), "resolved"); len(r.Summary) != 1 || !strings.Contains(r.Summary[0], "No critical or high leaked keys") {
		t.Errorf("resolved: %+v", r.Summary)
	}
}

// A leaked key goes where new issues go right away, not with problems
// about Stackurity itself.
func TestLeakUrgency(t *testing.T) {
	for _, tc := range []struct {
		name     string
		r        store.Route
		priority string
		want     bool
	}{
		{"urgent P1", store.Route{Enabled: true, Events: []string{store.EventUrgent}, MinPriority: "P1"}, "P1", true},
		{"urgent P1, a P2 leak", store.Route{Enabled: true, Events: []string{store.EventUrgent}, MinPriority: "P1"}, "P2", false},
		{"new issues", store.Route{Enabled: true, Events: []string{store.EventNewIssues}, NewMinPriority: "P2"}, "P2", true},
		{"problems only", store.Route{Enabled: true, Events: []string{store.EventProblems}, MinPriority: "P4"}, "P1", false},
		{"other environment", store.Route{Enabled: true, Events: []string{store.EventUrgent}, MinPriority: "P4", Environments: []string{"staging"}}, "P1", false},
		{"project without the asset", store.Route{Enabled: true, Events: []string{store.EventUrgent}, MinPriority: "P4", ProjectIDs: []int64{1},
			ProjectAssets: map[int64]bool{8: true}}, "P1", false},
		{"project with the asset", store.Route{Enabled: true, Events: []string{store.EventUrgent}, MinPriority: "P4", ProjectIDs: []int64{1},
			ProjectAssets: map[int64]bool{7: true}}, "P1", true},
	} {
		if got := urgentIncident(tc.r, leakIncident(tc.priority)); got != tc.want {
			t.Errorf("%s: urgent = %v, want %v", tc.name, got, tc.want)
		}
	}
}
