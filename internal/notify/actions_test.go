package notify

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// Every fix in a message carries Assign to me, Snooze and Open links to
// the dashboard; Slack shows them as URL buttons (no Slack app needed),
// email as links. A route limited to projects opens every link in its
// project.
func TestFixActionLinks(t *testing.T) {
	d := &Dispatcher{BaseURL: "https://stk.example"}
	r, incs, rows, infos := syntheticUrgent(2, 4, func(a int) string { return []string{"", "commmerceblog", "pos-api"}[a] })
	r.ProjectIDs, r.ProjectAssets = []int64{7}, map[int64]bool{1: true, 2: true}
	m, ok := d.urgentMessage(r, incs, rows, nil, infos, nil)
	if !ok {
		t.Fatal("no message")
	}
	if m.Link != "https://stk.example/?project=7" {
		t.Errorf("home link = %q", m.Link)
	}
	if strings.Contains(m.SettingsLink, "project=") {
		t.Errorf("settings are for the organisation: %q", m.SettingsLink)
	}
	fixes := 0
	var walk func([]Item)
	walk = func(list []Item) {
		for _, it := range list {
			u, err := url.Parse(it.Link)
			if err != nil || u.Query().Get("project") != "7" {
				t.Errorf("link without the project: %q", it.Link)
			}
			if strings.HasPrefix(u.Path, "/fixes/") && strings.Contains(u.Path, ":") {
				fixes++
				if len(it.Actions) != 3 {
					t.Fatalf("fix without actions: %+v", it)
				}
				id := strings.TrimPrefix(u.Path, "/fixes/")
				for i, want := range []string{"assign", "snooze", ""} {
					a := it.Actions[i]
					au, _ := url.Parse(a.Link)
					if au.Path != "/fixes/"+id || au.Query().Get("action") != want || au.Query().Get("project") != "7" {
						t.Errorf("%s link = %q", a.Kind, a.Link)
					}
				}
				if it.Actions[0].Label != "Assign to me" || it.Actions[1].Label != "Snooze" || it.Actions[2].Label != "Open" {
					t.Errorf("labels = %+v", it.Actions)
				}
			}
			walk(it.Items)
		}
	}
	for _, s := range m.Sections {
		walk(s.Items)
	}
	if fixes != 6 {
		t.Errorf("%d fixes with actions, want 6", fixes)
	}

	// Slack: URL buttons with unique action ids, inside the limits.
	blocks := slackPayload(m)["blocks"].([]map[string]any)
	ids := map[string]bool{}
	buttons := 0
	for _, b := range blocks {
		if b["type"] != "actions" {
			continue
		}
		for _, el := range b["elements"].([]map[string]any) {
			buttons++
			id := el["action_id"].(string)
			if ids[id] || el["type"] != "button" || !strings.HasPrefix(el["url"].(string), "https://stk.example/fixes/") {
				t.Errorf("button = %+v", el)
			}
			ids[id] = true
		}
	}
	if buttons != 18 || len(blocks) > slackBlocksMax {
		t.Errorf("%d buttons in %d blocks", buttons, len(blocks))
	}
	// Email: the links after each fix; plain text: the assign and snooze links.
	e := string(buildEmail("a@x.io", []string{"b@x.io"}, m))
	if !strings.Contains(e, `>Assign to me</a> &middot; <a href="https://stk.example/fixes/1:package_upgrade:0?action=snooze&amp;project=7">Snooze</a>`) ||
		!strings.Contains(e, "Assign to me: https://stk.example/fixes/1:package_upgrade:0?action=assign&project=7\r\n") {
		t.Errorf("email: %s", e)
	}
	// The webhook JSON carries them too.
	raw, _ := json.Marshal(m)
	if !strings.Contains(string(raw), `"actions":[{"kind":"assign","label":"Assign to me","link":"https://stk.example/fixes/`) {
		t.Errorf("webhook JSON: %s", raw)
	}
}

// A route on several projects opens each asset's links in the first of its
// projects the asset is in; a route on none adds no project.
func TestLinksPerProject(t *testing.T) {
	d := &Dispatcher{BaseURL: "https://stk.example"}
	r, incs, rows, infos := syntheticUrgent(2, 1, func(a int) string { return fmt.Sprintf("host-%d", a) })
	r.ProjectIDs, r.ProjectAssets = []int64{3, 4}, map[int64]bool{1: true, 2: true}
	r.AssetProject = map[int64]int64{1: 3, 2: 4}
	m, _ := d.urgentMessage(r, incs, rows, nil, infos, nil)
	for _, it := range m.Sections[0].Items {
		want := map[string]string{"host-1": "3", "host-2": "4"}[strings.SplitN(it.Text, ":", 2)[0]]
		for _, l := range []string{it.Link, it.Items[0].Link, it.Items[0].Actions[0].Link} {
			if u, _ := url.Parse(l); u.Query().Get("project") != want {
				t.Errorf("%q: want project %s", l, want)
			}
		}
	}
	if strings.Contains(m.Link, "project=") {
		t.Errorf("home link of a route on two projects: %q", m.Link)
	}
	r.ProjectIDs, r.ProjectAssets, r.AssetProject = nil, nil, nil
	m, _ = d.urgentMessage(r, incs, rows, nil, infos, nil)
	if raw, _ := json.Marshal(m); strings.Contains(string(raw), "project=") {
		t.Errorf("project in a route without projects: %s", raw)
	}
}
