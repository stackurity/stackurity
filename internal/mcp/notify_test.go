package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

// notifyAPI serves an organisation whose Slack alerts arrive twice: an old
// incoming webhook (1) and the Stackurity Slack app (2) both get urgent
// alerts. Teams (3) is off; the email channel (4) belongs to project 7.
type notifyAPI struct {
	role   string
	chans  string
	routes string
	reqs   []string
}

const notifyChans = `{"items":[
	{"id":1,"kind":"slack","name":"Old Slack webhook","enabled":true,"config":{"webhook_url":"https://hooks.slack.com/services/T0/B0/sEcReT"},"secret_ref":"secret:SLACK"},
	{"id":2,"kind":"slack","name":"#alerts (Stackurity app)","enabled":true,"config":{"slack_app":true,"slack_channel_id":"C1","configuration_url":"https://acme.slack.com/x"}},
	{"id":3,"kind":"teams","name":"Teams ops","enabled":false,"config":{"url":"https://acme.webhook.office.com/teamssecret"}},
	{"id":4,"kind":"email","name":"Security email","enabled":true,"owner_project_id":7,"config":{"to":["sec@acme.io"]}}],"total":4}`

const notifyRoutes = `{"items":[
	{"id":10,"name":"Urgent to old webhook","channel_id":1,"enabled":true,"min_priority":"P2","new_min_priority":"P3","events":["urgent","regressed"],
	 "mode":"custom","timezone":"Asia/Kolkata","quiet_start":"22:00","quiet_end":"07:00","max_per_hour":20,"kinds":["vulnerability"],
	 "environments":["production"],"team_ids":[],"project_ids":[],"event_channels":{},"summary_time":"09:30","summary_day":"monday",
	 "summary_updates":true,"send_resolved":true,"created_at":"2026-01-01T00:00:00Z","owner_project_id":null,"owner_asset_id":null},
	{"id":11,"name":"Urgent to Slack app","channel_id":2,"enabled":true,"min_priority":"P1","events":["urgent","daily_summary"],"mode":"urgent_summary",
	 "timezone":"UTC","event_channels":{}},
	{"id":12,"name":"Teams digest","channel_id":3,"enabled":true,"min_priority":"P3","events":["urgent"],"mode":"urgent_only","timezone":"UTC"},
	{"id":13,"name":"Project mail","channel_id":4,"enabled":false,"events":["urgent"],"mode":"urgent_only","timezone":"UTC","owner_project_id":7}],"total":4}`

func newNotifyAPI(role string) *notifyAPI {
	return &notifyAPI{role: role, chans: notifyChans, routes: notifyRoutes}
}

func (f *notifyAPI) Do(_ context.Context, method, path string, body io.Reader, _ map[string]string, out any) error {
	var b []byte
	if body != nil {
		b, _ = io.ReadAll(body)
	}
	f.reqs = append(f.reqs, strings.TrimSpace(method+" "+path+" "+string(b)))
	var resp string
	switch {
	case path == "/api/v1/auth/me":
		resp = `{"user":{"id":5,"email":"me@x.io"},"role":"` + f.role + `","project_role":""}`
	case method == "GET" && path == "/api/v1/channels":
		resp = f.chans
	case method == "GET" && path == "/api/v1/routes":
		resp = f.routes
	case method == "PATCH" && strings.HasPrefix(path, "/api/v1/channels/"):
		// The API answers the whole channel, config included.
		resp = `{"id":1,"kind":"slack","name":"Old Slack webhook","enabled":false,"config":{"webhook_url":"https://hooks.slack.com/services/T0/B0/sEcReT"},"secret_ref":"secret:SLACK"}`
	case method == "PUT" && strings.HasPrefix(path, "/api/v1/routes/"):
		resp = string(b)
	default:
		return fmt.Errorf("unexpected %s %s", method, path)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal([]byte(resp), out)
}

func (f *notifyAPI) writes() []string {
	var w []string
	for _, r := range f.reqs {
		if !strings.HasPrefix(r, "GET ") {
			w = append(w, r)
		}
	}
	return w
}

func confirmed(t *testing.T, s *Server, args map[string]any) (preview, done map[string]any) {
	t.Helper()
	preview = callTool(t, s, "set_notification_enabled", args)
	if preview["status"] != "preview" {
		t.Fatalf("preview: %v", preview)
	}
	with := map[string]any{"confirm": preview["confirm"]}
	for k, v := range args {
		with[k] = v
	}
	return preview, callTool(t, s, "set_notification_enabled", with)
}

func TestSetNotificationEnabledChannel(t *testing.T) {
	api := newNotifyAPI("admin")
	s := &Server{API: api, AllowWrites: true}
	args := map[string]any{"target": "channel", "id": 1.0, "enabled": false}

	pv := callTool(t, s, "set_notification_enabled", args)
	if pv["status"] != "preview" || len(api.writes()) != 0 {
		t.Fatalf("preview changed something: %v %v", pv, api.writes())
	}
	d := pv["details"].(map[string]any)
	if d["name"] != "Old Slack webhook" || d["kind"] != "slack" || d["connection"] != "Slack incoming webhook" ||
		d["belongs_to"] != "organisation" || d["enabled_now"] != true || d["enabled_after"] != false {
		t.Errorf("details: %v", d)
	}
	rules := d["rules_sending_here"].([]any)
	if len(rules) != 1 || rules[0].(map[string]any)["name"] != "Urgent to old webhook" ||
		fmt.Sprint(rules[0].(map[string]any)["events"]) != "[urgent regressed]" {
		t.Errorf("rules sending here: %v", rules)
	}
	// The webhook and the app get urgent alerts: possibly twice. After
	// turning the webhook off, no longer.
	dups := d["possible_duplicates"].([]any)
	if len(dups) != 1 || fmt.Sprint(dups[0].(map[string]any)["shared_events"]) != "[urgent]" {
		t.Errorf("possible duplicates: %v", dups)
	}
	if after, ok := d["possible_duplicates_after"].([]any); !ok || len(after) != 0 {
		t.Errorf("duplicates after: %v", d["possible_duplicates_after"])
	}

	wrong := map[string]any{"confirm": "000000000000"}
	for k, v := range args {
		wrong[k] = v
	}
	if out := callTool(t, s, "set_notification_enabled", wrong); out["status"] != "preview" || len(api.writes()) != 0 {
		t.Errorf("wrong code: %v %v", out, api.writes())
	}

	_, done := confirmed(t, s, args)
	if w := api.writes(); done["status"] != "done" || len(w) != 1 || w[0] != `PATCH /api/v1/channels/1 {"enabled":false}` {
		t.Errorf("confirmed: %v, writes %v", done, w)
	}
	b, _ := json.Marshal(done)
	for _, leak := range []string{"hooks.slack.com", "sEcReT", "secret:", "config"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("answer returns %q: %s", leak, b)
		}
	}
}

// A rule is replaced on PUT, so the tool sends it back as read with only
// enabled changed.
func TestSetNotificationEnabledRuleKeepsFields(t *testing.T) {
	api := newNotifyAPI("admin")
	s := &Server{API: api, AllowWrites: true}
	pv, done := confirmed(t, s, map[string]any{"target": "rule", "id": 10.0, "enabled": false})
	d := pv["details"].(map[string]any)
	if d["name"] != "Urgent to old webhook" || d["sends_now"] != true || d["sends_after"] != false ||
		d["channel"].(map[string]any)["connection"] != "Slack incoming webhook" {
		t.Errorf("details: %v", d)
	}
	w := api.writes()
	if done["status"] != "done" || len(w) != 1 || !strings.HasPrefix(w[0], "PUT /api/v1/routes/10 ") {
		t.Fatalf("confirmed: %v, writes %v", done, w)
	}
	var sent, read map[string]any
	_ = json.Unmarshal([]byte(strings.TrimPrefix(w[0], "PUT /api/v1/routes/10 ")), &sent)
	var all struct{ Items []map[string]any }
	_ = json.Unmarshal([]byte(notifyRoutes), &all)
	read = all.Items[0]
	if sent["enabled"] != false {
		t.Errorf("enabled not changed: %v", sent)
	}
	delete(sent, "enabled")
	delete(read, "enabled")
	if a, b := fmt.Sprint(sent), fmt.Sprint(read); a != b {
		t.Errorf("other fields changed:\nsent %s\nread %s", a, b)
	}
}

func TestSetNotificationEnabledAlreadyInState(t *testing.T) {
	for _, args := range []map[string]any{
		{"target": "channel", "id": 3.0, "enabled": false},
		{"target": "rule", "id": 13.0, "enabled": false},
	} {
		api := newNotifyAPI("admin")
		s := &Server{API: api, AllowWrites: true}
		pv, done := confirmed(t, s, args)
		if !strings.Contains(fmt.Sprint(pv["notes"]), "already off") {
			t.Errorf("%v: notes %v", args, pv["notes"])
		}
		if done["status"] != "done" || len(api.writes()) != 0 {
			t.Errorf("%v: %v, writes %v", args, done, api.writes())
		}
	}
	// Turning on a rule whose channel is off says it still sends nothing.
	s := &Server{API: newNotifyAPI("admin"), AllowWrites: true}
	api := newNotifyAPI("admin")
	api.routes = strings.Replace(notifyRoutes, `"name":"Teams digest","channel_id":3,"enabled":true`, `"name":"Teams digest","channel_id":3,"enabled":false`, 1)
	s.API = api
	pv := callTool(t, s, "set_notification_enabled", map[string]any{"target": "rule", "id": 12.0, "enabled": true})
	if !strings.Contains(fmt.Sprint(pv["notes"]), "still sends nothing") || pv["details"].(map[string]any)["sends_after"] != false {
		t.Errorf("rule on, channel off: %v", pv)
	}
}

func TestSetNotificationEnabledRefusals(t *testing.T) {
	s := &Server{API: newNotifyAPI("security"), AllowWrites: true}
	if out := callTool(t, s, "set_notification_enabled", map[string]any{"target": "channel", "id": 1.0, "enabled": false}); !strings.Contains(fmt.Sprint(out["error"]), "admin role") {
		t.Errorf("security role: %v", out)
	}
	s = &Server{API: newNotifyAPI("admin"), AllowWrites: true}
	for _, args := range []map[string]any{
		{"target": "channel", "id": 99.0, "enabled": false},
		{"target": "rule", "id": 99.0, "enabled": false},
		{"target": "team", "id": 1.0, "enabled": false},
		{"target": "channel", "id": 1.0},
	} {
		if out := callTool(t, s, "set_notification_enabled", args); out["error"] == nil {
			t.Errorf("%v: %v", args, out)
		}
	}
	// Not offered, nor callable, without allow-writes.
	ro := &Server{API: newNotifyAPI("admin")}
	res, _ := ro.handle(context.Background(), request{Method: "tools/list"})
	for _, x := range res.(map[string]any)["tools"].([]map[string]any) {
		if x["name"] == "set_notification_enabled" {
			t.Errorf("listed on a read-only connection")
		}
	}
	raw, _ := json.Marshal(map[string]any{"name": "set_notification_enabled", "arguments": map[string]any{"target": "channel", "id": 1, "enabled": false}})
	if _, rerr := ro.handle(context.Background(), request{Method: "tools/call", Params: raw}); rerr == nil || !strings.Contains(rerr.Message, "read-only") {
		t.Errorf("callable on a read-only connection: %v", rerr)
	}
}

func TestPossibleDuplicates(t *testing.T) {
	var chans struct{ Items []channel }
	var routes struct{ Items []rule }
	_ = json.Unmarshal([]byte(notifyChans), &chans)
	load := func(r string) []rule {
		routes.Items = nil
		_ = json.Unmarshal([]byte(r), &routes)
		return routes.Items
	}
	// Webhook and app with an overlapping event: flagged.
	got := possibleDuplicates(chans.Items, load(notifyRoutes), 0)
	if len(got) != 1 || fmt.Sprint(got[0]["shared_events"]) != "[urgent]" || got[0]["belongs_to"] != "organisation" {
		t.Errorf("webhook + app: %v", got)
	}
	// Different events: not flagged.
	other := strings.Replace(notifyRoutes, `"events":["urgent","regressed"]`, `"events":["regressed"]`, 1)
	if got := possibleDuplicates(chans.Items, load(other), 0); len(got) != 0 {
		t.Errorf("different events: %v", got)
	}
	// One rule off: not flagged.
	off := strings.Replace(notifyRoutes, `"name":"Urgent to Slack app","channel_id":2,"enabled":true`, `"name":"Urgent to Slack app","channel_id":2,"enabled":false`, 1)
	if got := possibleDuplicates(chans.Items, load(off), 0); len(got) != 0 {
		t.Errorf("one rule off: %v", got)
	}
	// One channel off: not flagged.
	chOff := append([]channel(nil), chans.Items...)
	chOff[1].Enabled = false
	if got := possibleDuplicates(chOff, load(notifyRoutes), 0); len(got) != 0 {
		t.Errorf("one channel off: %v", got)
	}
	// Different places (organisation and a project): not flagged.
	moved := append([]channel(nil), chans.Items...)
	p := int64(7)
	moved[1].OwnerProjectID = &p
	if got := possibleDuplicates(moved, load(notifyRoutes), 0); len(got) != 0 {
		t.Errorf("different places: %v", got)
	}
	// An event a rule sends to another channel through event_channels
	// counts for that channel.
	redirect := strings.Replace(notifyRoutes, `"events":["urgent","regressed"],`, `"events":["urgent","regressed","daily_summary"],`, 1)
	redirect = strings.Replace(redirect, `"event_channels":{},"summary_time"`, `"event_channels":{"daily_summary":2},"summary_time"`, 1)
	if got := possibleDuplicates(chans.Items, load(redirect), 0); len(got) != 1 || fmt.Sprint(got[0]["shared_events"]) != "[urgent]" {
		t.Errorf("event_channels: %v", got)
	}

	// notification_settings lists them too, without any configuration.
	out := callTool(t, &Server{API: newNotifyAPI("security")}, "notification_settings", nil)
	if d := out["possible_duplicates"].([]any); len(d) != 1 || out["possible_duplicates_note"] == nil {
		t.Errorf("notification_settings: %v", out)
	}
	b, _ := json.Marshal(out)
	for _, leak := range []string{"hooks.slack.com", "sEcReT", "teamssecret", "secret:", "config", "C1"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("notification_settings returns %q: %s", leak, b)
		}
	}
}
