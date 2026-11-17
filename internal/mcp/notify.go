package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// set_notification_enabled turns one notification channel or rule on or
// off. It uses the organisation's endpoints: PATCH /channels/{id} with
// {"enabled"} only (every other field keeps its value), and PUT
// /routes/{id} with the rule exactly as GET /routes returned it and only
// enabled changed, since PUT replaces a rule's settings. Both need the
// organisation-wide admin role; the API checks it and writes the audit
// log. A project's or asset's own endpoints refuse assistants, so a
// project admin changes their notifications in the dashboard.
//
// Like the read tools it never returns a channel's configuration: what it
// reads and what the API answers go through channel and rule, which leave
// out addresses, tokens and secret references.

// duplicatesNote explains possible_duplicates.
const duplicatesNote = "These enabled channels are of the same kind (Slack or Teams), belong to the same place and get the " +
	"same events from enabled rules, so the same message may arrive twice, for example from an old incoming webhook and the " +
	"Stackurity app posting to one Slack channel. Only possible: a webhook address does not tell Stackurity which channel it " +
	"posts to, so check in Slack or Teams before turning one off with set_notification_enabled."

// family is the kind a channel may duplicate messages with: a Slack
// incoming webhook and the Stackurity Slack app are both kind slack, and
// the same for Teams. Other kinds have one destination each, or keep
// their own records (Jira, PagerDuty, ServiceNow), so are not compared.
func family(kind string) string {
	switch kind {
	case "slack", "teams":
		return kind
	}
	return ""
}

// channelEvents is, for each channel, the events enabled rules send to it
// and which rules: a rule sends each event to its channel, or to the
// channel event_channels names for it.
func channelEvents(rules []rule) map[int64]map[string][]string {
	out := map[int64]map[string][]string{}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		for _, e := range r.Events {
			to := r.ChannelID
			if id := r.EventChannels[e]; id != 0 {
				to = id
			}
			if out[to] == nil {
				out[to] = map[string][]string{}
			}
			out[to][e] = append(out[to][e], r.Name)
		}
	}
	return out
}

func connection(c channel) string {
	switch {
	case c.Kind == "slack" && c.app():
		return "Stackurity Slack app"
	case c.Kind == "slack":
		return "Slack incoming webhook"
	case c.Kind == "teams" && c.app():
		return "Stackurity Teams app"
	case c.Kind == "teams":
		return "Teams incoming webhook"
	}
	return c.Kind
}

// possibleDuplicates finds pairs of enabled channels of one family that
// belong to the same place (the organisation, a project or an asset) and
// that enabled rules send at least one same event to. Two channels of the
// Stackurity app are not compared: each knows its own Slack or Teams
// channel, and the app is added once per channel. With only set (non-zero),
// only pairs including that channel are listed.
func possibleDuplicates(chans []channel, rules []rule, only int64) []map[string]any {
	events := channelEvents(rules)
	var cs []channel
	for _, c := range chans {
		if c.Enabled && family(c.Kind) != "" && len(events[c.ID]) > 0 {
			cs = append(cs, c)
		}
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
	out := []map[string]any{}
	for i, a := range cs {
		for _, b := range cs[i+1:] {
			if family(a.Kind) != family(b.Kind) || owner(a.OwnerProjectID, a.OwnerAssetID) != owner(b.OwnerProjectID, b.OwnerAssetID) ||
				(a.app() && b.app()) || (only != 0 && a.ID != only && b.ID != only) {
				continue
			}
			var shared []string
			for e := range events[a.ID] {
				if _, ok := events[b.ID][e]; ok {
					shared = append(shared, e)
				}
			}
			if len(shared) == 0 {
				continue
			}
			sort.Strings(shared)
			ref := func(c channel) map[string]any {
				return map[string]any{"id": c.ID, "name": withoutURLs(c.Name), "kind": c.Kind, "connection": connection(c)}
			}
			out = append(out, map[string]any{"channels": []map[string]any{ref(a), ref(b)},
				"belongs_to": owner(a.OwnerProjectID, a.OwnerAssetID), "shared_events": shared})
		}
	}
	return out
}

// notifyState is the organisation's channels and rules as the API lists
// them, with each rule's JSON as read (to send back on PUT).
type notifyState struct {
	chans []channel
	rules []rule
	raw   map[int64]json.RawMessage
}

func readNotify(ctx context.Context, api API) (*notifyState, error) {
	var chans struct {
		Items []channel `json:"items"`
	}
	if err := api.Do(ctx, "GET", "/api/v1/channels", nil, nil, &chans); err != nil {
		return nil, fmt.Errorf("could not read the notification channels: %s", refusal(err))
	}
	var routes struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := api.Do(ctx, "GET", "/api/v1/routes", nil, nil, &routes); err != nil {
		return nil, fmt.Errorf("could not read the notification rules: %s", refusal(err))
	}
	st := &notifyState{chans: chans.Items, raw: map[int64]json.RawMessage{}}
	for _, raw := range routes.Items {
		var r rule
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("could not read the notification rules: %w", err)
		}
		st.rules = append(st.rules, r)
		st.raw[r.ID] = raw
	}
	return st, nil
}

func (st *notifyState) channel(id int64) (channel, bool) {
	for _, c := range st.chans {
		if c.ID == id {
			return c, true
		}
	}
	return channel{}, false
}

// with returns the state after the change: the channel or rule id set to
// enabled.
func (st *notifyState) with(target string, id int64, enabled bool) *notifyState {
	next := &notifyState{chans: append([]channel(nil), st.chans...), rules: append([]rule(nil), st.rules...), raw: st.raw}
	if target == "channel" {
		for i := range next.chans {
			if next.chans[i].ID == id {
				next.chans[i].Enabled = enabled
			}
		}
	} else {
		for i := range next.rules {
			if next.rules[i].ID == id {
				next.rules[i].Enabled = enabled
			}
		}
	}
	return next
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func init() {
	tools["set_notification_enabled"] = tool{
		description: "Turn a notification channel (target channel) or a notification rule (target rule) on or off. A rule sends " +
			"only while it and its channel are both on; a channel that is off gets nothing from any rule. Use it, for example, " +
			"when the same alert arrives twice because two Slack channels (an incoming webhook and the Stackurity app) get the " +
			"same events: the preview lists such possible duplicates. Find ids with integrations_status (channels) and " +
			"notification_settings (rules). Nothing else about the channel or rule changes. Needs the organisation-wide admin " +
			"role and a connection to the whole organisation. Without confirm it only previews.",
		schema: obj(map[string]any{
			"target":  map[string]any{"type": "string", "enum": []string{"channel", "rule"}, "description": "channel or rule"},
			"id":      num("The channel's or rule's id"),
			"enabled": map[string]any{"type": "boolean", "description": "true turns it on, false turns it off"},
			"confirm": confirmProp(),
		}, "target", "id", "enabled"),
		write: &writeTool{title: "Turn a notification on or off", destructive: true, idempotent: true, plan: planNotificationEnabled},
	}
}

func planNotificationEnabled(ctx context.Context, s *Server, a map[string]any) (*change, error) {
	target := text(a, "target")
	if target != "channel" && target != "rule" {
		return nil, fmt.Errorf(`target must be "channel" or "rule"`)
	}
	id, err := positive(a, "id")
	if err != nil {
		return nil, err
	}
	enabled, ok := a["enabled"].(bool)
	if !ok {
		return nil, fmt.Errorf("enabled is required: true or false")
	}
	m, err := whoAmI(ctx, s.API)
	if err != nil {
		return nil, err
	}
	if m.Role != "admin" {
		return nil, fmt.Errorf("turning notifications on or off here needs the organisation-wide admin role (you are %s); "+
			"a project's or asset's own notifications are changed in Stackurity", roleWord(m.Role))
	}
	st, err := readNotify(ctx, s.API)
	if err != nil {
		return nil, err
	}
	after := st.with(target, id, enabled)
	if target == "channel" {
		return planChannel(s, st, after, id, enabled)
	}
	return planRule(s, st, after, id, enabled)
}

func planChannel(s *Server, st, after *notifyState, id int64, enabled bool) (*change, error) {
	c, ok := st.channel(id)
	if !ok {
		return nil, fmt.Errorf("no notification channel %d (integrations_status lists the channels and their ids)", id)
	}
	name := withoutURLs(c.Name)
	sends := channelEvents(st.rules)[id]
	var rules []map[string]any
	for _, r := range st.rules {
		var evs []string
		for _, e := range r.Events {
			to := r.ChannelID
			if x := r.EventChannels[e]; x != 0 {
				to = x
			}
			if to == id {
				evs = append(evs, e)
			}
		}
		if len(evs) > 0 {
			rules = append(rules, map[string]any{"id": r.ID, "name": r.Name, "enabled": r.Enabled, "events": evs,
				"belongs_to": owner(r.OwnerProjectID, r.OwnerAssetID)})
		}
	}
	d := map[string]any{"target": "channel", "id": id, "name": name, "kind": c.Kind, "connection": connection(c),
		"belongs_to": owner(c.OwnerProjectID, c.OwnerAssetID), "enabled_now": c.Enabled, "enabled_after": enabled,
		"rules_sending_here": nonNil(rules)}
	dupsNow := possibleDuplicates(st.chans, st.rules, id)
	dupsAfter := possibleDuplicates(after.chans, after.rules, id)
	d["possible_duplicates"] = dupsNow
	if len(dupsAfter) != len(dupsNow) {
		d["possible_duplicates_after"] = dupsAfter
	}
	var notes []string
	switch {
	case c.Enabled == enabled:
		notes = append(notes, fmt.Sprintf("The channel %q is already %s: confirming changes nothing.", name, onOff(enabled)))
	case !enabled && len(sends) > 0:
		notes = append(notes, fmt.Sprintf("While it is off, %q gets nothing: the enabled rules listed under rules_sending_here stop "+
			"sending to it (their other channels are not affected).", name))
	case !enabled:
		notes = append(notes, "No enabled rule sends to this channel now, so turning it off silences nothing today.")
	case len(sends) == 0:
		notes = append(notes, "No enabled rule sends to this channel, so nothing arrives until a rule uses it (notification_settings).")
	default:
		notes = append(notes, fmt.Sprintf("The enabled rules listed under rules_sending_here start sending to %q again.", name))
	}
	if len(dupsNow) > 0 || len(dupsAfter) > 0 {
		notes = append(notes, duplicatesNote)
	}
	return &change{summary: fmt.Sprintf("Turn the notification channel %q (%d) %s", name, id, onOff(enabled)), details: d, notes: notes,
		key: fmt.Sprintf("channel|%d|%v", id, c.Enabled),
		apply: func(ctx context.Context) (any, error) {
			if c.Enabled == enabled {
				return map[string]any{"id": id, "name": name, "enabled": enabled, "changed": false}, nil
			}
			var out channel
			if err := send(ctx, s.API, "PATCH", fmt.Sprintf("/api/v1/channels/%d", id), map[string]any{"enabled": enabled}, &out); err != nil {
				return nil, err
			}
			return map[string]any{"id": id, "name": withoutURLs(out.Name), "enabled": out.Enabled, "changed": true}, nil
		}}, nil
}

func planRule(s *Server, st, after *notifyState, id int64, enabled bool) (*change, error) {
	var r *rule
	for i := range st.rules {
		if st.rules[i].ID == id {
			r = &st.rules[i]
		}
	}
	if r == nil {
		return nil, fmt.Errorf("no notification rule %d (notification_settings lists the rules and their ids)", id)
	}
	ch, chOK := st.channel(r.ChannelID)
	chRef := map[string]any{"id": r.ChannelID}
	if chOK {
		chRef = map[string]any{"id": ch.ID, "name": withoutURLs(ch.Name), "kind": ch.Kind, "connection": connection(ch), "enabled": ch.Enabled}
	}
	d := map[string]any{"target": "rule", "id": id, "name": r.Name, "belongs_to": owner(r.OwnerProjectID, r.OwnerAssetID),
		"channel": chRef, "events": nonNil(r.Events), "enabled_now": r.Enabled, "enabled_after": enabled,
		"sends_now": r.Enabled && ch.Enabled, "sends_after": enabled && ch.Enabled}
	if len(r.EventChannels) > 0 {
		ev := map[string]any{}
		for e, cid := range r.EventChannels {
			if c, ok := st.channel(cid); ok {
				ev[e] = map[string]any{"id": c.ID, "name": withoutURLs(c.Name), "enabled": c.Enabled}
			} else {
				ev[e] = map[string]any{"id": cid}
			}
		}
		d["event_channels"] = ev
	}
	// Duplicates involving the channels this rule sends to.
	targets := map[int64]bool{r.ChannelID: true}
	for _, cid := range r.EventChannels {
		targets[cid] = true
	}
	involving := func(state *notifyState) []map[string]any {
		out := []map[string]any{}
		for _, x := range possibleDuplicates(state.chans, state.rules, 0) {
			for _, c := range x["channels"].([]map[string]any) {
				if targets[c["id"].(int64)] {
					out = append(out, x)
					break
				}
			}
		}
		return out
	}
	dupsNow, dupsAfter := involving(st), involving(after)
	d["possible_duplicates"] = dupsNow
	if len(dupsAfter) != len(dupsNow) {
		d["possible_duplicates_after"] = dupsAfter
	}
	var notes []string
	switch {
	case r.Enabled == enabled:
		notes = append(notes, fmt.Sprintf("The rule %q is already %s: confirming changes nothing.", r.Name, onOff(enabled)))
	case enabled && chOK && !ch.Enabled:
		notes = append(notes, fmt.Sprintf("Its channel %q is off, so the rule still sends nothing until the channel is turned on.", withoutURLs(ch.Name)))
	case !enabled:
		notes = append(notes, fmt.Sprintf("While it is off, the rule %q sends nothing (%s); other rules are not affected.", r.Name, strings.Join(r.Events, ", ")))
	}
	if len(dupsNow) > 0 || len(dupsAfter) > 0 {
		notes = append(notes, duplicatesNote)
	}
	raw := st.raw[id]
	return &change{summary: fmt.Sprintf("Turn the notification rule %q (%d) %s", r.Name, id, onOff(enabled)), details: d, notes: notes,
		key: fmt.Sprintf("rule|%d|%v", id, r.Enabled),
		apply: func(ctx context.Context) (any, error) {
			if r.Enabled == enabled {
				return map[string]any{"id": id, "name": r.Name, "enabled": enabled, "changed": false}, nil
			}
			// PUT replaces the rule's settings: send back every field as
			// read, with only enabled changed.
			var body map[string]json.RawMessage
			if err := json.Unmarshal(raw, &body); err != nil {
				return nil, err
			}
			body["enabled"] = json.RawMessage(fmt.Sprint(enabled))
			var out rule
			if err := send(ctx, s.API, "PUT", fmt.Sprintf("/api/v1/routes/%d", id), body, &out); err != nil {
				return nil, err
			}
			return map[string]any{"id": id, "name": out.Name, "enabled": out.Enabled, "changed": true}, nil
		}}, nil
}
