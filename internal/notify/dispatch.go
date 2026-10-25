package notify

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
)

const maxAttempts = 8

// burstThreshold: above this many incidents for one route in one cycle, a
// single summary is sent instead of one message each.
const burstThreshold = 3

type Dispatcher struct {
	Store   *store.Store
	Sender  *Sender
	Secrets secrets.Resolver
	Log     *slog.Logger
	BaseURL string // dashboard URL for links, e.g. https://stackurity.example.com
	Now     func() time.Time
	// Escalate reports whether the workspace in ctx may escalate overdue
	// incidents (a paid feature); nil allows it.
	Escalate func(ctx context.Context) bool
}

func (d *Dispatcher) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Tick runs one full cycle: workflow upkeep, prioritisation, correlation,
// system checks, planning and delivery.
func (d *Dispatcher) Tick(ctx context.Context) error {
	if _, err := d.Store.ExpireSuppressions(ctx); err != nil {
		return fmt.Errorf("expire suppressions: %w", err)
	}
	policy, err := d.Store.RiskPolicy(ctx)
	if err != nil {
		return err
	}
	if _, err := d.Store.Prioritize(ctx, policy, d.now()); err != nil {
		return fmt.Errorf("prioritize: %w", err)
	}
	if _, err := planner.Rebuild(ctx, d.Store, d.now()); err != nil {
		return fmt.Errorf("action plan: %w", err)
	}
	if err := d.Store.CorrelateIncidents(ctx); err != nil {
		return fmt.Errorf("correlate: %w", err)
	}
	sys, err := d.Store.DetectSystemProblems(ctx)
	if err != nil {
		return fmt.Errorf("detect system problems: %w", err)
	}
	if err := d.Store.SyncSystemIncidents(ctx, sys); err != nil {
		return fmt.Errorf("system incidents: %w", err)
	}
	if err := d.Plan(ctx); err != nil {
		return fmt.Errorf("plan: %w", err)
	}
	return d.Deliver(ctx)
}

// Plan queues deliveries for new, raised, escalated and resolved incidents.
func (d *Dispatcher) Plan(ctx context.Context) error {
	routes, err := d.Store.ListRoutes(ctx)
	if err != nil {
		return err
	}
	announce, err := d.Store.IncidentsToAnnounce(ctx)
	if err != nil {
		return err
	}
	// Per route, collect what it would announce this cycle. More than
	// burstThreshold becomes one summary, so onboarding a server or a big
	// feed update never floods a channel (FR-08: grouping, no storms).
	perRoute := map[int64][]store.Incident{}
	for _, in := range announce {
		for _, r := range routes {
			if !r.Escalation && routeMatches(r, in) {
				perRoute[r.ID] = append(perRoute[r.ID], in)
			}
		}
	}
	for _, r := range routes {
		list := perRoute[r.ID]
		if len(list) == 0 {
			continue
		}
		r := r
		if len(list) > burstThreshold {
			msg, key, err := d.burstMessage(ctx, list, "opened")
			if err != nil {
				return err
			}
			if _, err := d.Store.EnqueueDelivery(ctx, r.ChannelID, &r.ID, nil, "digest", key, msg); err != nil {
				return err
			}
			continue
		}
		for _, in := range list {
			in := in
			event := "opened"
			if in.NotifiedPriority != "" {
				event = "priority_raised"
			}
			key := fmt.Sprintf("incident:%d:%s:%s", in.ID, event, in.Priority)
			if _, err := d.Store.EnqueueDelivery(ctx, r.ChannelID, &r.ID, &in.ID, event, key, d.message(in, event)); err != nil {
				return err
			}
		}
	}
	for _, in := range announce {
		// Recorded even when no route matched, so adding a route later does
		// not flood it with every historical incident.
		if err := d.Store.MarkIncidentNotified(ctx, in.ID, in.Priority); err != nil {
			return err
		}
	}

	if err := d.escalate(ctx, routes); err != nil {
		return err
	}

	resolved, err := d.Store.ResolvedToAnnounce(ctx)
	if err != nil {
		return err
	}
	perRoute = map[int64][]store.Incident{}
	for _, in := range resolved {
		for _, r := range routes {
			if !r.Escalation && r.SendResolved && routeMatches(r, in) {
				perRoute[r.ID] = append(perRoute[r.ID], in)
			}
		}
	}
	for _, r := range routes {
		list := perRoute[r.ID]
		r := r
		if len(list) > burstThreshold {
			msg, key, err := d.burstMessage(ctx, list, "resolved")
			if err != nil {
				return err
			}
			if _, err := d.Store.EnqueueDelivery(ctx, r.ChannelID, &r.ID, nil, "digest", key, msg); err != nil {
				return err
			}
			continue
		}
		for _, in := range list {
			in := in
			key := fmt.Sprintf("incident:%d:resolved", in.ID)
			if _, err := d.Store.EnqueueDelivery(ctx, r.ChannelID, &r.ID, &in.ID, "resolved", key, d.message(in, "resolved")); err != nil {
				return err
			}
		}
	}
	for _, in := range resolved {
		if err := d.Store.MarkResolvedNotified(ctx, in.ID); err != nil {
			return err
		}
	}
	return nil
}

// routeMatches applies a route's filters. Resolved and escalation events use
// the priority the incident reached.
func routeMatches(r store.Route, in store.Incident) bool {
	if !r.Enabled {
		return false
	}
	if r.SOSOnly && !in.SOS {
		return false
	}
	pri := in.Priority
	if in.NotifiedPriority != "" && in.NotifiedPriority < pri {
		pri = in.NotifiedPriority
	}
	if !risk.PriorityAtLeast(pri, r.MinPriority) {
		return false
	}
	if len(r.Kinds) > 0 && !contains(r.Kinds, in.Kind) {
		return false
	}
	if len(r.TeamIDs) > 0 {
		if in.OwnerTeamID == nil {
			return false
		}
		found := false
		for _, t := range r.TeamIDs {
			if t == *in.OwnerTeamID {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	if len(r.Environments) > 0 {
		var detail struct {
			Environments []string `json:"environments"`
		}
		_ = json.Unmarshal(in.Detail, &detail)
		match := false
		for _, e := range detail.Environments {
			if contains(r.Environments, e) {
				match = true
			}
		}
		if !match {
			return false
		}
	}
	return true
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func (d *Dispatcher) message(in store.Incident, event string) Message {
	var det map[string]any
	_ = json.Unmarshal(in.Detail, &det)
	m := Message{
		Event: event, IncidentID: in.ID, Kind: in.Kind, Key: in.Key, Title: in.Title, Priority: in.Priority,
		SOS: in.SOS, Status: in.Status, OwnerTeam: in.OwnerTeam, Findings: in.FindingCount, Assets: in.AssetCount,
		Escalation: in.EscalationLevel, Detail: det, At: d.now().UTC(),
	}
	if d.BaseURL != "" {
		m.Link = strings.TrimSuffix(d.BaseURL, "/") + fmt.Sprintf("/incidents/%d", in.ID)
	}
	list := func(k string) []string {
		var out []string
		if v, ok := det[k].([]any); ok {
			for _, x := range v {
				if s, ok := x.(string); ok && s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	}
	switch in.Kind {
	case "vulnerability", "end_of_life":
		m.Summary = append(m.Summary, fmt.Sprintf("%d finding(s) on %d asset(s): %s", in.FindingCount, in.AssetCount, strings.Join(list("assets"), ", ")))
		if c := list("components"); len(c) > 0 {
			m.Summary = append(m.Summary, "Components: "+strings.Join(c, ", "))
		}
		if e := list("environments"); len(e) > 0 {
			m.Summary = append(m.Summary, "Environments: "+strings.Join(e, ", "))
		}
		if kev, _ := det["known_exploited"].(bool); kev {
			m.Summary = append(m.Summary, "Known exploited in the wild (CISA KEV)")
		}
		if in.Kind == "vulnerability" {
			if f := list("fixed_versions"); len(f) > 0 {
				m.Action = "Upgrade to " + strings.Join(f, " / ") + " or later"
			} else {
				m.Action = "No fixed version is listed yet; review the advisory for mitigations"
			}
		} else {
			m.Action = "Move to a supported release"
		}
	case "feed":
		m.Summary = append(m.Summary, "Findings for this source are going out of date; affected components cannot be evaluated reliably")
		if e, _ := det["last_error"].(string); e != "" {
			m.Summary = append(m.Summary, "Last error: "+e)
		}
		m.Action = "Check outbound connectivity to the feed or its mirror"
	case "collection":
		if e, _ := det["last_error"].(string); e != "" {
			m.Summary = append(m.Summary, "Last error: "+e)
		}
		m.Action = "Check the agent, integration credentials or network path"
	case "coverage":
		m.Action = "Confirm whether software was removed or the collector lost access"
	}
	switch event {
	case "escalated":
		if in.EscalationLevel >= 2 {
			m.Summary = append([]string{"Remediation deadline has passed"}, m.Summary...)
		} else {
			m.Summary = append([]string{"Not acknowledged within the agreed time"}, m.Summary...)
		}
	case "resolved":
		m.Summary = []string{"No open findings remain for this incident"}
		m.Action = ""
	}
	return m
}

// Deliver sends due deliveries, honouring quiet hours and rate limits.
func (d *Dispatcher) Deliver(ctx context.Context) error {
	due, err := d.Store.DueDeliveries(ctx, 100)
	if err != nil {
		return err
	}
	if len(due) == 0 {
		return nil
	}
	routes := map[int64]*store.Route{}
	channels := map[int64]*store.Channel{}
	for _, del := range due {
		var msg Message
		_ = json.Unmarshal(del.Payload, &msg)
		var route *store.Route
		if del.RouteID != nil {
			if route = routes[*del.RouteID]; route == nil {
				if r, err := d.Store.GetRoute(ctx, *del.RouteID); err == nil {
					route, routes[r.ID] = r, r
				}
			}
		}
		if route != nil && !msg.SOS && del.Event != "test" {
			if until, quiet := quietUntil(*route, d.now()); quiet {
				if err := d.Store.DeferDelivery(ctx, del.ID, until); err != nil {
					return err
				}
				continue
			}
			sent, err := d.Store.RouteSentSince(ctx, route.ID, d.now().Add(-time.Hour))
			if err != nil {
				return err
			}
			if route.MaxPerHour > 0 && sent >= route.MaxPerHour {
				if err := d.Store.HoldDelivery(ctx, del.ID, "rate limit reached; included in the next digest"); err != nil {
					return err
				}
				continue
			}
		}
		ch := channels[del.ChannelID]
		if ch == nil {
			if ch, err = d.Store.GetChannel(ctx, del.ChannelID); err != nil {
				return err
			}
			channels[ch.ID] = ch
		}
		sendErr := d.send(ctx, ch, del.ID, msg)
		if sendErr != nil {
			d.Log.Warn("delivery failed", "delivery", del.ID, "channel", ch.Name, "attempt", del.Attempts+1, "err", sendErr)
			if err := d.Store.DeliveryFailed(ctx, del.ID, del.Attempts, maxAttempts, sendErr); err != nil {
				return err
			}
		} else if err := d.Store.DeliverySent(ctx, del.ID); err != nil {
			return err
		}
		_ = d.Store.ChannelResult(ctx, ch.ID, sendErr)
	}
	return nil
}

func (d *Dispatcher) send(ctx context.Context, ch *store.Channel, deliveryID int64, msg Message) error {
	var cfg ChannelConfig
	if err := json.Unmarshal(ch.Config, &cfg); err != nil {
		return err
	}
	secret, err := d.Secrets.Resolve(ctx, ch.SecretRef)
	if err != nil {
		return err
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return d.Sender.Send(sctx, ch.Kind, cfg, secret, deliveryID, msg)
}

// SendTest sends a test message through a channel immediately.
func (d *Dispatcher) SendTest(ctx context.Context, ch *store.Channel) error {
	msg := Message{Event: "test", Title: "Stackurity test notification", At: d.now().UTC(),
		Summary: []string{"This channel is configured correctly."}}
	err := d.send(ctx, ch, 0, msg)
	_ = d.Store.ChannelResult(ctx, ch.ID, err)
	return err
}

// Digest sends one summary per channel for deliveries held by rate limits.
func (d *Dispatcher) Digest(ctx context.Context) error {
	held, err := d.Store.HeldByChannel(ctx)
	if err != nil {
		return err
	}
	stamp := d.now().UTC().Format("2006-01-02T15")
	for chID, list := range held {
		var lines []string
		var ids []int64
		for _, del := range list {
			var m Message
			_ = json.Unmarshal(del.Payload, &m)
			lines = append(lines, m.Subject())
			ids = append(ids, del.ID)
		}
		if len(lines) > 50 {
			lines = append(lines[:50], fmt.Sprintf("…and %d more", len(lines)-50))
		}
		key := "digest:" + stamp
		msg := Message{Event: "digest", Title: fmt.Sprintf("Stackurity digest: %d notification(s) held by rate limits", len(ids)),
			Summary: lines, At: d.now().UTC()}
		if d.BaseURL != "" {
			msg.Link = strings.TrimSuffix(d.BaseURL, "/") + "/incidents"
		}
		if _, err := d.Store.EnqueueDelivery(ctx, chID, nil, nil, "digest", key, msg); err != nil {
			return err
		}
		if err := d.Store.MarkDigested(ctx, ids, key); err != nil {
			return err
		}
	}
	return d.Deliver(ctx)
}

// quietUntil reports whether now is within the route's quiet hours and, if
// so, when they end.
func quietUntil(r store.Route, now time.Time) (time.Time, bool) {
	if r.QuietStart == "" || r.QuietEnd == "" {
		return time.Time{}, false
	}
	loc, err := time.LoadLocation(r.Timezone)
	if err != nil {
		loc = time.UTC
	}
	local := now.In(loc)
	start, err1 := time.ParseInLocation("15:04", r.QuietStart, loc)
	end, err2 := time.ParseInLocation("15:04", r.QuietEnd, loc)
	if err1 != nil || err2 != nil {
		return time.Time{}, false
	}
	day := func(t time.Time, base time.Time) time.Time {
		return time.Date(base.Year(), base.Month(), base.Day(), t.Hour(), t.Minute(), 0, 0, loc)
	}
	s, e := day(start, local), day(end, local)
	if !e.After(s) { // window crosses midnight
		if local.Before(e) {
			return e, true
		}
		if !local.Before(s) {
			return e.AddDate(0, 0, 1), true
		}
		return time.Time{}, false
	}
	if !local.Before(s) && local.Before(e) {
		return e, true
	}
	return time.Time{}, false
}

// ValidQuietTime checks "HH:MM".
func ValidQuietTime(s string) bool {
	if s == "" {
		return true
	}
	_, err := time.Parse("15:04", s)
	return err == nil
}

// burstMessage summarises many incidents as the actions that resolve them.
func (d *Dispatcher) burstMessage(ctx context.Context, list []store.Incident, event string) (Message, string, error) {
	ids := make([]int64, 0, len(list))
	sos, kev := 0, 0
	top := "P4"
	for _, in := range list {
		ids = append(ids, in.ID)
		if in.SOS {
			sos++
		}
		var det struct {
			KnownExploited bool `json:"known_exploited"`
		}
		_ = json.Unmarshal(in.Detail, &det)
		if det.KnownExploited {
			kev++
		}
		if in.Priority < top {
			top = in.Priority
		}
	}
	assetIDs, names, err := d.Store.IncidentAssetIDs(ctx, ids)
	if err != nil {
		return Message{}, "", err
	}
	where := strings.Join(firstN(names, 3), ", ")
	if len(names) > 3 {
		where += fmt.Sprintf(" and %d more", len(names)-3)
	}
	m := Message{Event: "digest", Priority: top, SOS: sos > 0, At: d.now().UTC()}
	if event == "resolved" {
		m.Title = fmt.Sprintf("%s resolved on %s", plural(len(list), "incident"), where)
		m.Summary = []string{"No open findings remain for these incidents."}
	} else {
		m.Title = fmt.Sprintf("%s on %s", plural(len(list), "new incident"), where)
		if sos > 0 {
			m.Summary = append(m.Summary, fmt.Sprintf("%s need urgent attention (SOS)", thousands(sos)))
		}
		if kev > 0 {
			m.Summary = append(m.Summary, fmt.Sprintf("%s are known to be exploited in the wild (CISA KEV)", thousands(kev)))
		}
		groups, err := d.Store.FixGroupsForAssets(ctx, assetIDs, 5)
		if err != nil {
			return Message{}, "", err
		}
		if len(groups) > 0 {
			m.Summary = append(m.Summary, "Top actions:")
		}
		for _, g := range groups {
			line := fmt.Sprintf("%s on %s: resolves %s", g.Title, g.AssetName, plural(g.FindingCount, "finding"))
			if g.UniqueIssues > 0 && g.UniqueIssues != g.FindingCount {
				line += fmt.Sprintf(" (%s)", plural(g.UniqueIssues, "unique vulnerability"))
			}
			line += ", highest " + g.TopPriority
			if g.Needs == "ubuntu-pro" {
				line += ", needs Ubuntu Pro"
			}
			m.Summary = append(m.Summary, line)
		}
		m.Action = "Open the action plan to see what to do first; each action lists its individual findings."
	}
	if d.BaseURL != "" {
		m.Link = strings.TrimSuffix(d.BaseURL, "/") + "/action-plan"
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	h := sha256.New()
	for _, id := range ids {
		fmt.Fprintf(h, "%d,", id)
	}
	key := fmt.Sprintf("burst:%s:%x", event, h.Sum(nil)[:8])
	return m, key, nil
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	if strings.HasSuffix(word, "y") {
		return thousands(n) + " " + strings.TrimSuffix(word, "y") + "ies"
	}
	return thousands(n) + " " + word + "s"
}

// thousands formats 19558 as "19,558".
func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0 && s[i-1] != '-'; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
