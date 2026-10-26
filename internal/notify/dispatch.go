package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

const maxAttempts = 8

// deliveryLease is how long a claimed delivery is reserved for the replica
// sending it; a replica that dies mid-send leaves it to be retried after this.
const deliveryLease = 5 * time.Minute

type Dispatcher struct {
	Store   *store.Store
	Sender  *Sender
	Secrets secrets.Resolver
	Log     *slog.Logger
	BaseURL string // dashboard URL for links, e.g. https://stackurity.example.com
	Now     func() time.Time
	// Lease is how long a claimed delivery is reserved for this replica;
	// zero means deliveryLease. Tests shorten it.
	Lease time.Duration
	// Escalate reports whether the workspace in ctx may escalate overdue
	// incidents (a paid feature); nil allows it.
	Escalate func(ctx context.Context) bool
	// Platform returns incidents about the installation itself (stuck
	// background tasks, no intelligence); nil disables them. They are raised
	// in the workspace PlatformTarget returns, the operator's, or in the
	// default workspace when PlatformTarget is nil.
	Platform func(ctx context.Context) ([]store.SystemIncident, error)
	// PlatformTarget returns the workspace for platform incidents, or 0 and
	// the reason when there is none (it is missing or disabled).
	PlatformTarget func(ctx context.Context) (id int64, why string, err error)
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
	// Ignore rules for every asset also cover issues found since.
	if _, err := d.Store.ApplyExceptions(ctx); err != nil {
		return fmt.Errorf("ignore rules: %w", err)
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
	here, err := d.platformHere(ctx)
	if err != nil {
		return fmt.Errorf("platform workspace: %w", err)
	}
	if here {
		p, err := d.Platform(ctx)
		if err != nil {
			return fmt.Errorf("platform health: %w", err)
		}
		sys = append(sys, p...)
	}
	if err := d.Store.SyncSystemIncidents(ctx, sys); err != nil {
		return fmt.Errorf("system incidents: %w", err)
	}
	if err := d.Plan(ctx); err != nil {
		return fmt.Errorf("plan: %w", err)
	}
	return d.Deliver(ctx)
}

// platformHere reports whether platform incidents belong to the workspace
// ctx is scoped to.
func (d *Dispatcher) platformHere(ctx context.Context) (bool, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok || d.Platform == nil {
		return false, nil
	}
	if d.PlatformTarget == nil {
		return ws == tenant.DefaultWorkspace, nil
	}
	id, _, err := d.PlatformTarget(tenant.System(ctx))
	return err == nil && id == ws, err
}

// PlatformFallback logs critical platform problems while there is no
// workspace to raise them in, because the configured one is missing or
// disabled. Instance admins also see them in the dashboard's banner. It runs
// in system scope.
func (d *Dispatcher) PlatformFallback(ctx context.Context) error {
	if d.Platform == nil || d.PlatformTarget == nil {
		return nil
	}
	_, why, err := d.PlatformTarget(ctx)
	if err != nil || why == "" {
		return err
	}
	problems, err := d.Platform(ctx)
	if err != nil {
		return err
	}
	for _, p := range problems {
		d.Log.Error("platform problem not raised as an incident", "problem", p.Key, "title", p.Title, "reason", why,
			"fix", "set STACKURITY_PLATFORM_WORKSPACE to an active workspace")
	}
	return nil
}

// Plan queues what this cycle has to say: grouped messages to people
// (urgent alerts, "connected" messages, overdue alerts, summaries; see
// grouped.go) and, for Jira channels, issue creation and updates per
// incident.
func (d *Dispatcher) Plan(ctx context.Context) error {
	routes, err := d.Store.ListRoutes(ctx)
	if err != nil {
		return err
	}
	announce, err := d.Store.IncidentsToAnnounce(ctx)
	if err != nil {
		return err
	}
	// Tracker channels (Jira) keep one issue per incident: they get no
	// grouped messages, and once an incident has an issue it is updated
	// from the issue's state (planIssueUpdates) rather than per event.
	tracker, err := d.trackerChannels(ctx)
	if err != nil {
		return err
	}
	ids := make([]int64, len(announce))
	for i, in := range announce {
		ids[i] = in.ID
	}
	issued, err := d.Store.IssuedChannels(ctx, ids)
	if err != nil {
		return err
	}

	// An asset's first scan is quiet: the backlog it reports raises no
	// urgent alert and no Jira issue; one "connected" message describes it
	// instead. Until its first complete collection is evaluated, incidents
	// found only on it wait. A finding is backlog while its asset is not
	// announced (quiet), or when it was first seen before the asset's
	// announcement (Backlog, assets connected since 0.9).
	fresh, err := d.Store.UnannouncedAssets(ctx)
	if err != nil {
		return err
	}
	quiet, waiting := map[int64]bool{}, map[int64]bool{}
	var ready []store.NewAsset
	for _, a := range fresh {
		quiet[a.ID] = true
		if a.Ready {
			ready = append(ready, a)
		} else {
			waiting[a.ID] = true
		}
	}
	rows := map[int64][]store.IssueCount{}
	if len(ids) > 0 {
		counts, err := d.Store.IncidentIssues(ctx, ids)
		if err != nil {
			return err
		}
		for _, c := range counts {
			if quiet[c.AssetID] {
				c.Backlog = true
			}
			rows[c.IncidentID] = append(rows[c.IncidentID], c)
		}
	}
	var live []store.Incident // incidents that may raise urgent alerts and Jira issues
	var notified []int64
	for _, in := range announce {
		if isFindingKind(in.Kind) && len(rows[in.ID]) > 0 {
			known, wait := false, false
			for _, c := range rows[in.ID] {
				known = known || !c.Backlog
				wait = wait || waiting[c.AssetID]
			}
			if !known && wait {
				continue // deferred until the first scan is evaluated
			}
			if !known {
				notified = append(notified, in.ID) // first-scan backlog
				continue
			}
		}
		live = append(live, in)
		notified = append(notified, in.ID)
	}

	for _, in := range live {
		in := in
		for _, r := range routes {
			if !tracker[r.ChannelID] || r.Escalation || !routeMatches(r, in) || issued[in.ID][r.ChannelID] {
				continue
			}
			r := r
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

	people := func(r store.Route) bool {
		return r.Enabled && !tracker[r.ChannelID] && r.Mode == store.ModeUrgentSummary
	}
	// Issues that came back after a fix are urgent whatever their priority.
	regressedAll, regressedUpTo, err := d.Store.RegressedToAnnounce(ctx)
	if err != nil {
		return err
	}
	var regressed []store.IssueCount
	for _, c := range regressedAll {
		if !c.Backlog && !quiet[c.AssetID] {
			regressed = append(regressed, c)
		}
	}
	var infos map[string]store.FixInfo
	for _, r := range routes {
		if !people(r) {
			continue
		}
		var urgent []store.Incident
		var urgentIDs []int64
		for _, in := range live {
			if urgentIncident(r, in) {
				urgent = append(urgent, in)
				urgentIDs = append(urgentIDs, in.ID)
			}
		}
		var back []store.IssueCount
		if assetsWanted(r) {
			for _, c := range regressed {
				if issueInScope(r, c) {
					back = append(back, c)
				}
			}
		}
		if len(urgent) == 0 && len(back) == 0 {
			continue
		}
		if infos == nil {
			all := append([]store.IssueCount(nil), regressed...)
			for _, in := range live {
				all = append(all, rows[in.ID]...)
			}
			if infos, err = d.Store.FixInfos(ctx, fixIDs(all)); err != nil {
				return err
			}
		}
		msg, ok := d.urgentMessage(r, urgent, rows, quiet, infos, back)
		if !ok {
			continue
		}
		r := r
		key := keyOf("urgent", r.ID, urgentIDs)
		if len(back) > 0 {
			key += ":regressed:" + regressedUpTo.UTC().Format(time.RFC3339Nano)
		}
		if err := d.enqueueRouted(ctx, r, EventUrgent, key, msg); err != nil {
			return err
		}
	}
	// Recorded even when no route matched, as incidents are below.
	if !regressedUpTo.IsZero() {
		if err := d.Store.MarkRegressedNotified(ctx, regressedUpTo); err != nil {
			return err
		}
	}

	if len(ready) > 0 {
		readyIDs := make([]int64, len(ready))
		for i, a := range ready {
			readyIDs[i] = a.ID
		}
		fixes, err := d.Store.OpenFixes(ctx, readyIDs)
		if err != nil {
			return err
		}
		byAsset := fixesByAsset(fixes)
		for _, r := range routes {
			if !people(r) || !assetsWanted(r) {
				continue
			}
			var mine []store.NewAsset
			var mineIDs []int64
			for _, a := range ready {
				if assetInScope(r, a.ID, a.Environment, a.OwnerTeamID) {
					mine, mineIDs = append(mine, a), append(mineIDs, a.ID)
				}
			}
			if len(mine) == 0 {
				continue
			}
			r := r
			msg := d.connectedMessage(r, mine, byAsset)
			if err := d.enqueueRouted(ctx, r, EventConnected, keyOf("connected", r.ID, mineIDs), msg); err != nil {
				return err
			}
		}
		if err := d.Store.MarkAssetsAnnounced(ctx, readyIDs); err != nil {
			return err
		}
	}
	// Recorded even when no route matched, so adding a route later does
	// not flood it with every historical incident.
	if err := d.Store.MarkIncidentsNotified(ctx, notified); err != nil {
		return err
	}

	if err := d.planOverdue(ctx, routes, tracker); err != nil {
		return err
	}

	// Resolved incidents are counted in summaries (findings fixed), never
	// announced one by one; Jira issues are resolved by planIssueUpdates.
	resolved, err := d.Store.ResolvedToAnnounce(ctx)
	if err != nil {
		return err
	}
	done := make([]int64, len(resolved))
	for i, in := range resolved {
		done[i] = in.ID
	}
	if err := d.Store.MarkResolvedNotifiedAll(ctx, done); err != nil {
		return err
	}
	if err := d.planSummaries(ctx, routes, tracker); err != nil {
		return err
	}
	return d.planIssueUpdates(ctx)
}

// planOverdue records escalation levels of overdue incidents (licensed
// builds) and tells people about it at most once a day per route: when
// urgent issues have just passed their fix deadline, one message groups
// every overdue urgent issue by fix. Jira issues still get one comment
// each.
func (d *Dispatcher) planOverdue(ctx context.Context, routes []store.Route, tracker map[int64]bool) error {
	esc, err := d.escalate(ctx)
	if err != nil || len(esc) == 0 {
		return err
	}
	ids := make([]int64, 0, len(esc))
	for id := range esc {
		ids = append(ids, id)
	}
	incs, err := d.Store.IncidentsByID(ctx, ids)
	if err != nil {
		return err
	}
	var counts []store.IssueCount
	var infos map[string]store.FixInfo
	for _, r := range routes {
		if !r.Escalation || !r.Enabled {
			continue
		}
		r := r
		if tracker[r.ChannelID] {
			for _, in := range incs {
				in.EscalationLevel = esc[in.ID]
				if !routeMatches(r, in) {
					continue
				}
				key := fmt.Sprintf("incident:%d:escalated:%d", in.ID, in.EscalationLevel)
				if _, err := d.Store.EnqueueDelivery(ctx, r.ChannelID, &r.ID, &in.ID, "escalated", key, d.message(in, "escalated")); err != nil {
					return err
				}
			}
			continue
		}
		if r.Mode != store.ModeUrgentSummary {
			continue // the overdue section of the summary covers it
		}
		crossed := false
		for _, in := range incs {
			if esc[in.ID] >= 2 && overdueUrgent(in.Priority, in.SOS) && inScope(r, in) {
				crossed = true
				break
			}
		}
		if !crossed {
			continue
		}
		if counts == nil {
			now := d.now()
			if counts, err = d.Store.CountIssues(ctx, store.IssuesOverdue, now, now); err != nil {
				return err
			}
			if infos, err = d.Store.FixInfos(ctx, fixIDs(counts)); err != nil {
				return err
			}
		}
		msg, ok := d.overdueMessage(r, counts, infos)
		if !ok {
			continue
		}
		loc, err := time.LoadLocation(r.Timezone)
		if err != nil {
			loc = time.UTC
		}
		key := fmt.Sprintf("overdue:%d:%s", r.ID, d.now().In(loc).Format("2006-01-02"))
		if err := d.enqueueRouted(ctx, r, EventOverdue, key, msg); err != nil {
			return err
		}
	}
	return nil
}

// trackerChannels returns the ids of the workspace's tracker (Jira) channels.
func (d *Dispatcher) trackerChannels(ctx context.Context) (map[int64]bool, error) {
	chs, err := d.Store.ListChannels(ctx)
	if err != nil {
		return nil, err
	}
	out := map[int64]bool{}
	for _, c := range chs {
		if c.Kind == KindJira {
			out[c.ID] = true
		}
	}
	return out, nil
}

// planIssueUpdates queues an update for every tracker issue whose incident
// changed (priority, findings, assets) since the issue was last updated, and
// a resolution for every issue whose incident resolved. Updates are keyed by
// when the issue was last updated, so each change is queued once.
func (d *Dispatcher) planIssueUpdates(ctx context.Context) error {
	changes, err := d.Store.IssueChanges(ctx)
	if err != nil {
		return err
	}
	for _, c := range changes {
		in := c.Incident
		event, key := "updated", fmt.Sprintf("issue:%d:updated:%d", c.LinkID, c.SyncedAt.UnixMicro())
		if c.Resolution {
			event, key = "resolved", fmt.Sprintf("issue:%d:resolved", c.LinkID)
		}
		if _, err := d.Store.EnqueueDelivery(ctx, c.ChannelID, nil, &in.ID, event, key, d.message(in, event)); err != nil {
			return err
		}
	}
	return nil
}

// routeMatches applies a route's filters. Resolved and escalation events use
// the priority the incident reached.
func routeMatches(r store.Route, in store.Incident) bool {
	// Tracker issues describe the whole incident, across every asset, so a
	// route limited to projects never creates or updates them.
	if len(r.ProjectIDs) > 0 || !inScope(r, in) {
		return false
	}
	pri := in.Priority
	if in.NotifiedPriority != "" && in.NotifiedPriority < pri {
		pri = in.NotifiedPriority
	}
	return risk.PriorityAtLeast(pri, r.MinPriority)
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
	case "platform":
		m.Summary = append(m.Summary, "A problem with the Stackurity installation itself: findings and notifications may be out of date")
		m.Action = "An instance administrator should check Platform health in the dashboard and the server logs"
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
		ch := channels[del.ChannelID]
		if ch == nil {
			if ch, err = d.Store.GetChannel(ctx, del.ChannelID); err != nil {
				return err
			}
			channels[ch.ID] = ch
		}
		// Quiet hours and hourly limits are for people: an issue tracker
		// is kept current. SOS is never delayed. A summary is never held:
		// it is where held messages go.
		if route != nil && !msg.SOS && del.Event != "test" && ch.Kind != KindJira {
			if until, quiet := quietUntil(*route, d.now()); quiet {
				if err := d.Store.DeferDelivery(ctx, del.ID, until); err != nil {
					return err
				}
				continue
			}
			if route.MaxPerHour > 0 && del.Event != EventSummary {
				sent, err := d.Store.RouteSentSince(ctx, route.ID, d.now().Add(-time.Hour))
				if err != nil {
					return err
				}
				if sent >= route.MaxPerHour {
					if err := d.Store.HoldDelivery(ctx, del.ID, "hourly limit reached; counted in the next summary"); err != nil {
						return err
					}
					continue
				}
			}
		}
		// Claim right before sending: another replica's Tick or Digest may
		// be delivering the same queue.
		lease := d.Lease
		if lease <= 0 {
			lease = deliveryLease
		}
		attempts, ok, err := d.Store.ClaimDelivery(ctx, del.ID, lease)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		sendErr := d.send(ctx, ch, del, attempts, msg)
		// Record what happened even if shutdown began during the send, so a
		// sent message is not sent again when the lease ends.
		bg := context.WithoutCancel(ctx)
		if sendErr != nil {
			d.Log.Warn("delivery failed", "delivery", del.ID, "channel", ch.Name, "attempt", attempts, "err", sendErr)
			// The receiver may ask for a pause (Retry-After), or say that
			// retrying cannot help (rejected credentials).
			var wait time.Duration
			var ra *RetryAfterError
			if errors.As(sendErr, &ra) {
				wait = ra.Wait
			}
			n := attempts
			var pe *PermanentError
			if errors.As(sendErr, &pe) {
				n = maxAttempts
			}
			if err := d.Store.DeliveryFailedWait(bg, del.ID, n, maxAttempts, sendErr, wait); err != nil {
				return err
			}
		} else if err := d.Store.DeliverySent(bg, del.ID); err != nil {
			return err
		}
		_ = d.Store.ChannelResult(bg, ch.ID, sendErr)
	}
	return nil
}

// send delivers one claimed delivery; attempts counts this attempt.
func (d *Dispatcher) send(ctx context.Context, ch *store.Channel, del store.Delivery, attempts int, msg Message) error {
	if ch.Kind == KindJira {
		sctx, cancel := context.WithTimeout(ctx, jiraTimeout)
		defer cancel()
		return d.syncJira(sctx, ch, del, attempts, msg)
	}
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
	return d.Sender.Send(sctx, ch.Kind, cfg, secret, del.ID, msg)
}

// SendTest sends a test message through a channel immediately. For Jira it
// checks the credentials and project access instead, creating nothing.
func (d *Dispatcher) SendTest(ctx context.Context, ch *store.Channel) error {
	if ch.Kind == KindJira {
		err := d.checkJira(ctx, ch)
		_ = d.Store.ChannelResult(ctx, ch.ID, err)
		return err
	}
	msg := Message{Event: "test", Title: "Stackurity test notification", At: d.now().UTC(),
		Summary: []string{"This channel is configured correctly."}}
	err := d.send(ctx, ch, store.Delivery{Event: "test"}, 1, msg)
	_ = d.Store.ChannelResult(ctx, ch.ID, err)
	return err
}

// Digest runs hourly. Messages a route's hourly limit held are taken in
// by that route's next summary, never sent one by one; this plans the
// summaries that are due (as every Tick does) and, for held messages whose
// route was deleted, sends one digest per channel.
func (d *Dispatcher) Digest(ctx context.Context) error {
	routes, err := d.Store.ListRoutes(ctx)
	if err != nil {
		return err
	}
	tracker, err := d.trackerChannels(ctx)
	if err != nil {
		return err
	}
	if err := d.planSummaries(ctx, routes, tracker); err != nil {
		return err
	}
	held, err := d.Store.HeldByChannel(ctx)
	if err != nil {
		return err
	}
	stamp := d.now().UTC().Format("2006-01-02T15")
	for chID, list := range held {
		var lines []string
		var ids []int64
		for _, del := range list {
			if del.RouteID != nil {
				continue
			}
			var m Message
			_ = json.Unmarshal(del.Payload, &m)
			lines = append(lines, m.Subject())
			ids = append(ids, del.ID)
		}
		if len(ids) == 0 {
			continue
		}
		if len(lines) > 20 {
			lines = append(lines[:20], fmt.Sprintf("+%d more", len(lines)-20))
		}
		key := "digest:" + stamp
		msg := Message{Event: "digest", Title: fmt.Sprintf("Stackurity: %s held by an hourly limit", plural(len(ids), "notification")),
			Summary: lines, At: d.now().UTC(), Link: d.url("/settings/notifications", url.Values{"tab": {"deliveries"}})}
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

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	switch {
	case strings.HasSuffix(word, "y"):
		return thousands(n) + " " + strings.TrimSuffix(word, "y") + "ies"
	case strings.HasSuffix(word, "x"), strings.HasSuffix(word, "s"), strings.HasSuffix(word, "ch"):
		return thousands(n) + " " + word + "es"
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

func firstN[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}
