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
	"sync"
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
	// PlatformMail delivers email sent by Stackurity (stackurity_email
	// channels) through the platform's own mail server; nil (self-hosted)
	// turns that channel kind off. EmailQuota limits each organisation
	// (zero: DefaultEmailLimits); MaxRecipients caps a channel's recipients.
	PlatformMail  Mailer
	EmailQuota    store.EmailLimits
	MaxRecipients int
	// SlackApp is the Stackurity Slack app ("Add to Slack"); nil turns it
	// off. Its signing secret verifies clicks on channels it added.
	SlackApp *SlackApp
}

// tickSkips counts, per store and workspace, the ticks in a row whose
// upkeep waited for an evaluation (Dispatcher values are copied, so the
// count lives outside them).
var (
	tickSkipsMu sync.Mutex
	tickSkips   = map[tickSkipKey]int{}
)

type tickSkipKey struct {
	st *store.Store
	ws int64
}

func (d *Dispatcher) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// tickLockWait is how long a tick waits for a running evaluation of its
// workspace before it leaves the upkeep of findings to the next tick;
// after a few ticks in a row without it, it waits longer, so a workspace
// that evaluates all the time still gets its upkeep.
const (
	tickLockWait     = 5 * time.Second
	tickLockWaitLong = 30 * time.Second
	tickSkipsBefore  = 3
)

// Tick runs one full cycle: workflow upkeep, prioritisation, correlation,
// system checks, planning and delivery.
//
// Everything up to planning writes findings an evaluation also writes
// (states, priorities, fix groups, incidents), many rows per statement.
// Run at the same time, the two could lock the same rows in opposite
// orders and deadlock, so this part holds the workspace's evaluation lock
// (Store.LockEvaluationsWait). When an evaluation runs longer than the
// wait, the tick delivers what is queued and leaves the rest to the next.
func (d *Dispatcher) Tick(ctx context.Context) error {
	ws, _ := tenant.Workspace(ctx)
	wait := tickLockWait
	if d.skipped(ws, false) >= tickSkipsBefore {
		wait = tickLockWaitLong
	}
	release, err := d.Store.LockEvaluationsWait(ctx, wait)
	switch {
	case errors.Is(err, store.ErrEvaluationBusy):
		n := d.skipped(ws, true)
		if d.Log != nil {
			d.Log.Info("an evaluation is running: findings upkeep waits for the next tick", "workspace", ws, "waited", wait, "ticks_skipped", n)
		}
		return d.Deliver(ctx)
	case err != nil:
		return fmt.Errorf("evaluation lock: %w", err)
	}
	d.resetSkips(ws)
	err = d.upkeep(ctx)
	release()
	if err != nil {
		return err
	}
	return d.Deliver(ctx)
}

// skipped returns how many ticks in a row the workspace's upkeep was left
// for later, counting one more when add.
func (d *Dispatcher) skipped(ws int64, add bool) int {
	tickSkipsMu.Lock()
	defer tickSkipsMu.Unlock()
	k := tickSkipKey{d.Store, ws}
	if add {
		tickSkips[k]++
	}
	return tickSkips[k]
}

func (d *Dispatcher) resetSkips(ws int64) {
	tickSkipsMu.Lock()
	defer tickSkipsMu.Unlock()
	delete(tickSkips, tickSkipKey{d.Store, ws})
}

// upkeep is the part of a tick that writes findings and plans messages.
func (d *Dispatcher) upkeep(ctx context.Context) error {
	if _, err := d.Store.ExpireSuppressions(ctx); err != nil {
		return fmt.Errorf("expire suppressions: %w", err)
	}
	// Ignore rules for every asset also cover issues found since.
	if _, err := d.Store.ApplyExceptions(ctx); err != nil {
		return fmt.Errorf("ignore rules: %w", err)
	}
	// Ignore rules made from VEX statements end once the component version
	// or image they were made for is gone.
	if _, err := d.Store.EndStaleVEXRules(ctx); err != nil {
		return fmt.Errorf("vex rules: %w", err)
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
	return nil
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
	routes, err := d.routes(ctx)
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
		return r.Enabled && !tracker[r.ChannelID] && sendsUrgent(r)
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
		if r.HasEvent(store.EventRegressed) && assetsWanted(r) {
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
		// One message per destination: events may go to other channels
		// than the route's (Route.EventChannels).
		type part struct {
			incs []store.Incident
			ids  []int64
			back []store.IssueCount
		}
		parts := map[int64]*part{}
		var order []int64
		get := func(ch int64) *part {
			if parts[ch] == nil {
				parts[ch] = &part{}
				order = append(order, ch)
			}
			return parts[ch]
		}
		for i, in := range urgent {
			ch := findingsChannel(r)
			if !isFindingKind(in.Kind) {
				ch = r.ChannelFor(store.EventProblems)
			}
			p := get(ch)
			p.incs, p.ids = append(p.incs, in), append(p.ids, urgentIDs[i])
		}
		if len(back) > 0 {
			get(r.ChannelFor(store.EventRegressed)).back = back
		}
		for _, ch := range order {
			p := parts[ch]
			msg, ok := d.urgentMessage(r, p.incs, rows, quiet, infos, p.back)
			if !ok {
				continue
			}
			key := keyOf("urgent", r.ID, p.ids)
			if len(p.back) > 0 {
				key += ":regressed:" + regressedUpTo.UTC().Format(time.RFC3339Nano)
			}
			if err := d.enqueueTo(ctx, r, ch, EventUrgent, key, msg); err != nil {
				return err
			}
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
			if !people(r) || !assetsWanted(r) || !r.HasEvent(store.EventConnected) {
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
			if err := d.enqueueTo(ctx, r, r.ChannelFor(store.EventConnected), EventConnected, keyOf("connected", r.ID, mineIDs), msg); err != nil {
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
	// announced one by one, except a stale feed's in the operators'
	// workspace (feedStalls); Jira issues are resolved by planIssueUpdates.
	resolved, err := d.Store.ResolvedToAnnounce(ctx)
	if err != nil {
		return err
	}
	if err := d.feedStalls(ctx, announce, resolved, routes, people); err != nil {
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
	// Jira routes limited to a project: after the incidents above were
	// marked announced, so their announcement counts (jira_projects.go).
	if err := d.planProjectIssues(ctx, routes, tracker); err != nil {
		return err
	}
	if err := d.planProjectIssueUpdates(ctx, routes, tracker); err != nil {
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
		if pid, ok := projectTracker(r, tracker); ok {
			if err := d.planProjectEscalations(ctx, r, pid, esc); err != nil {
				return err
			}
			continue
		}
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
		if !r.HasEvent(store.EventOverdue) {
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
		if err := d.enqueueTo(ctx, r, r.ChannelFor(store.EventOverdue), EventOverdue, key, msg); err != nil {
			return err
		}
	}
	return nil
}

// routes lists the workspace's routes for planning. An event sent to
// another channel (event_channels) goes to the route's own channel instead
// while that channel is missing or disabled, so a deleted or switched-off
// channel never stops the route.
func (d *Dispatcher) routes(ctx context.Context) ([]store.Route, error) {
	routes, err := d.Store.ListRoutes(ctx)
	if err != nil {
		return nil, err
	}
	chs, err := d.Store.ListChannels(ctx)
	if err != nil {
		return nil, err
	}
	usable := map[int64]bool{}
	for _, c := range chs {
		usable[c.ID] = c.Enabled && c.Kind != KindJira
	}
	for i := range routes {
		for e, id := range routes[i].EventChannels {
			if !usable[id] {
				delete(routes[i].EventChannels, e)
			}
		}
	}
	return routes, nil
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
	// route limited to projects never creates or updates them: it keeps
	// issues of its own about its project's part (jira_projects.go).
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
		if in.Kind == "feed" {
			m.Title = "Intelligence feed " + in.Key + " has recovered"
			m.Summary = []string{"The feed has synced again and its data is within its freshness limit"}
		}
		m.Action = ""
	}
	return m
}

// feedStalls tells the operators when an intelligence feed passes its stale
// limit and when it recovers, once each. Every workspace gets a feed
// incident while a feed is stale (store.DetectSystemProblems), announced
// like any problem; in the operators' workspace the server also logs both
// changes, and the routes the stale feed was sent to right away are told
// when it syncs again. announce and resolved are this cycle's incidents to
// announce and resolved incidents not yet announced as such.
func (d *Dispatcher) feedStalls(ctx context.Context, announce, resolved []store.Incident, routes []store.Route, people func(store.Route) bool) error {
	here, err := d.platformHere(ctx)
	if err != nil || !here {
		return err
	}
	for _, in := range announce {
		if in.Kind == "feed" && in.NotifiedPriority == "" && d.Log != nil {
			var det map[string]any
			_ = json.Unmarshal(in.Detail, &det)
			d.Log.Warn("intelligence feed is stale", "feed", in.Key, "last_success", det["last_success"], "last_error", det["last_error"])
		}
	}
	for _, in := range resolved {
		if in.Kind != "feed" {
			continue
		}
		if d.Log != nil {
			d.Log.Info("intelligence feed recovered", "feed", in.Key)
		}
		for _, r := range routes {
			if !people(r) || !urgentIncident(r, in) {
				continue
			}
			key := fmt.Sprintf("incident:%d:resolved:%d", in.ID, r.ID)
			if err := d.enqueueTo(ctx, r, r.ChannelFor(store.EventProblems), "resolved", key, d.message(in, "resolved")); err != nil {
				return err
			}
		}
	}
	return nil
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
			if route.MaxPerHour > 0 && del.Event != EventSummary && del.Event != EventDigest {
				sent, err := d.Store.RouteSentSince(ctx, route.ID, d.now().Add(-time.Hour))
				if err != nil {
					return err
				}
				if sent >= route.MaxPerHour {
					why := "hourly limit reached; counted in the next summary"
					if !sendsSummary(*route) {
						why = "hourly limit reached; sent in the next hourly digest"
					}
					if err := d.Store.HoldDelivery(ctx, del.ID, why); err != nil {
						return err
					}
					continue
				}
			}
		}
		// Email sent by Stackurity counts against the organisation's email
		// limits; over them, the message is held or waits.
		var reservation int64
		if ch.Kind == KindStackurityEmail && del.Event != "test" {
			res, ok, err := d.quotaCheck(ctx, ch, del, route)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			reservation = res
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
			_ = d.Store.ReleaseEmails(context.WithoutCancel(ctx), reservation)
			continue
		}
		sendErr := d.send(ctx, ch, del, attempts, msg)
		// Record what happened even if shutdown began during the send, so a
		// sent message is not sent again when the lease ends.
		bg := context.WithoutCancel(ctx)
		if sendErr != nil {
			_ = d.Store.ReleaseEmails(bg, reservation)
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
	if ch.Kind == KindStackurityEmail {
		return d.sendPlatformEmail(ctx, ch, msg)
	}
	var cfg ChannelConfig
	if err := json.Unmarshal(ch.Config, &cfg); err != nil {
		return err
	}
	secret, err := d.Secrets.Resolve(ctx, ch.SecretRef)
	if err != nil {
		return err
	}
	if ch.Kind == KindSlack && cfg.SlackApp && d.SlackApp != nil && d.SlackApp.SigningSecret != "" {
		// Added with the Stackurity Slack app: its signing secret verifies
		// clicks (internal/api/slack.go).
		cfg.interactive = ch.ID
	} else if ch.Kind == KindSlack && cfg.SigningSecretRef != "" {
		// Interactive buttons only when clicks can be verified: with a
		// signing secret that resolves. Otherwise the message keeps the URL
		// buttons, which always work.
		if sig, err := d.Secrets.Resolve(ctx, cfg.SigningSecretRef); err == nil && sig != "" {
			cfg.interactive = ch.ID
		} else {
			d.Log.Warn("slack signing secret cannot be read; sending link buttons", "channel", ch.Name)
		}
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
	var reservation int64
	if ch.Kind == KindStackurityEmail {
		to, err := d.recipients(ctx, ch)
		if err != nil {
			return err
		}
		if reservation, err = d.Store.ReserveEmails(ctx, max(len(to), 1), d.EmailLimits()); err != nil {
			return err
		}
	}
	err := d.send(ctx, ch, store.Delivery{Event: "test"}, 1, msg)
	if err != nil {
		_ = d.Store.ReleaseEmails(context.WithoutCancel(ctx), reservation)
	}
	_ = d.Store.ChannelResult(ctx, ch.ID, err)
	return err
}

// Digest runs hourly. Messages a route's hourly limit held are taken in
// by that route's next summary, never sent one by one; this plans the
// summaries that are due (as every Tick does), sends one digest per route
// that has no summary (urgent only) and, for held messages whose route was
// deleted, one digest per channel.
func (d *Dispatcher) Digest(ctx context.Context) error {
	routes, err := d.routes(ctx)
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
	if err := d.digestRoutes(ctx, routes, held, stamp); err != nil {
		return err
	}
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
		msg := Message{Event: EventDigest, Title: fmt.Sprintf("Stackurity: %s held by an hourly limit", plural(len(ids), "notification")),
			Summary: lines, At: d.now().UTC(), Link: d.url("/settings/notifications", url.Values{"tab": {"deliveries"}})}
		if _, err := d.Store.EnqueueDelivery(ctx, chID, nil, nil, EventDigest, key, msg); err != nil {
			return err
		}
		if err := d.Store.MarkDigested(ctx, ids, key); err != nil {
			return err
		}
	}
	return d.Deliver(ctx)
}

// digestRoutes sends, for each route without a summary (urgent only), one
// message listing the urgent messages its hourly limit held, which a
// summary would otherwise take in. It goes to the route, so its quiet hours
// apply; the hourly limit does not.
func (d *Dispatcher) digestRoutes(ctx context.Context, routes []store.Route, held map[int64][]store.Delivery, stamp string) error {
	byRoute := map[int64][]store.Delivery{}
	for _, list := range held {
		for _, del := range list {
			if del.RouteID != nil {
				byRoute[*del.RouteID] = append(byRoute[*del.RouteID], del)
			}
		}
	}
	for _, r := range routes {
		list := byRoute[r.ID]
		if len(list) == 0 || sendsSummary(r) || !r.Enabled {
			continue
		}
		var lines []string
		var ids []int64
		byQuota := 0
		for _, del := range list {
			if !routeChannel(r, del.ChannelID) {
				continue // queued before the route moved to another channel
			}
			var m Message
			_ = json.Unmarshal(del.Payload, &m)
			lines = append(lines, m.Subject())
			ids = append(ids, del.ID)
			if del.HeldBy == store.HeldEmailQuota {
				byQuota++
			}
		}
		limit := "the hourly limit"
		switch {
		case byQuota == len(ids) && byQuota > 0:
			limit = "the email limit"
		case byQuota > 0:
			limit = "the hourly and email limits"
		}
		if len(ids) == 0 {
			continue
		}
		if len(lines) > 20 {
			lines = append(lines[:20], fmt.Sprintf("+%d more", len(lines)-20))
		}
		key := fmt.Sprintf("digest:%d:%s", r.ID, stamp)
		msg := Message{Event: EventDigest, Title: fmt.Sprintf("Stackurity: %s held by %s", plural(len(ids), "urgent message"), limit),
			Route: r.Name, Summary: lines, At: d.now().UTC(),
			Link: inProject(d.url("/settings/notifications", url.Values{"tab": {"deliveries"}}), routeProject(r, 0))}
		if err := d.enqueueRouted(ctx, r, EventDigest, key, msg); err != nil {
			return err
		}
		if err := d.Store.MarkDigested(ctx, ids, key); err != nil {
			return err
		}
	}
	return nil
}

// routeChannel reports whether the route sends anything to channel id.
func routeChannel(r store.Route, id int64) bool {
	if id == r.ChannelID {
		return true
	}
	for _, c := range r.EventChannels {
		if c == id {
			return true
		}
	}
	return false
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

// SendEmail sends m to one address through an email channel's SMTP
// server, now. Invitations use it: the organisation's first enabled email
// channel is its mail server.
func (d *Dispatcher) SendEmail(ctx context.Context, ch *store.Channel, to string, m Message) error {
	if ch.Kind != KindEmail {
		return errors.New("not an email channel")
	}
	var cfg ChannelConfig
	if err := json.Unmarshal(ch.Config, &cfg); err != nil {
		return err
	}
	cfg.To = []string{to}
	secret, err := d.Secrets.Resolve(ctx, ch.SecretRef)
	if err != nil {
		return err
	}
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return d.Sender.Send(sctx, KindEmail, cfg, secret, 0, m)
}
