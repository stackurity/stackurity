package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// PagerDuty and ServiceNow channels: one record per incident, like Jira
// (jira_sync.go), kept in incident_issues. Routes to them choose which
// incidents get a record (priority, kinds, environments, teams); they get
// no grouped messages, and quiet hours and hourly limits do not apply.

// trackerTimeout bounds one PagerDuty or ServiceNow delivery.
const trackerTimeout = 90 * time.Second

// defaultTrackerPoll is how often a ServiceNow record's state is read back.
const defaultTrackerPoll = 5 * time.Minute

// trackerPollBatch bounds the records read back per channel and tick.
const trackerPollBatch = 100

func (d *Dispatcher) trackerConfig(ctx context.Context, ch *store.Channel) (ChannelConfig, string, error) {
	var cfg ChannelConfig
	if err := json.Unmarshal(ch.Config, &cfg); err != nil {
		return cfg, "", err
	}
	secret, err := d.Secrets.Resolve(ctx, ch.SecretRef)
	return cfg, secret, err
}

// syncTracker brings the incident's PagerDuty alert or ServiceNow record
// up to date for one delivery. Messages without an incident do not become
// records.
func (d *Dispatcher) syncTracker(ctx context.Context, ch *store.Channel, del store.Delivery, attempts int, msg Message) error {
	if del.IncidentID == nil {
		return nil
	}
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return fmt.Errorf("%s delivery outside a workspace", ch.Kind)
	}
	cfg, secret, err := d.trackerConfig(ctx, ch)
	if err != nil {
		return err
	}
	// Work from the incident as it is now, not as it was when queued.
	in, err := d.Store.GetIncident(ctx, *del.IncidentID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	link, err := d.Store.IssueLinkFor(ctx, ch.ID, in.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	switch ch.Kind {
	case KindPagerDuty:
		return d.syncPagerDuty(ctx, cfg, secret, ch, ws, in, link, del)
	case KindServiceNow:
		sn, err := d.Sender.serviceNow(cfg, secret)
		if err != nil {
			return err
		}
		return d.syncServiceNow(ctx, sn, ch, ws, in, link, del, attempts, msg)
	}
	return fmt.Errorf("not a tracker channel: %s", ch.Kind)
}

// acked reports whether an incident counts as acknowledged: none of its
// findings is new any more (acknowledged or in progress).
func acked(in *store.Incident) bool { return in.State != "" && in.State != "new" }

// --- PagerDuty

func (d *Dispatcher) pagerDutyTrigger(cfg ChannelConfig, secret, key string, in *store.Incident, event string) pagerDutyEvent {
	m := d.message(*in, event)
	var det struct {
		Components     []string `json:"components"`
		Environments   []string `json:"environments"`
		KnownExploited bool     `json:"known_exploited"`
		Severity       string   `json:"severity"`
	}
	_ = json.Unmarshal(in.Detail, &det)
	details := map[string]any{
		"incident_id": in.ID, "kind": in.Kind, "key": in.Key, "priority": in.Priority, "sos": in.SOS,
		"findings": in.FindingCount, "assets": in.AssetCount, "state": in.State, "event": event,
	}
	if len(det.Environments) > 0 {
		details["environments"] = firstN(det.Environments, 10)
	}
	if det.KnownExploited {
		details["known_exploited"] = true
	}
	if det.Severity != "" {
		details["severity"] = det.Severity
	}
	if m.Action != "" {
		details["recommended_action"] = m.Action
	}
	if len(m.Summary) > 0 {
		details["summary"] = firstN(m.Summary, 5)
	}
	if in.EscalationLevel > 0 {
		details["escalation_level"] = in.EscalationLevel
	}
	p := &pagerDutyPayload{
		Summary:       clip(issueSummary(*in), 1024),
		Source:        d.source(),
		Severity:      pagerDutySeverity(cfg, in.Priority, in.SOS),
		Group:         in.OwnerTeam,
		Class:         in.Kind,
		CustomDetails: details,
	}
	if len(det.Components) > 0 {
		p.Component = det.Components[0]
	}
	ev := pagerDutyEvent{RoutingKey: secret, EventAction: "trigger", DedupKey: key, Payload: p, Client: "Stackurity"}
	if u := d.incidentURL(in.ID); u != "" {
		ev.ClientURL = u
		ev.Links = []pagerDutyLink{{Href: u, Text: fmt.Sprintf("Incident #%d in Stackurity", in.ID)}}
	}
	return ev
}

// source names this Stackurity in PagerDuty: the dashboard's host.
func (d *Dispatcher) source() string {
	if u, err := url.Parse(d.BaseURL); err == nil && u.Host != "" {
		return u.Host
	}
	return "stackurity"
}

func (d *Dispatcher) syncPagerDuty(ctx context.Context, cfg ChannelConfig, secret string, ch *store.Channel, ws int64, in *store.Incident,
	link *store.IssueLink, del store.Delivery) error {
	bg := context.WithoutCancel(ctx)
	key := IncidentLabel(ws, in.ID)
	send := func(action string) error {
		if action == "trigger" {
			return d.Sender.pagerDuty(ctx, cfg, d.pagerDutyTrigger(cfg, secret, key, in, del.Event))
		}
		return d.Sender.pagerDuty(ctx, cfg, pagerDutyEvent{RoutingKey: secret, EventAction: action, DedupKey: key})
	}
	if link == nil {
		if in.Status != "open" {
			return nil // resolved before it was announced: nothing to page about
		}
		// The Events API deduplicates by key: a retry, or another replica
		// sending the same event, lands on the same alert.
		if err := send("trigger"); err != nil {
			return err
		}
		if acked(in) {
			if err := send("acknowledge"); err != nil {
				return err
			}
		}
		return d.Store.RecordTrackerIssue(bg, store.TrackerRecord{ChannelID: ch.ID, IncidentID: in.ID, Tracker: KindPagerDuty, Key: key,
			Priority: in.Priority, Findings: in.FindingCount, Assets: in.AssetCount, Acked: acked(in)})
	}
	if in.Status != "open" {
		if link.ResolvedSynced {
			return nil
		}
		if err := send("resolve"); err != nil {
			return err
		}
		return d.Store.IssueSynced(bg, link.ID, link.SyncedPriority, link.SyncedFindings, link.SyncedAssets, true)
	}
	// Trigger again only when it is worth paging about: the priority rose,
	// it escalated, or new findings arrived after it was acknowledged.
	// Findings that join or leave otherwise change nothing in PagerDuty.
	raised := link.SyncedPriority != "" && in.Priority < link.SyncedPriority
	if raised || del.Event == "escalated" || (link.SyncedAcked && !acked(in)) {
		if err := send("trigger"); err != nil {
			return err
		}
	}
	if acked(in) && !link.SyncedAcked {
		if err := send("acknowledge"); err != nil {
			return err
		}
	}
	if acked(in) != link.SyncedAcked {
		if err := d.Store.IssueAckSynced(bg, link.ID, acked(in)); err != nil {
			return err
		}
	}
	return d.Store.IssueSynced(bg, link.ID, in.Priority, in.FindingCount, in.AssetCount, false)
}

// --- ServiceNow

func (d *Dispatcher) syncServiceNow(ctx context.Context, sn *snClient, ch *store.Channel, ws int64, in *store.Incident,
	link *store.IssueLink, del store.Delivery, attempts int, msg Message) error {
	var created error
	if link == nil {
		if in.Status != "open" {
			return nil // resolved before a record was made: nothing to track
		}
		var err error
		if link, err = d.createServiceNow(ctx, sn, ch, ws, in); err != nil {
			var pe *PermanentError
			if link != nil || !errors.As(err, &pe) || !strings.Contains(err.Error(), "did not set") {
				return err
			}
			created = err // recorded, but fields were dropped: say so after the update
		}
		if link == nil {
			// Just created: the description covers the incident as it is,
			// but not what this event adds (an escalation's note).
			if link, err = d.Store.IssueLinkFor(ctx, ch.ID, in.ID); err != nil {
				return err
			}
		}
	}
	if err := d.updateServiceNow(ctx, sn, link, in, del, attempts, msg); err != nil {
		return err
	}
	return created
}

// createServiceNow creates the incident's record, or finds the one an
// earlier attempt created, and records it. It returns the link when the
// record already existed, and nil when it has just been created.
func (d *Dispatcher) createServiceNow(ctx context.Context, sn *snClient, ch *store.Channel, ws int64, in *store.Incident) (*store.IssueLink, error) {
	existing, err := d.Store.ClaimIssueCreation(ctx, ch.ID, in.ID, issueClaimLease)
	if err != nil || existing != nil {
		return existing, err
	}
	release := func() { _ = d.Store.ReleaseIssueClaim(context.WithoutCancel(ctx), ch.ID, in.ID) }
	label := IncidentLabel(ws, in.ID)
	rec, err := sn.find(ctx, label)
	if err != nil {
		release()
		return nil, err
	}
	var dropped []string
	if rec == nil {
		brief, err := d.Store.IncidentBrief(ctx, in.ID, jiraAffectedLimit)
		if err != nil {
			release()
			return nil, err
		}
		fields := map[string]any{}
		for k, v := range sn.cfg.Fields {
			fields[k] = v
		}
		fields["short_description"] = clip(issueSummary(*in), snMaxShort)
		fields["description"] = renderText(d.issueDescription(*in, brief))
		fields["urgency"] = sn.cfg.snUrgency(in.Priority)
		fields["impact"] = sn.cfg.snImpact(in.Priority)
		fields["correlation_id"] = label
		fields["correlation_display"] = "Stackurity"
		for k, v := range map[string]string{"assignment_group": sn.cfg.AssignmentGroup, "category": sn.cfg.Category, "subcategory": sn.cfg.Subcategory} {
			if v != "" {
				fields[k] = v
			}
		}
		if rec, err = sn.create(ctx, fields); err != nil {
			release()
			return nil, err
		}
		dropped = droppedFields(fields, rec)
	}
	sysID, number := rec.str("sys_id"), rec.str("number")
	if number == "" {
		number = sysID
	}
	// Record even if shutdown began, so the record is not searched for again.
	if err := d.Store.RecordTrackerIssue(context.WithoutCancel(ctx), store.TrackerRecord{ChannelID: ch.ID, IncidentID: in.ID,
		Tracker: KindServiceNow, Key: number, URL: sn.recordURL(sysID), RemoteID: sysID, Priority: in.Priority,
		Findings: in.FindingCount, Assets: in.AssetCount, Acked: acked(in)}); err != nil {
		return nil, err
	}
	if len(dropped) > 0 {
		return nil, &PermanentError{fmt.Errorf("ServiceNow created %s but did not set %s: the account may not write these fields (a field ACL), or table %s has no such field; later updates continue",
			number, strings.Join(dropped, ", "), sn.table)}
	}
	return nil, nil
}

func (d *Dispatcher) updateServiceNow(ctx context.Context, sn *snClient, link *store.IssueLink, in *store.Incident, del store.Delivery,
	attempts int, msg Message) error {
	bg := context.WithoutCancel(ctx)
	if link.RemoteState != "" {
		// Closed in ServiceNow: people decided there; it is not reopened
		// or written to. The incident page shows it.
		return d.Store.IssueSynced(bg, link.ID, in.Priority, in.FindingCount, in.AssetCount, in.Status != "open")
	}
	marker := fmt.Sprintf("Stackurity delivery %d", del.ID)
	footer := renderText(jiraDoc{{Para: d.footer(in.ID, marker)}})
	if in.Status != "open" {
		if link.ResolvedSynced {
			return nil
		}
		// Setting the same state again is harmless, so a retry needs no check.
		fields := map[string]any{
			"state":       sn.cfg.snResolveState(),
			"close_code":  sn.cfg.snCloseCode(),
			"close_notes": "Resolved in Stackurity: no open findings remain for this incident.\n\n" + footer,
		}
		if _, err := sn.update(ctx, link.RemoteID, fields); err != nil {
			return err
		}
		return d.Store.IssueSynced(bg, link.ID, link.SyncedPriority, link.SyncedFindings, link.SyncedAssets, true)
	}
	var lines []string
	if del.Event == "escalated" && len(msg.Summary) > 0 {
		lines = append(lines, "Escalated: "+msg.Summary[0]+".")
	}
	switch {
	case acked(in) && !link.SyncedAcked:
		lines = append(lines, "Acknowledged in Stackurity: every finding of this incident has been acknowledged or is in progress.")
	case !acked(in) && link.SyncedAcked:
		lines = append(lines, "New findings to look at: the incident is no longer acknowledged in Stackurity.")
	}
	lines = append(lines, issueChanges(link, in)...)
	if len(lines) > 0 {
		fields := map[string]any{}
		if in.Priority != link.SyncedPriority {
			fields["urgency"] = sn.cfg.snUrgency(in.Priority)
			fields["impact"] = sn.cfg.snImpact(in.Priority)
		}
		done := false
		if attempts > 1 {
			var err error
			if done, err = sn.hasNote(ctx, link.RemoteID, marker); err != nil {
				return err
			}
		}
		if !done {
			fields["work_notes"] = strings.Join(lines, "\n") + "\n\n" + footer
		}
		if len(fields) > 0 {
			if _, err := sn.update(ctx, link.RemoteID, fields); err != nil {
				return err
			}
		}
	}
	if acked(in) != link.SyncedAcked {
		if err := d.Store.IssueAckSynced(bg, link.ID, acked(in)); err != nil {
			return err
		}
	}
	// Also when nothing changed: the dedupe key of the next update moves on.
	return d.Store.IssueSynced(bg, link.ID, in.Priority, in.FindingCount, in.AssetCount, false)
}

// --- Send test

// checkTracker is Send test for PagerDuty and ServiceNow. ServiceNow:
// checks the credentials, read access to the table and the assignment
// group, creating nothing. PagerDuty has no way to check a routing key
// without an event: it triggers a test alert (severity info) and resolves
// it at once.
func (d *Dispatcher) checkTracker(ctx context.Context, ch *store.Channel) error {
	cfg, secret, err := d.trackerConfig(ctx, ch)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, trackerTimeout)
	defer cancel()
	switch ch.Kind {
	case KindServiceNow:
		sn, err := d.Sender.serviceNow(cfg, secret)
		if err != nil {
			return err
		}
		return sn.Check(ctx)
	case KindPagerDuty:
		ws, _ := tenant.Workspace(ctx)
		key := fmt.Sprintf("stackurity-test-%d-%d-%d", ws, ch.ID, d.now().Unix())
		ev := pagerDutyEvent{RoutingKey: secret, EventAction: "trigger", DedupKey: key, Client: "Stackurity", Payload: &pagerDutyPayload{
			Summary: "Stackurity test alert: this integration works (resolved at once)", Source: d.source(), Severity: "info", Class: "test",
		}}
		if u := d.BaseURL; u != "" {
			ev.ClientURL = u
		}
		if err := d.Sender.pagerDuty(ctx, cfg, ev); err != nil {
			return err
		}
		return d.Sender.pagerDuty(ctx, cfg, pagerDutyEvent{RoutingKey: secret, EventAction: "resolve", DedupKey: key})
	}
	return fmt.Errorf("not a tracker channel: %s", ch.Kind)
}

// --- reading ServiceNow back

// pollTrackers reads back the state of ServiceNow records of channels with
// sync_back. A record closed in ServiceNow (resolved, closed or canceled,
// or the configured closed_states) is marked so on the incident, recorded
// in the activity log, and no longer updated; one reopened there is
// updated again. Stackurity never closes findings because of it: only a
// scan shows they are fixed.
func (d *Dispatcher) pollTrackers(ctx context.Context) error {
	chs, err := d.Store.ListChannels(ctx)
	if err != nil {
		return err
	}
	every := d.TrackerPoll
	if every <= 0 {
		every = defaultTrackerPoll
	}
	for i := range chs {
		ch := &chs[i]
		if ch.Kind != KindServiceNow || !ch.Enabled {
			continue
		}
		var cfg ChannelConfig
		if json.Unmarshal(ch.Config, &cfg) != nil || !cfg.SyncBack {
			continue
		}
		if err := d.pollServiceNow(ctx, ch, cfg, every); err != nil {
			if d.Log != nil {
				d.Log.Warn("servicenow sync back failed", "channel", ch.Name, "err", err)
			}
			_ = d.Store.ChannelResult(context.WithoutCancel(ctx), ch.ID, fmt.Errorf("reading states back: %w", err))
		}
	}
	return nil
}

func (d *Dispatcher) pollServiceNow(ctx context.Context, ch *store.Channel, cfg ChannelConfig, every time.Duration) error {
	checks, err := d.Store.RemoteChecksDue(ctx, ch.ID, every, trackerPollBatch)
	if err != nil || len(checks) == 0 {
		return err
	}
	secret, err := d.Secrets.Resolve(ctx, ch.SecretRef)
	if err != nil {
		return err
	}
	sn, err := d.Sender.serviceNow(cfg, secret)
	if err != nil {
		return err
	}
	ids := make([]string, len(checks))
	for i, c := range checks {
		ids[i] = c.RemoteID
	}
	sctx, cancel := context.WithTimeout(ctx, trackerTimeout)
	defer cancel()
	states, err := sn.states(sctx, ids)
	if err != nil {
		return err
	}
	bg := context.WithoutCancel(ctx)
	actor := store.Actor{Type: "system", Name: "ServiceNow: " + ch.Name}
	for _, c := range checks {
		st, found := states[c.RemoteID]
		closed := c.RemoteState // missing (deleted or hidden): unchanged
		if found {
			closed = cfg.snClosedState(st)
		}
		if err := d.Store.SetRemoteState(bg, c.LinkID, closed); err != nil {
			return err
		}
		detail := map[string]any{"channel_id": ch.ID, "record": c.IssueKey, "state": st}
		switch {
		case closed != "" && c.RemoteState == "":
			_ = d.Store.Audit(bg, actor, "incident.tracker_closed", "incident", strconv.FormatInt(c.IncidentID, 10), detail)
		case closed == "" && c.RemoteState != "":
			_ = d.Store.Audit(bg, actor, "incident.tracker_reopened", "incident", strconv.FormatInt(c.IncidentID, 10), detail)
		}
	}
	return nil
}
