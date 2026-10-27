package notify

import (
	"context"
	"errors"
	"fmt"

	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Jira routes limited to a project.
//
// A Jira issue for a whole incident names every asset it touches, so a
// route limited to a project keeps its own issue per incident instead,
// describing only the project's part: its findings, assets, counts,
// priority, escalations and links. Such a route names exactly one project.
//
// Isolation does not rest on filtering in Go. Everything the issue says is
// read with a connection narrowed to the project (tenant.WithProject, the
// stackurity.project setting), the same narrowing the project switcher
// uses, so row-level security returns only the project's findings and
// assets and the store recomputes the incident from them
// (store.narrowIncidents). Deliveries carry only the incident id and the
// project; the text is built when the issue is created or updated.
//
// The issues are kept in route_issues, keyed by route, project, channel and
// incident, with workspace-wide connections (the table is hidden from
// narrowed ones, like incident_issues). Their label adds the route and
// project to the incident's, so a whole-incident issue and a project's
// issue in the same Jira project never find each other.

// ProjectIssueLabel is the label on the issue a route limited to a project
// keeps for an incident.
func ProjectIssueLabel(ws, incidentID, routeID, projectID int64) string {
	return fmt.Sprintf("%s-route-%d-project-%d", IncidentLabel(ws, incidentID), routeID, projectID)
}

// projectTracker reports whether r is a Jira route limited to a project,
// and which.
func projectTracker(r store.Route, tracker map[int64]bool) (int64, bool) {
	if !tracker[r.ChannelID] || len(r.ProjectIDs) != 1 {
		return 0, false
	}
	return r.ProjectIDs[0], true
}

// partMatches applies the route's filters to the project's part of an
// incident, given as counts read under the narrowed connection.
func partMatches(r store.Route, counts []store.IssueCount) bool {
	for _, c := range counts {
		if !c.Backlog && issueInScope(r, c) && risk.PriorityAtLeast(c.Priority, r.MinPriority) {
			return true
		}
	}
	return false
}

// matchingParts returns the incidents whose part, seen from nctx, matches r.
func (d *Dispatcher) matchingParts(nctx context.Context, r store.Route, ids []int64) ([]int64, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	counts, err := d.Store.IncidentIssues(nctx, ids)
	if err != nil {
		return nil, err
	}
	by := map[int64][]store.IssueCount{}
	for _, c := range counts {
		by[c.IncidentID] = append(by[c.IncidentID], c)
	}
	var out []int64
	for _, id := range ids {
		if partMatches(r, by[id]) {
			out = append(out, id)
		}
	}
	return out, nil
}

// planProjectIssues queues the creation of an issue for every incident
// whose part in a route's project matches the route and has no issue yet.
// An incident qualifies when it was announced, or one of the project's
// findings appeared or came back, after the route was created, so a new
// route does not open issues for every past incident.
func (d *Dispatcher) planProjectIssues(ctx context.Context, routes []store.Route, tracker map[int64]bool) error {
	for _, r := range routes {
		pid, ok := projectTracker(r, tracker)
		if !ok || !r.Enabled || r.Escalation {
			continue
		}
		if active, err := d.Store.ActiveProject(ctx, pid); err != nil || !active {
			if err != nil {
				return err
			}
			continue
		}
		nctx := tenant.WithProject(ctx, pid)
		cands, err := d.Store.ProjectIssueCandidates(nctx, r.CreatedAt, r.MinPriority, r.SOSOnly)
		if err != nil {
			return err
		}
		issued, err := d.Store.RouteIssued(ctx, r.ID, pid, r.ChannelID, cands)
		if err != nil {
			return err
		}
		var todo []int64
		for _, id := range cands {
			if !issued[id] {
				todo = append(todo, id)
			}
		}
		matched, err := d.matchingParts(nctx, r, todo)
		if err != nil {
			return err
		}
		for _, id := range matched {
			key := fmt.Sprintf("route:%d:project:%d:incident:%d:opened", r.ID, pid, id)
			if err := d.enqueueProjectIssue(ctx, r, pid, id, "opened", key, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *Dispatcher) enqueueProjectIssue(ctx context.Context, r store.Route, pid, incident int64, event, key string, level int) error {
	msg := Message{Event: event, IncidentID: incident, ProjectID: pid, Escalation: level, At: d.now().UTC()}
	_, err := d.Store.EnqueueDelivery(ctx, r.ChannelID, &r.ID, &incident, event, key, msg)
	return err
}

// planProjectEscalations queues an escalation comment, on routes with
// escalation, for each escalated incident whose project part matches.
func (d *Dispatcher) planProjectEscalations(ctx context.Context, r store.Route, pid int64, esc map[int64]int) error {
	if active, err := d.Store.ActiveProject(ctx, pid); err != nil || !active {
		return err
	}
	ids := make([]int64, 0, len(esc))
	for id := range esc {
		ids = append(ids, id)
	}
	matched, err := d.matchingParts(tenant.WithProject(ctx, pid), r, ids)
	if err != nil {
		return err
	}
	for _, id := range matched {
		key := fmt.Sprintf("route:%d:project:%d:incident:%d:escalated:%d", r.ID, pid, id, esc[id])
		if err := d.enqueueProjectIssue(ctx, r, pid, id, "escalated", key, esc[id]); err != nil {
			return err
		}
	}
	return nil
}

// planProjectIssueUpdates queues an update for every issue of a route
// limited to a project whose part changed (priority, findings, assets)
// since the issue was last told, a resolution when none of the project's
// findings remain open, and a note when they open again.
func (d *Dispatcher) planProjectIssueUpdates(ctx context.Context, routes []store.Route, tracker map[int64]bool) error {
	for _, r := range routes {
		pid, ok := projectTracker(r, tracker)
		if !ok {
			continue
		}
		if active, err := d.Store.ActiveProject(ctx, pid); err != nil || !active {
			if err != nil {
				return err
			}
			continue
		}
		links, err := d.Store.RouteIssues(ctx, r.ID, pid, r.ChannelID)
		if err != nil || len(links) == 0 {
			if err != nil {
				return err
			}
			continue
		}
		ids := make([]int64, len(links))
		for i, l := range links {
			ids[i] = l.IncidentID
		}
		seen, err := d.Store.IncidentsSeen(tenant.WithProject(ctx, pid), ids)
		if err != nil {
			return err
		}
		for _, l := range links {
			in, visible := seen[l.IncidentID]
			open := visible && partOpen(&in)
			stamp := l.UpdatedAt.UnixMicro()
			var event, key string
			switch {
			case !open && !l.ResolvedSynced:
				event, key = "resolved", fmt.Sprintf("route-issue:%d:resolved:%d", l.ID, stamp)
			case open && (l.ResolvedSynced || in.Priority != l.SyncedPriority || in.FindingCount != l.SyncedFindings || in.AssetCount != l.SyncedAssets):
				event, key = "updated", fmt.Sprintf("route-issue:%d:updated:%d", l.ID, stamp)
			default:
				continue
			}
			if err := d.enqueueProjectIssue(ctx, r, pid, l.IncidentID, event, key, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

// partOpen: the incident, as seen from a project, has open findings there.
func partOpen(in *store.Incident) bool {
	return in != nil && in.Status == "open" && in.FindingCount > 0
}

// syncProjectJira brings a route's project issue for an incident up to
// date for one delivery. The route is read again: a delivery queued before
// the route changed project or channel, or was deleted, is dropped.
func (d *Dispatcher) syncProjectJira(ctx context.Context, ch *store.Channel, del store.Delivery, attempts int, msg Message) error {
	if del.RouteID == nil || del.IncidentID == nil {
		return nil
	}
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return errors.New("jira delivery outside a workspace")
	}
	ctx = tenant.WithoutProject(ctx)
	r, err := d.Store.GetRoute(ctx, *del.RouteID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	pid := msg.ProjectID
	if len(r.ProjectIDs) != 1 || r.ProjectIDs[0] != pid || r.ChannelID != ch.ID {
		return nil
	}
	p, err := d.Store.GetProject(ctx, pid)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if p.ArchivedAt != nil {
		return nil
	}
	sc := issueScope{ProjectID: pid, Project: p.Name}
	j, cfg, err := d.jiraClient(ctx, ch)
	if err != nil {
		return err
	}
	// The project's part of the incident, read as the project sees it:
	// row-level security leaves out every other project's findings and
	// assets, and the store recomputes counts, names and priority.
	nctx := tenant.WithProject(ctx, pid)
	in, err := d.Store.GetIncident(nctx, *del.IncidentID)
	if errors.Is(err, store.ErrNotFound) {
		in, err = nil, nil
	}
	if err != nil {
		return err
	}
	k := store.RouteIssueKey{RouteID: r.ID, ProjectID: pid, ChannelID: ch.ID, IncidentID: *del.IncidentID}
	link, err := d.Store.RouteIssueFor(ctx, k)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if link == nil {
		if !partOpen(in) {
			return nil // the part closed before an issue was made
		}
		if link, err = d.createProjectIssue(ctx, nctx, j, cfg, k, ws, sc, in); err != nil || link == nil {
			return err
		}
	}
	return d.updateProjectIssue(ctx, j, cfg, link, sc, in, del, attempts, msg)
}

// createProjectIssue creates the route's issue for the project's part of
// the incident, or finds the one an earlier attempt created, and records
// it. It returns the link to update when the issue already existed.
func (d *Dispatcher) createProjectIssue(ctx, nctx context.Context, j *jiraClient, cfg ChannelConfig, k store.RouteIssueKey, ws int64,
	sc issueScope, in *store.Incident) (*store.RouteIssue, error) {
	existing, err := d.Store.ClaimRouteIssue(ctx, k, issueClaimLease)
	if err != nil || existing != nil {
		return existing, err
	}
	release := func() { _ = d.Store.ReleaseRouteIssue(context.WithoutCancel(ctx), k) }
	label := ProjectIssueLabel(ws, k.IncidentID, k.RouteID, k.ProjectID)
	key, err := j.findIssue(ctx, label)
	if err != nil {
		release()
		return nil, err
	}
	if key == "" {
		brief, err := d.Store.IncidentBrief(nctx, in.ID, jiraAffectedLimit)
		if err != nil {
			release()
			return nil, err
		}
		labels := append(append([]string{}, cfg.Labels...), "stackurity", label)
		summary := clip(issueSummary(*in)+" in "+sc.Project, jiraMaxSummary)
		key, err = j.createIssue(ctx, summary, d.issueDescriptionIn(*in, brief, sc), labels, cfg.Priorities[in.Priority])
		if err != nil {
			release()
			return nil, err
		}
	}
	if err := d.Store.RecordRouteIssue(context.WithoutCancel(ctx), k, key, j.base+"/browse/"+key, in.Priority, in.FindingCount, in.AssetCount); err != nil {
		return nil, err
	}
	return nil, nil
}

func (d *Dispatcher) updateProjectIssue(ctx context.Context, j *jiraClient, cfg ChannelConfig, link *store.RouteIssue, sc issueScope,
	in *store.Incident, del store.Delivery, attempts int, msg Message) error {
	bg := context.WithoutCancel(ctx)
	marker := fmt.Sprintf("Stackurity delivery %d", del.ID)
	post := func(doc jiraDoc) error {
		if attempts > 1 {
			if done, err := j.hasComment(ctx, link.IssueKey, marker); err != nil || done {
				return err
			}
		}
		return j.comment(ctx, link.IssueKey, append(doc, jiraBlock{Para: d.footerIn(link.IncidentID, marker, sc)}))
	}
	if !partOpen(in) {
		if link.ResolvedSynced {
			return nil
		}
		if err := post(jiraDoc{{Para: plain(fmt.Sprintf("Resolved in Stackurity: no open findings of this incident remain in project %s.", sc.Project))}}); err != nil {
			return err
		}
		if cfg.ResolveTransition != "" {
			if err := j.transition(ctx, link.IssueKey, cfg.ResolveTransition); err != nil {
				return err
			}
		}
		return d.Store.RouteIssueSynced(bg, link.ID, link.SyncedPriority, link.SyncedFindings, link.SyncedAssets, true)
	}
	var lines []string
	if link.ResolvedSynced {
		lines = append(lines, fmt.Sprintf("Open again in Stackurity: %s on %s in project %s.",
			plural(in.FindingCount, "finding"), plural(in.AssetCount, "asset"), sc.Project))
	} else {
		if del.Event == "escalated" {
			if msg.Escalation >= 2 {
				lines = append(lines, "Escalated: Remediation deadline has passed.")
			} else {
				lines = append(lines, "Escalated: Not acknowledged within the agreed time.")
			}
		}
		lines = append(lines, issueChanges(&link.IssueLink, in)...)
	}
	if len(lines) > 0 {
		var doc jiraDoc
		for _, l := range lines {
			doc = append(doc, jiraBlock{Para: plain(l)})
		}
		if err := post(doc); err != nil {
			return err
		}
		if p := cfg.Priorities[in.Priority]; p != "" && in.Priority != link.SyncedPriority {
			if err := j.setPriority(ctx, link.IssueKey, p); err != nil {
				return err
			}
		}
	}
	return d.Store.RouteIssueSynced(bg, link.ID, in.Priority, in.FindingCount, in.AssetCount, false)
}
