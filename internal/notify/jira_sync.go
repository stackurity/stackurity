package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// issueClaimLease is how long one attempt may take to create an issue before
// another attempt may try (after searching for it first).
const issueClaimLease = 3 * time.Minute

// jiraTimeout bounds one Jira delivery, which takes several requests.
const jiraTimeout = 90 * time.Second

// jiraAffectedLimit bounds the affected assets listed in an issue.
const jiraAffectedLimit = 20

func (d *Dispatcher) jiraClient(ctx context.Context, ch *store.Channel) (*jiraClient, ChannelConfig, error) {
	var cfg ChannelConfig
	if err := json.Unmarshal(ch.Config, &cfg); err != nil {
		return nil, cfg, err
	}
	secret, err := d.Secrets.Resolve(ctx, ch.SecretRef)
	if err != nil {
		return nil, cfg, err
	}
	j, err := d.Sender.jira(cfg, secret)
	return j, cfg, err
}

// checkJira verifies a Jira channel's credentials and project access.
func (d *Dispatcher) checkJira(ctx context.Context, ch *store.Channel) error {
	j, _, err := d.jiraClient(ctx, ch)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, jiraTimeout)
	defer cancel()
	return j.Check(ctx)
}

// syncJira brings the incident's issue in a Jira channel up to date for one
// delivery: it creates the issue if there is none, otherwise comments on what
// changed, and on resolution comments and transitions it. Messages without an
// incident (digests, bursts) do not become issues.
func (d *Dispatcher) syncJira(ctx context.Context, ch *store.Channel, del store.Delivery, attempts int, msg Message) error {
	if del.IncidentID == nil {
		return nil
	}
	if msg.ProjectID != 0 {
		return d.syncProjectJira(ctx, ch, del, attempts, msg)
	}
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return errors.New("jira delivery outside a workspace")
	}
	j, cfg, err := d.jiraClient(ctx, ch)
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
	if link == nil {
		if in.Status != "open" {
			return nil // resolved before an issue was made: nothing to track
		}
		if link, err = d.createJiraIssue(ctx, j, cfg, ch, ws, in); err != nil {
			return err
		}
		if link == nil {
			// Just created: the description covers the incident as it is,
			// but not what this event adds (an escalation's note), so the
			// update below still runs. Several events for a new incident
			// race to create its issue, and any of them can win.
			if link, err = d.Store.IssueLinkFor(ctx, ch.ID, in.ID); err != nil {
				return err
			}
		}
	}
	return d.updateJiraIssue(ctx, j, cfg, link, in, del, attempts, msg)
}

// createJiraIssue creates the incident's issue, or finds the one an earlier
// attempt created, and records it. It returns the link to update when the
// issue already existed, and nil when it has just been created (recorded as
// in sync with the incident as it is).
func (d *Dispatcher) createJiraIssue(ctx context.Context, j *jiraClient, cfg ChannelConfig, ch *store.Channel, ws int64, in *store.Incident) (*store.IssueLink, error) {
	existing, err := d.Store.ClaimIssueCreation(ctx, ch.ID, in.ID, issueClaimLease)
	if err != nil || existing != nil {
		return existing, err
	}
	release := func() { _ = d.Store.ReleaseIssueClaim(context.WithoutCancel(ctx), ch.ID, in.ID) }
	label := IncidentLabel(ws, in.ID)
	key, err := j.findIssue(ctx, label)
	if err != nil {
		release()
		return nil, err
	}
	if key == "" {
		brief, err := d.Store.IncidentBrief(ctx, in.ID, jiraAffectedLimit)
		if err != nil {
			release()
			return nil, err
		}
		labels := append(append([]string{}, cfg.Labels...), "stackurity", label)
		key, err = j.createIssue(ctx, issueSummary(*in), d.issueDescription(*in, brief), labels, cfg.Priorities[in.Priority])
		if err != nil {
			release()
			return nil, err
		}
	}
	// Record even if shutdown began, so the issue is not searched for again.
	if err := d.Store.RecordIssue(context.WithoutCancel(ctx), ch.ID, in.ID, key, j.base+"/browse/"+key, in.Priority, in.FindingCount, in.AssetCount); err != nil {
		return nil, err
	}
	return nil, nil
}

func (d *Dispatcher) updateJiraIssue(ctx context.Context, j *jiraClient, cfg ChannelConfig, link *store.IssueLink, in *store.Incident,
	del store.Delivery, attempts int, msg Message) error {
	bg := context.WithoutCancel(ctx)
	marker := fmt.Sprintf("Stackurity delivery %d", del.ID)
	// A retried delivery (attempt 2 or later) may have commented already.
	post := func(doc jiraDoc) error {
		if attempts > 1 {
			if done, err := j.hasComment(ctx, link.IssueKey, marker); err != nil || done {
				return err
			}
		}
		return j.comment(ctx, link.IssueKey, append(doc, jiraBlock{Para: d.footer(in.ID, marker)}))
	}
	if in.Status != "open" {
		if link.ResolvedSynced {
			return nil
		}
		if err := post(jiraDoc{{Para: plain("Resolved in Stackurity: no open findings remain for this incident.")}}); err != nil {
			return err
		}
		if cfg.ResolveTransition != "" {
			if err := j.transition(ctx, link.IssueKey, cfg.ResolveTransition); err != nil {
				return err
			}
		}
		return d.Store.IssueSynced(bg, link.ID, link.SyncedPriority, link.SyncedFindings, link.SyncedAssets, true)
	}
	var lines []string
	if del.Event == "escalated" && len(msg.Summary) > 0 {
		lines = append(lines, "Escalated: "+msg.Summary[0]+".")
	}
	lines = append(lines, issueChanges(link, in)...)
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
	// Also when nothing changed: the dedupe key of the next update moves on.
	return d.Store.IssueSynced(bg, link.ID, in.Priority, in.FindingCount, in.AssetCount, false)
}

// issueChanges describes how the incident differs from what its issue says.
func issueChanges(link *store.IssueLink, in *store.Incident) []string {
	var out []string
	if link.SyncedPriority != "" && in.Priority != link.SyncedPriority {
		verb := "lowered"
		if in.Priority < link.SyncedPriority {
			verb = "raised"
		}
		out = append(out, fmt.Sprintf("Priority %s from %s to %s.", verb, link.SyncedPriority, in.Priority))
	}
	if in.FindingCount != link.SyncedFindings || in.AssetCount != link.SyncedAssets {
		now := fmt.Sprintf("now %s on %s", plural(in.FindingCount, "finding"), plural(in.AssetCount, "asset"))
		switch diff := in.FindingCount - link.SyncedFindings; {
		case diff > 0:
			out = append(out, fmt.Sprintf("%s joined this incident (%s).", plural(diff, "new finding"), now))
		case diff < 0:
			out = append(out, fmt.Sprintf("%s no longer open: fixed, suppressed or accepted (%s).", plural(-diff, "finding"), now))
		default:
			out = append(out, fmt.Sprintf("The affected assets changed (%s).", now))
		}
	}
	return out
}

func (d *Dispatcher) incidentURL(id int64) string {
	if d.BaseURL == "" {
		return ""
	}
	return strings.TrimSuffix(d.BaseURL, "/") + fmt.Sprintf("/incidents/%d", id)
}

// issueScope is what an issue describes: the whole incident (zero), or
// one project's part of it, for a Jira route limited to that project.
type issueScope struct {
	ProjectID int64
	Project   string // its name
}

// in opens a dashboard link in the scope's project.
func (sc issueScope) in(link string) string { return inProject(link, sc.ProjectID) }

func (d *Dispatcher) footer(incidentID int64, marker string) []jiraInline {
	return d.footerIn(incidentID, marker, issueScope{})
}

func (d *Dispatcher) footerIn(incidentID int64, marker string, sc issueScope) []jiraInline {
	if u := sc.in(d.incidentURL(incidentID)); u != "" {
		return []jiraInline{{Text: "Open in Stackurity", Href: u}, {Text: " (" + marker + ")"}}
	}
	return plain("(" + marker + ")")
}

// issueSummary is the issue title, e.g. "[P1] CVE-2024-1234 in openssl on 5
// assets".
func issueSummary(in store.Incident) string {
	var det struct {
		Components []string `json:"components"`
	}
	_ = json.Unmarshal(in.Detail, &det)
	s := fmt.Sprintf("[%s] %s", in.Priority, in.Title)
	switch in.Kind {
	case "vulnerability":
		s = fmt.Sprintf("[%s] %s", in.Priority, in.Key)
		if len(det.Components) > 0 {
			s += " in " + strings.Join(firstN(det.Components, 2), ", ")
			if len(det.Components) > 2 {
				s += fmt.Sprintf(" and %d more", len(det.Components)-2)
			}
		}
		s += " on " + plural(in.AssetCount, "asset")
	case "end_of_life":
		s += " on " + plural(in.AssetCount, "asset")
	}
	return clip(s, jiraMaxSummary)
}

// issueDescription explains the incident: priority and why, what is
// affected, and how to fix it. Lists are bounded; the full detail is linked.
func (d *Dispatcher) issueDescription(in store.Incident, brief *store.IncidentBrief) jiraDoc {
	return d.issueDescriptionIn(in, brief, issueScope{})
}

// issueDescriptionIn is issueDescription for a scope. For a project, in
// and brief must have been read with a connection narrowed to it, so they
// hold only its findings and assets; the text then says so, leaves out the
// owner team (which may come from another project's asset) and opens every
// link in the project.
func (d *Dispatcher) issueDescriptionIn(in store.Incident, brief *store.IncidentBrief, sc issueScope) jiraDoc {
	m := d.message(in, "opened")
	var det struct {
		Severity       string   `json:"severity"`
		KnownExploited bool     `json:"known_exploited"`
		Environments   []string `json:"environments"`
		Components     []string `json:"components"`
		FixedVersions  []string `json:"fixed_versions"`
	}
	_ = json.Unmarshal(in.Detail, &det)
	intro := []jiraInline{{Text: fmt.Sprintf("Stackurity opened this issue for incident #%d (%s) and keeps it updated: findings that join or leave and priority changes are added as comments, and it is commented on when the incident resolves. ", in.ID, in.Title)}}
	if sc.ProjectID != 0 {
		intro = []jiraInline{{Text: fmt.Sprintf("Stackurity opened this issue for incident #%d (%s) in project %s. It describes only the project's assets, and is kept updated: findings that join or leave and priority changes are added as comments, and it is commented on when none of the project's findings remain open. ", in.ID, in.Title, sc.Project)}}
	}
	if u := sc.in(d.incidentURL(in.ID)); u != "" {
		intro = append(intro, jiraInline{Text: "Open the incident in Stackurity", Href: u})
	}
	doc := jiraDoc{{Para: intro}, {Heading: "Risk"}}
	pri := "Priority: " + in.Priority
	if in.SOS {
		pri += " (SOS"
		if brief.SOSRule != "" {
			pri += ": " + brief.SOSRule
		}
		pri += ")"
	}
	facts := [][]jiraInline{plain(pri)}
	vuln := in.Kind == "vulnerability" || in.Kind == "end_of_life"
	if vuln {
		if det.Severity != "" {
			facts = append(facts, plain("Severity: "+det.Severity))
		}
		if det.KnownExploited {
			facts = append(facts, plain("Known exploited in the wild (listed in CISA KEV)"))
		} else {
			facts = append(facts, plain("Not listed as known exploited (CISA KEV)"))
		}
		scope := fmt.Sprintf("Scope: %s on %s", plural(in.FindingCount, "finding"), plural(in.AssetCount, "asset"))
		if sc.ProjectID != 0 {
			scope += " in project " + sc.Project
		}
		facts = append(facts, plain(scope))
		if len(det.Environments) > 0 {
			facts = append(facts, plain("Environments: "+strings.Join(firstN(det.Environments, 10), ", ")))
		}
		if in.OwnerTeam != "" && sc.ProjectID == 0 {
			facts = append(facts, plain("Owner team: "+in.OwnerTeam))
		}
	} else {
		for _, l := range m.Summary {
			facts = append(facts, plain(l))
		}
	}
	doc = append(doc, jiraBlock{List: facts})
	if len(brief.Factors) > 0 {
		var fs [][]jiraInline
		for _, f := range firstN(brief.Factors, 12) {
			fs = append(fs, plain(fmt.Sprintf("%s (%+.1f): %s", f.Name, f.Points, f.Detail)))
		}
		doc = append(doc, jiraBlock{Heading: "Why this priority"}, jiraBlock{Para: plain("Risk factors of the most urgent finding:")}, jiraBlock{List: fs})
	}
	if len(brief.Affected) > 0 {
		var as [][]jiraInline
		for _, a := range brief.Affected {
			where := []string{}
			if a.Environment != "" {
				where = append(where, a.Environment)
			}
			if a.Exposed != nil && *a.Exposed {
				where = append(where, "internet exposed")
			}
			line := a.Asset
			if len(where) > 0 {
				line += " (" + strings.Join(where, ", ") + ")"
			}
			line += ": " + a.Component + " " + a.Version
			if a.FixedVersion != "" {
				line += ", fixed in " + a.FixedVersion
			}
			as = append(as, plain(line))
		}
		if more := in.FindingCount - len(brief.Affected); more > 0 {
			item := plain(fmt.Sprintf("…and %s more", plural(more, "finding")))
			if u := sc.in(d.incidentURL(in.ID)); u != "" {
				item = append(item, jiraInline{Text: ": "}, jiraInline{Text: "see all in Stackurity", Href: u})
			}
			as = append(as, item)
		}
		doc = append(doc, jiraBlock{Heading: "Affected assets"}, jiraBlock{List: as})
	}
	if m.Action != "" {
		fix := plain(m.Action + ".")
		if d.BaseURL != "" && vuln {
			fix = append(fix, jiraInline{Text: " "}, jiraInline{Text: "See the fixes", Href: sc.in(strings.TrimSuffix(d.BaseURL, "/") + "/fixes")})
		}
		doc = append(doc, jiraBlock{Heading: "Fix"}, jiraBlock{Para: fix})
	}
	return doc
}
