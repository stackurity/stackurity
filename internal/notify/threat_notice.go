package notify

// Threat notices (docs/threat-notices.md): one message per organisation and
// threat, built here so the email to administrators, the notification
// routes, the email checks and the previews (tools/emailpreview) all show
// the same thing. A notice names no asset: it gives counts and links to
// the findings, so the same text is safe for every route and for the
// operator's copy.

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/threats"
)

// Threat notice events.
const (
	// EventThreatNotice is a notice to an organisation: by email to its
	// administrators and security team, and through its notification
	// routes (route event store.EventThreatNotices).
	EventThreatNotice = "threat_notice"
	// EventThreatNoticeCopy is the operator's one summary per threat
	// (Stackurity Cloud, STACKURITY_THREAT_NOTICE_COPY_TO).
	EventThreatNoticeCopy = "threat_notice_copy"
)

// NoticeFacts is what a notice says about one organisation.
type NoticeFacts struct {
	Verdict   string
	Findings  int
	Assets    int
	Connected map[string]int
	// Outdated: assets per connection whose collector is older than the
	// check; Signals: findings only named like the threat.
	Outdated map[string]int
	Signals  int
	Missing  []threats.Need
	// Running is this server's release, for an upgrade notice.
	Running string
}

// absURL makes a dashboard path absolute with base; "" when there is no
// base (a self-hosted server without STACKURITY_BASE_URL): a relative
// link would not work in an email or a chat message.
func absURL(base, path string) string {
	if strings.HasPrefix(path, "https://") {
		return path
	}
	if base == "" {
		return ""
	}
	return strings.TrimRight(base, "/") + path
}

// ThreatFindingsPath is the dashboard page with a threat's findings.
func ThreatFindingsPath(t threats.Threat) string {
	if len(t.Detects.ConfigRules) > 0 {
		return "/fixes/config?category=attack_tool"
	}
	if len(t.Detects.CVEs) > 0 {
		return "/search?q=" + url.QueryEscape(t.Detects.CVEs[0])
	}
	return "/fixes/issues"
}

func plainCount(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// connectedText says what is checked: "3 servers with the agent, 2
// container images".
func connectedText(conn map[string]int) string {
	var parts []string
	for _, c := range threats.Connections {
		n := conn[c]
		if n == 0 {
			continue
		}
		switch c {
		case threats.ConnHostAgent:
			parts = append(parts, plainCount(n, "server with the agent", "servers with the agent"))
		case threats.ConnDocker:
			parts = append(parts, plainCount(n, "container image", "container images"))
		case threats.ConnRepository:
			parts = append(parts, plainCount(n, "repository", "repositories"))
		case threats.ConnCloudAccount:
			parts = append(parts, plainCount(n, "cloud service", "cloud services"))
		case threats.ConnKubernetes:
			parts = append(parts, plainCount(n, "Kubernetes cluster", "Kubernetes clusters"))
		}
	}
	return strings.Join(parts, ", ")
}

// ThreatNoticeMessage is an organisation's notice about t. base is the
// dashboard's address (links are left out without one).
func ThreatNoticeMessage(base string, t threats.Threat, f NoticeFacts, at time.Time) Message {
	m := Message{Event: EventThreatNotice, Kind: "threat", Key: "threat:" + t.ID, At: at,
		Detail: map[string]any{"threat": t.ID, "verdict": f.Verdict, "findings": f.Findings, "assets": f.Assets, "signals": f.Signals}}
	inTheWild := t.Name + " is being used against systems on the public internet."
	if t.Kind == threats.KindExploitedVuln {
		inTheWild = t.Name + " is being exploited against systems on the public internet."
	}
	switch f.Verdict {
	case threats.Found:
		m.Title = fmt.Sprintf("%s was found on %s", t.Name, plainCount(f.Assets, "of your assets", "of your assets"))
		found := fmt.Sprintf("Stackurity's checks found it on %s.", plainCount(f.Assets, "asset", "assets"))
		if f.Findings > 0 {
			found = fmt.Sprintf("Stackurity's checks found it: %s on %s.", plainCount(f.Findings, "finding", "findings"), plainCount(f.Assets, "asset", "assets"))
		}
		m.Summary = []string{inTheWild, found}
		m.Action = "Open the findings, find out who installed it and why, and remove it. If nobody in your organisation put it there, treat the asset as compromised."
		if t.Kind == threats.KindExploitedVuln {
			m.Action = "Open the findings and apply the fix on these assets first: this vulnerability is being exploited now."
		}
		m.Link, m.LinkLabel = absURL(base, ThreatFindingsPath(t)), "See findings"
	case threats.Covered:
		m.Title = fmt.Sprintf("%s: your connected assets are checked, nothing was found", t.Name)
		m.Summary = []string{inTheWild,
			"Your connected assets are checked for it (" + connectedText(f.Connected) + ") and nothing was found. You don't need to do anything."}
		if len(f.Missing) > 0 {
			var more []string
			for _, n := range f.Missing {
				more = append(more, threats.ConnectionLabel(n.Connection))
			}
			m.Summary = append(m.Summary, "To check more of your estate for it, also connect "+strings.Join(more, " and ")+".")
		}
		m.Link, m.LinkLabel = absURL(base, "/help/threat-notices"), "About threat notices"
	case threats.NeedsConnection:
		m.Title = fmt.Sprintf("%s: Stackurity can check for it, but needs %s", t.Name, threats.ConnectionLabel(firstMissing(f.Missing)))
		m.Summary = []string{inTheWild, "We can check for it, but need this from you:"}
		for _, n := range f.Missing {
			line := "Connect " + threats.ConnectionLabel(n.Connection) + ". What it checks: " + n.Checks + "."
			if o := f.Outdated[n.Connection]; o > 0 {
				line = fmt.Sprintf("Update %s: %s connected but last checked by a release older than %s, the first with this check. What it checks: %s.",
					threats.ConnectionLabel(n.Connection), plainCount(o, "asset is", "assets are"), t.MinVersion, n.Checks)
			}
			if l := absURL(base, n.Help); l != "" {
				line += " How to connect: " + l
			}
			m.Summary = append(m.Summary, line)
		}
		if c := connectedText(f.Connected); c != "" {
			m.Summary = append(m.Summary, "Already checked, nothing found: "+c+".")
		}
		if len(f.Missing) > 0 {
			m.Link, m.LinkLabel = absURL(base, f.Missing[0].Help), "Connect"
			if first := firstMissing(f.Missing); f.Outdated[first] > 0 {
				m.Title = fmt.Sprintf("%s: Stackurity can check for it, once %s is updated", t.Name, threats.ConnectionLabel(first))
				if f.Outdated[f.Missing[0].Connection] > 0 {
					m.LinkLabel = "Update"
				}
			}
		}
	case threats.Upgrade:
		m.Title = fmt.Sprintf("%s: upgrade Stackurity to check for it", t.Name)
		running := f.Running
		if running == "" {
			running = "an older release"
		}
		m.Summary = []string{inTheWild,
			fmt.Sprintf("This Stackurity server runs %s. The check for %s is in Stackurity %s and later: upgrade to the latest version to check your assets for it.", running, t.Name, t.MinVersion)}
		m.Link, m.LinkLabel = absURL(base, "/help/backups-upgrades"), "How to upgrade"
	}
	if f.Signals > 0 && f.Verdict != threats.Found {
		m.Summary = append(m.Summary, fmt.Sprintf("%s only named like %s (a weaker sign, not counted as found): look at it under Risky settings to rule it out.",
			plainCount(f.Signals, "finding is", "findings are"), t.Name))
	}
	m.Summary = append(m.Summary, "About "+t.Name+": "+t.Summary)
	// Sources are linked only on hosts every email may link to
	// (EmailExternalHosts); the others are in the dashboard and in
	// threat_check.
	var src []string
	for _, s := range t.Sources {
		if u, err := url.Parse(s); err == nil && slices.Contains(EmailExternalHosts, strings.ToLower(u.Hostname())) {
			src = append(src, s)
		}
	}
	if len(src) > 0 {
		m.Summary = append(m.Summary, "Sources: "+strings.Join(src, ", "))
	}
	return m
}

func firstMissing(ns []threats.Need) string {
	for _, n := range ns {
		if n.Required {
			return n.Connection
		}
	}
	if len(ns) > 0 {
		return ns[0].Connection
	}
	return ""
}

// ThreatNoticeCopyMessage is the operator's one summary of a threat's
// notices: how many organisations got each verdict, and the text one of
// them got. It names no organisation and no asset.
func ThreatNoticeCopyMessage(t threats.Threat, counts map[string]int, example Message, at time.Time) Message {
	total := 0
	for _, n := range counts {
		total += n
	}
	m := Message{Event: EventThreatNoticeCopy, At: at,
		Title: fmt.Sprintf("Threat notices sent: %s (%s)", t.Name, plainCount(total, "organisation", "organisations"))}
	m.Summary = []string{fmt.Sprintf("Stackurity told %s about %s. Each organisation's administrators and security team got the email and the banner, and its notification routes the message.",
		plainCount(total, "organisation", "organisations"), t.Name)}
	for _, v := range threats.Verdicts {
		if n := counts[v]; n > 0 {
			m.Summary = append(m.Summary, fmt.Sprintf("%s: %d", verdictLabel(v), n))
		}
	}
	m.Summary = append(m.Summary, "Example of what one organisation got (no names are kept in this copy):",
		"Subject: "+example.Subject())
	for _, l := range example.Summary {
		m.Summary = append(m.Summary, "> "+l)
	}
	if example.Action != "" {
		m.Summary = append(m.Summary, "> Recommended action: "+example.Action)
	}
	return m
}

func verdictLabel(v string) string {
	switch v {
	case threats.Found:
		return "Found on their assets"
	case threats.Covered:
		return "Checked, nothing found"
	case threats.NeedsConnection:
		return "Need a connection to be checked"
	case threats.Upgrade:
		return "Must upgrade to be checked"
	}
	return v
}

// QueueThreatNotice gives a notice to the workspace's notification routes
// that send threat notices (store.EventThreatNotices), scoped like other
// alerts: an organisation's routes get every notice; a project's or an
// asset's route only a "found" notice with a finding on one of its assets,
// counting those assets only. Tracker channels (Jira, PagerDuty,
// ServiceNow) keep one record per incident and get none. build makes the
// message for a count of assets (-1: the organisation's totals). It
// returns how many routes were given it. A route that does not have the
// event gets nothing; migration 0118 gave it to every right-away route
// except webhooks, which opt in.
func (d *Dispatcher) QueueThreatNotice(ctx context.Context, noticeID int64, verdict string, toldAt time.Time, foundAssets []int64, build func(assets int) Message) (int, error) {
	ctx = withSentOnce(ctx)
	routes, err := d.routes(ctx)
	if err != nil {
		return 0, err
	}
	tracker, _, err := d.trackerChannels(ctx)
	if err != nil {
		return 0, err
	}
	// Keyed by when people were told, so a threat found again after a fix
	// is a new message.
	key := fmt.Sprintf("threat:%d:%s:%d", noticeID, verdict, toldAt.UnixNano())
	queued := 0
	for _, r := range routes {
		if !r.Enabled || r.Escalation || tracker[r.ChannelID] || !r.HasEvent(store.EventThreatNotices) {
			continue
		}
		msg := build(-1)
		if r.Limited() {
			if verdict != threats.Found {
				continue
			}
			n := 0
			for _, a := range foundAssets {
				if r.Covers(a) {
					n++
				}
			}
			if n == 0 {
				continue
			}
			msg = build(n)
		}
		msg.Route, msg.SettingsLink = r.Name, d.settingsURL()
		if err := d.enqueueTo(ctx, r, r.ChannelFor(store.EventThreatNotices), EventThreatNotice, key, msg); err != nil {
			return queued, err
		}
		queued++
	}
	return queued, nil
}
