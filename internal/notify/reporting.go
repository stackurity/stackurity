package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/words"
)

// Reporting incidents (store/reporting_incidents.go): a server whose agent
// is silent, or a repository, image or SBOM whose scheduled scan stopped.
// Each message says what happened, that the services themselves may be
// fine, what is at risk, the likely causes and the fix, with a help link.

// reportingHelp is the help article each message links to, per cause.
var reportingHelp = map[string]string{
	"agent":  "/help/asset-reporting#servers",
	"scan":   "/help/asset-reporting#scans",
	"upload": "/help/asset-reporting#scans",
}

type reportingDetail struct {
	Cause           string                 `json:"cause"`
	AssetKind       string                 `json:"asset_kind"`
	Since           time.Time              `json:"since"`
	Assets          []store.ReportingAsset `json:"assets"`
	AssetIDs        []int64                `json:"asset_ids"`
	DigestOnly      bool                   `json:"digest_only"`
	PeopleAnnounced bool                   `json:"people_announced"`
	Resolution      string                 `json:"resolution"`
	ReplacedBy      int64                  `json:"replaced_by"`
	GroupSize       int                    `json:"group_size"`
}

func readReporting(in store.Incident) (reportingDetail, bool) {
	var d reportingDetail
	if in.Kind != "collection" {
		return d, false
	}
	_ = json.Unmarshal(in.Detail, &d)
	return d, d.Cause != ""
}

// digestOnly: a repository, image or SBOM that went quiet is told in the
// daily and weekly summaries only, never right away or in a tracker.
func digestOnly(in store.Incident) bool {
	d, ok := readReporting(in)
	return ok && d.DigestOnly
}

// peopleAnnounced: a reporting incident that replaced per-asset incidents
// people were all told about already (upgrade to 0.13.10). Trackers still
// get its issue.
func peopleAnnounced(in store.Incident) bool {
	d, ok := readReporting(in)
	return ok && d.PeopleAnnounced
}

// reportingMessage fills a reporting incident's summary and action.
func (d *Dispatcher) reportingMessage(m *Message, det reportingDetail) {
	now := d.now()
	n := len(det.Assets)
	noun := store.AssetNoun(det.AssetKind, n)
	m.Summary = append(m.Summary, "Your services may be fine; this is about Stackurity's view of them.")
	switch det.Cause {
	case "agent":
		server := strings.TrimSuffix(d.BaseURL, "/")
		if server == "" {
			server = "the Stackurity server"
		}
		m.Summary = append(m.Summary,
			"At risk: findings for "+these(n, noun)+" are not refreshed, so new vulnerabilities on "+them(n)+" go unseen. "+
				"The last results are kept, marked stale.",
			"Likely causes: "+offOrRebuilt(det.AssetKind, n)+", the agent service stopped, or it can't reach "+server+".")
		windows, linux := false, false
		for _, a := range det.Assets {
			if a.OS == "windows" {
				windows = true
			} else {
				linux = true
			}
		}
		var fix []string
		if linux || !windows {
			fix = append(fix, "run `systemctl status stackurity-agent` and `journalctl -u stackurity-agent -n 50`; restart with `systemctl restart stackurity-agent`")
		}
		if windows {
			fix = append(fix, "on Windows, open Task Scheduler (or the service wrapper) that runs `stackurity.exe agent`, check its last run result, and run the command by hand in PowerShell to see the error")
		}
		m.Action = "Fix: " + strings.Join(fix, "; ")
	default:
		cause := "the CI job or scheduled scan that uploads " + them(n) + " stopped or failed"
		if det.Cause == "upload" {
			cause = "nobody has uploaded " + them(n) + " again in the dashboard"
		}
		m.Summary = append(m.Summary,
			"At risk: findings for "+these(n, noun)+" are not refreshed, so new vulnerabilities in "+them(n)+" go unseen. "+
				"The last results are kept, marked stale.",
			"Likely cause: "+cause+".")
		m.Action = "Fix: check " + its(n) + " last pipeline run. Scan commands are in Settings → Integrations → CI pipeline."
		if det.Cause == "upload" {
			m.Action = "Fix: upload a current SBOM, or run the scan in CI (Settings → Integrations → CI pipeline) so it stays current."
		}
	}
	var lines []string
	for i, a := range det.Assets {
		if i == 20 {
			lines = append(lines, "+"+words.Count(n-20, "more", "more"))
			break
		}
		l := a.Name + ": last report " + store.ReportTime(a.LastSeen, now)
		if a.UsualSeconds > 0 {
			l += ", usually every " + store.Every(time.Duration(a.UsualSeconds)*time.Second)
		}
		if apps := len(a.Applications); apps > 0 {
			l += fmt.Sprintf(" (and its %s: %s)", words.Pick(apps, "application", words.Count(apps, "application", "applications")),
				strings.Join(firstN(a.Applications, 5), ", "))
		}
		lines = append(lines, l)
	}
	m.Summary = append(m.Summary, capitalizeFirst(store.AssetNoun(det.AssetKind, n))+": "+strings.Join(lines, "; "))
	if help := d.url(reportingHelp[det.Cause], nil); help != "" {
		m.Summary = append(m.Summary, "How to fix it: "+help)
	}
}

// reportingResolved says why a reporting incident closed: in a Jira,
// PagerDuty or ServiceNow record, since people get no recovery message.
func reportingResolved(m *Message, det reportingDetail) {
	m.Action = ""
	switch det.Resolution {
	case "replaced":
		m.Summary = []string{replacedNote(det)}
	case "one_off":
		what := "another report"
		if det.AssetKind != "" {
			what = "this " + store.AssetNoun(det.AssetKind, 1) + " to report again"
		}
		m.Summary = []string{"Scanned once: Stackurity no longer expects " + what + ". Its results stay as of that scan."}
	case "integration":
		m.Summary = []string{"Reported by an integration: a failing integration has its own incident."}
	default:
		m.Summary = []string{"Reporting again: findings are being refreshed."}
	}
}

func these(n int, noun string) string { return words.Pick(n, "this ", "these ") + noun }

func them(n int) string { return words.Pick(n, "it", "them") }

func its(n int) string { return words.Pick(n, "its", "each one's") }

// offOrRebuilt is the first likely cause of a silent agent: "the server is
// off or was rebuilt", "the servers are off or were rebuilt".
func offOrRebuilt(kind string, n int) string {
	switch {
	case kind == "host" && n == 1:
		return "the server is off or was rebuilt"
	case kind == "host":
		return "the servers are off or were rebuilt"
	case n == 1:
		return "the server it runs on is off or was rebuilt"
	}
	return "the servers they run on are off or were rebuilt"
}

func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// systemSections splits problems with Stackurity's own data: servers,
// repositories and images that stopped reporting under "Not reporting to
// Stackurity", the rest (feeds, integrations, the platform) under
// "Stackurity needs attention".
func (d *Dispatcher) systemSections(list []store.Incident) []Section {
	var quiet, other []store.Incident
	for _, in := range list {
		if _, ok := readReporting(in); ok {
			quiet = append(quiet, in)
		} else {
			other = append(other, in)
		}
	}
	var out []Section
	if len(other) > 0 {
		out = append(out, Section{Title: "Stackurity needs attention", Items: d.systemItems(other)})
	}
	if len(quiet) > 0 {
		out = append(out, Section{Title: "Not reporting to Stackurity (your services may be fine)", Items: d.systemItems(quiet)})
	}
	return out
}

// systemTitle titles a message about problems alone: one reporting problem
// is its own title.
func systemTitle(list []store.Incident) string {
	if len(list) == 1 {
		if _, ok := readReporting(list[0]); ok {
			return list[0].Title
		}
	}
	for _, in := range list {
		if _, ok := readReporting(in); !ok {
			return fmt.Sprintf("Stackurity needs attention: %s", plural(len(list), "problem"))
		}
	}
	return fmt.Sprintf("Not reporting to Stackurity: %s", plural(len(list), "problem"))
}

// oneOffItem is the weekly nudge about assets scanned once.
func (d *Dispatcher) oneOffItem(data *summaryData) (Item, bool) {
	if !data.oneOffRead {
		data.oneOffRead = true
		var err error
		if data.oneOff, err = d.Store.OneOffAssets(data.ctx); err != nil && d.Log != nil {
			d.Log.Warn("one-off assets", "error", err)
		}
	}
	if len(data.oneOff) == 0 {
		return Item{}, false
	}
	n := 0
	var oldest, newest time.Time
	for _, g := range data.oneOff {
		n += g.Count
		if oldest.IsZero() || g.Oldest.Before(oldest) {
			oldest = g.Oldest
		}
		if g.Newest.After(newest) {
			newest = g.Newest
		}
	}
	one, many := "asset", "assets"
	if len(data.oneOff) == 1 {
		one, many = store.AssetNoun(data.oneOff[0].Kind, 1), store.AssetNoun(data.oneOff[0].Kind, 2)
	}
	text := fmt.Sprintf("%s scanned once, results as of %s. Set up a scheduled scan to keep %s current.",
		words.Count(n, one, many), store.AsOf(oldest, newest, d.now()), words.Pick(n, "it", "them"))
	return Item{Text: text, Link: d.url("/help/asset-reporting#one-off", nil)}, true
}

// resolvedNote is what a Jira issue or ServiceNow record says when its
// incident resolves: why a reporting incident closed ("Replaced by #N",
// "Scanned once"), otherwise that no open findings remain.
func resolvedNote(in *store.Incident, msg Message) string {
	if in.Kind == "collection" && len(msg.Summary) > 0 {
		var d reportingDetail
		_ = json.Unmarshal(in.Detail, &d)
		if d.Cause != "" || d.Resolution != "" {
			return "Resolved in Stackurity: " + msg.Summary[0]
		}
	}
	return "Resolved in Stackurity: no open findings remain for this incident."
}

// reopenCount is how many times the incident opened again after resolving
// (detail.reopened, store.SyncSystemIncidents).
func reopenCount(in store.Incident) int {
	var d struct {
		Reopened int `json:"reopened"`
	}
	_ = json.Unmarshal(in.Detail, &d)
	return d.Reopened
}

// reopenLabel names an incident's open period in a tracker: its label, then
// "-2", "-3" for the periods after it reopened.
func reopenLabel(ws int64, in *store.Incident) string {
	return fmt.Sprintf("%s-%d", IncidentLabel(ws, in.ID), reopenCount(*in)+1)
}

// reopenNote leads a reopened incident's new tracker record.
func reopenNote(previous string) string {
	return "Stopped reporting again after recovering. This incident reopened; the previous record was " + previous + "."
}

// replacedNote closes a per-asset incident from before 0.13.10 replaced by a
// reporting incident: "Replaced by #12, the new incident for this server",
// or "…, which groups the 3 servers that stopped reporting on the same day".
func replacedNote(det reportingDetail) string {
	switch {
	case det.AssetKind == "":
		return fmt.Sprintf("Replaced by #%d, which groups what stopped reporting on the same day for the same reason.", det.ReplacedBy)
	case det.GroupSize == 1:
		return fmt.Sprintf("Replaced by #%d, the new incident for this %s.", det.ReplacedBy, store.AssetNoun(det.AssetKind, 1))
	case det.GroupSize > 1:
		return fmt.Sprintf("Replaced by #%d, which groups the %s that stopped reporting on the same day.", det.ReplacedBy,
			words.Count(det.GroupSize, store.AssetNoun(det.AssetKind, 1), store.AssetNoun(det.AssetKind, 2)))
	}
	return fmt.Sprintf("Replaced by #%d, which groups the %s that stopped reporting on the same day.", det.ReplacedBy, store.AssetNoun(det.AssetKind, 2))
}
