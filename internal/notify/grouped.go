package notify

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
)

// Grouped notifications. People are told little and often enough to act:
//
//   - urgent: at most one message per route per evaluation cycle, when the
//     cycle produced issues at the route's urgent priority (or SOS, or known
//     exploited), summarised per asset with the fixes that clear them;
//   - summary: daily or weekly at the route's time, what is new, what was
//     fixed (and by what), the top fixes still open and what is overdue;
//   - overdue: at most once a day per route, when urgent issues pass their
//     fix deadline (licensed builds, routes with escalation);
//   - connected: an asset's first scan, instead of alerts for its backlog.
//
// A route's mode picks them: urgent_summary sends all of them, urgent_only
// all but summaries, daily and weekly only summaries (with an overdue
// section instead of the overdue message).
//
// Every item links to the dashboard. Jira channels keep one issue per
// incident (see Plan); none of this applies to them.
const (
	EventUrgent    = "urgent"
	EventSummary   = "summary"
	EventOverdue   = "overdue"
	EventConnected = "connected"
	// EventDigest lists messages an hourly limit held, for a route
	// without summaries or a deleted route.
	EventDigest = "digest"
)

// sendsUrgent: the route sends something as it happens (urgent or new
// issues, issues that came back, overdue, connected or problems).
func sendsUrgent(r store.Route) bool {
	for _, e := range []string{store.EventUrgent, store.EventNewIssues, store.EventRegressed, store.EventOverdue, store.EventConnected, store.EventProblems} {
		if r.HasEvent(e) {
			return true
		}
	}
	return false
}

// sendsSummary: the route sends a daily or weekly summary.
func sendsSummary(r store.Route) bool {
	return r.HasEvent(store.EventDailySummary) || r.HasEvent(store.EventWeeklySummary)
}

// newIssueThreshold is the lowest priority of new issues the route sends
// right away: min_priority for urgent, new_min_priority for new issues,
// the lower of the two with both; "" for none.
func newIssueThreshold(r store.Route) string {
	t := ""
	if r.HasEvent(store.EventUrgent) {
		t = r.MinPriority
	}
	if r.HasEvent(store.EventNewIssues) {
		n := r.NewMinPriority
		if n == "" {
			n = "P4"
		}
		if n > t {
			t = n
		}
	}
	return t
}

// findingsChannel is where the route sends new issues right away.
func findingsChannel(r store.Route) int64 {
	if r.HasEvent(store.EventNewIssues) {
		return r.ChannelFor(store.EventNewIssues)
	}
	return r.ChannelFor(store.EventUrgent)
}

const (
	maxAssetItems = 5 // assets listed in one section, then "+N more"
	maxFixItems   = 3 // fixes listed per asset or section, then "+N more"
	maxNameLen    = 60
)

// --- scope

// inScope applies a route's filters other than priority.
func inScope(r store.Route, in store.Incident) bool {
	if !r.Enabled || r.SOSOnly && !in.SOS {
		return false
	}
	if len(r.ProjectIDs) > 0 && !incidentInProjects(r, in) {
		return false
	}
	if len(r.Kinds) > 0 && !contains(r.Kinds, in.Kind) {
		return false
	}
	if len(r.TeamIDs) > 0 && !teamIn(r.TeamIDs, in.OwnerTeamID) {
		return false
	}
	if len(r.Environments) > 0 {
		var detail struct {
			Environments []string `json:"environments"`
		}
		_ = json.Unmarshal(in.Detail, &detail)
		for _, e := range detail.Environments {
			if contains(r.Environments, e) {
				return true
			}
		}
		return false
	}
	return true
}

func teamIn(ids []int64, team *int64) bool {
	if team == nil {
		return false
	}
	for _, t := range ids {
		if t == *team {
			return true
		}
	}
	return false
}

// incidentInProjects: a route limited to projects hears about an issue
// (its findings are then counted per asset, for the project's assets only)
// and about collection and coverage problems of the project's assets, not
// about other problems.
func incidentInProjects(r store.Route, in store.Incident) bool {
	if isFindingKind(in.Kind) {
		return true
	}
	if in.Kind != "collection" && in.Kind != "coverage" {
		return false
	}
	rest, ok := strings.CutPrefix(in.Key, "asset:")
	if !ok {
		return false
	}
	id, _, _ := strings.Cut(rest, ":")
	n, err := strconv.ParseInt(id, 10, 64)
	return err == nil && r.ProjectAssets[n]
}

// assetInScope applies a route's project, team and environment filters to
// an asset.
func assetInScope(r store.Route, id int64, env string, team *int64) bool {
	if len(r.ProjectIDs) > 0 && !r.ProjectAssets[id] {
		return false
	}
	if len(r.TeamIDs) > 0 && !teamIn(r.TeamIDs, team) {
		return false
	}
	return len(r.Environments) == 0 || contains(r.Environments, env)
}

// issueInScope applies a route's filters to a count of findings.
func issueInScope(r store.Route, c store.IssueCount) bool {
	if r.SOSOnly && !c.SOS {
		return false
	}
	if len(r.Kinds) > 0 && !contains(r.Kinds, c.Kind) {
		return false
	}
	return assetInScope(r, c.AssetID, c.Environment, c.OwnerTeamID)
}

// assetsWanted: routes limited to system problems or SOS get no asset news.
func assetsWanted(r store.Route) bool {
	if r.SOSOnly {
		return false
	}
	return len(r.Kinds) == 0 || contains(r.Kinds, "vulnerability") || contains(r.Kinds, "end_of_life")
}

func knownExploited(in store.Incident) bool {
	var det struct {
		KnownExploited bool `json:"known_exploited"`
	}
	_ = json.Unmarshal(in.Detail, &det)
	return det.KnownExploited
}

// urgentIncident: the incident is for this route and is sent right away:
// new issues at its threshold, SOS or known exploited (urgent or
// new_issues), or a problem at min_priority or SOS (problems).
func urgentIncident(r store.Route, in store.Incident) bool {
	if !inScope(r, in) {
		return false
	}
	if !isFindingKind(in.Kind) {
		return r.HasEvent(store.EventProblems) && (risk.PriorityAtLeast(in.Priority, r.MinPriority) || in.SOS)
	}
	t := newIssueThreshold(r)
	return t != "" && (risk.PriorityAtLeast(in.Priority, t) || in.SOS || knownExploited(in))
}

// rightAwayIssue: a new issue the route sends as it happens.
func rightAwayIssue(r store.Route, c store.IssueCount) bool {
	t := newIssueThreshold(r)
	return t != "" && (risk.PriorityAtLeast(c.Priority, t) || c.SOS || c.KEV)
}

func urgentIssue(r store.Route, c store.IssueCount) bool {
	return risk.PriorityAtLeast(c.Priority, r.MinPriority) || c.SOS || c.KEV
}

// overdueUrgent: what the immediate overdue alert is about (P1 or SOS).
func overdueUrgent(priority string, sos bool) bool { return priority == "P1" || sos }

func isFindingKind(kind string) bool { return kind == "vulnerability" || kind == "end_of_life" }

// --- links

func (d *Dispatcher) url(path string, q url.Values) string {
	if d.BaseURL == "" {
		return ""
	}
	u := strings.TrimSuffix(d.BaseURL, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

func (d *Dispatcher) homeURL() string { return d.url("/", nil) }
func (d *Dispatcher) settingsURL() string {
	return d.url("/settings/notifications", url.Values{"tab": {"routes"}})
}
func (d *Dispatcher) fixURL(id string) string { return d.url("/fixes/"+url.PathEscape(id), nil) }
func (d *Dispatcher) assetURL(id int64) string {
	return d.url("/assets/"+strconv.FormatInt(id, 10), nil)
}

func (d *Dispatcher) planURL(assetID int64) string {
	if assetID == 0 {
		return d.url("/fixes", nil)
	}
	return d.url("/fixes", url.Values{"asset_id": {strconv.FormatInt(assetID, 10)}})
}

// findingsURL is All issues (/fixes/issues) with filters; asset 0 means
// every asset.
func (d *Dispatcher) findingsURL(assetID int64, extra url.Values) string {
	q := url.Values{}
	for k, v := range extra {
		q[k] = v
	}
	if assetID > 0 {
		q.Set("asset_id", strconv.FormatInt(assetID, 10))
	}
	return d.url("/fixes/issues", q)
}

// priorityFilter lists the priorities at or above min, for issue links.
func priorityFilter(min string) url.Values {
	var ps []string
	for _, p := range []string{"P1", "P2", "P3", "P4"} {
		if risk.PriorityAtLeast(p, min) {
			ps = append(ps, p)
		}
	}
	if len(ps) == 4 {
		return url.Values{}
	}
	return url.Values{"priority": {strings.Join(ps, ",")}}
}

func (d *Dispatcher) grouped(r store.Route, event, title string, sections []Section) Message {
	for i := range sections {
		scopeItems(r, sections[i].Items)
	}
	return Message{Event: event, Title: title, Route: r.Name, Sections: sections, Summary: itemTexts(sections),
		Link: inProject(d.homeURL(), routeProject(r, 0)), SettingsLink: d.settingsURL(), At: d.now().UTC()}
}

// --- links into the route's project

// routeProject is the project a link about asset (0: none or several)
// opens in the dashboard: the route's project when it has one, else the
// first of its projects the asset is in. 0: all projects.
func routeProject(r store.Route, asset int64) int64 {
	switch {
	case len(r.ProjectIDs) == 1:
		return r.ProjectIDs[0]
	case len(r.ProjectIDs) == 0 || asset == 0:
		return 0
	}
	return r.AssetProject[asset]
}

// inProject adds the project to a dashboard link, so it opens scoped to it.
func inProject(link string, project int64) string {
	if project == 0 || link == "" {
		return link
	}
	u, err := url.Parse(link)
	if err != nil {
		return link
	}
	q := u.Query()
	q.Set("project", strconv.FormatInt(project, 10))
	u.RawQuery = q.Encode()
	return u.String()
}

// scopeItems opens every link of the items in the route's project.
func scopeItems(r store.Route, items []Item) {
	for i := range items {
		it := &items[i]
		p := routeProject(r, it.asset)
		it.Link = inProject(it.Link, p)
		for j := range it.Actions {
			it.Actions[j].Link = inProject(it.Actions[j].Link, p)
		}
		for j := range it.Items {
			if it.Items[j].asset == 0 {
				it.Items[j].asset = it.asset
			}
		}
		scopeItems(r, it.Items)
	}
}

// fixItem is a fix in a message, with links to assign it, snooze it or
// open it. The links open the fix page with the action ready; nothing
// changes until the person confirms it there.
func (d *Dispatcher) fixItem(text, id string, asset int64) Item {
	it := Item{Text: text, Link: d.fixURL(id), asset: asset}
	if d.BaseURL == "" {
		return it
	}
	path := "/fixes/" + url.PathEscape(id)
	it.Actions = []Action{
		{Kind: "assign", Label: "Assign to me", Link: d.url(path, url.Values{"action": {"assign"}}), Fix: id},
		{Kind: "snooze", Label: "Snooze", Link: d.url(path, url.Values{"action": {"snooze"}}), Fix: id},
		{Kind: "open", Label: "Open", Link: d.fixURL(id), Fix: id},
	}
	return it
}

// --- aggregation

// assetIssues is one asset's share of a set of findings.
type assetIssues struct {
	ID     int64
	Name   string
	Count  int
	Urgent int
	SOS    int
	KEV    int
	Fixes  map[string]int // fix group id -> findings
	Titles map[string]int // closing fix title -> findings (fixed issues)
}

// byAsset sums counts per asset, most urgent and largest first.
func byAsset(counts []store.IssueCount, keep func(store.IssueCount) bool, urgent func(store.IssueCount) bool) []*assetIssues {
	m := map[int64]*assetIssues{}
	for _, c := range counts {
		if keep != nil && !keep(c) {
			continue
		}
		a := m[c.AssetID]
		if a == nil {
			a = &assetIssues{ID: c.AssetID, Name: shorten(c.AssetName, maxNameLen), Fixes: map[string]int{}, Titles: map[string]int{}}
			m[c.AssetID] = a
		}
		a.Count += c.Count
		if urgent != nil && urgent(c) {
			a.Urgent += c.Count
		}
		if c.SOS {
			a.SOS += c.Count
		}
		if c.KEV {
			a.KEV += c.Count
		}
		if c.FixGroup != "" {
			a.Fixes[c.FixGroup] += c.Count
		}
		if c.FixTitle != "" {
			a.Titles[c.FixTitle] += c.Count
		}
	}
	out := make([]*assetIssues, 0, len(m))
	for _, a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Urgent != out[j].Urgent {
			return out[i].Urgent > out[j].Urgent
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func total(list []*assetIssues) (n, urgent int) {
	for _, a := range list {
		n += a.Count
		urgent += a.Urgent
	}
	return n, urgent
}

// fixItems lists the fixes behind counts, the ones covering most of them
// first, as "Install security updates and reboot (clears 2,913 issues)".
// When top is set the first is labelled "Top fix".
func (d *Dispatcher) fixItems(counts map[string]int, infos map[string]store.FixInfo, assetID int64, top bool) []Item {
	ids := make([]string, 0, len(counts))
	for id := range counts {
		if _, ok := infos[id]; ok {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := infos[ids[i]], infos[ids[j]]
		if counts[ids[i]] != counts[ids[j]] {
			return counts[ids[i]] > counts[ids[j]]
		}
		return a.SortOrder < b.SortOrder
	})
	var out []Item
	for i, id := range ids {
		if i == maxFixItems {
			out = append(out, Item{Text: fmt.Sprintf("+%s", plural(len(ids)-maxFixItems, "more fix")), Link: d.planURL(assetID)})
			break
		}
		g := infos[id]
		text := fmt.Sprintf("%s (clears %s)", g.Title, plural(g.FindingCount, "issue"))
		if top && i == 0 {
			text = "Top fix: " + text
		}
		out = append(out, d.fixItem(text, id, g.AssetID))
	}
	return out
}

func fixIDs(counts []store.IssueCount) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range counts {
		if c.FixGroup != "" && !seen[c.FixGroup] {
			seen[c.FixGroup] = true
			out = append(out, c.FixGroup)
		}
	}
	return out
}

// moreAssets is the "+N more" item after the listed assets.
func moreAssets(n int, what, link string) Item {
	return Item{Text: fmt.Sprintf("+%s %s", plural(n, "more asset"), what), Link: link}
}

func keyOf(prefix string, routeID int64, ids []int64) string {
	sorted := append([]int64(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	h := sha256.New()
	for _, id := range sorted {
		fmt.Fprintf(h, "%d,", id)
	}
	return fmt.Sprintf("%s:%d:%x", prefix, routeID, h.Sum(nil)[:8])
}

func detail(parts ...string) string {
	var keep []string
	for _, p := range parts {
		if p != "" {
			keep = append(keep, p)
		}
	}
	if len(keep) == 0 {
		return ""
	}
	return " (" + strings.Join(keep, ", ") + ")"
}

// countIf is "3 urgent" or "" for none; the words do not change in the plural.
func countIf(n int, word string) string {
	if n == 0 {
		return ""
	}
	return thousands(n) + " " + word
}

// --- urgent alerts

// urgentMessage summarises a route's urgent incidents of one cycle: per
// asset, the new urgent issues and the fixes that clear them; then
// problems with Stackurity's own data. quiet assets (first scan) are left
// out. ok is false when nothing is left to say.
func (d *Dispatcher) urgentMessage(r store.Route, incs []store.Incident, rows map[int64][]store.IssueCount,
	quiet map[int64]bool, infos map[string]store.FixInfo, regressed []store.IssueCount) (Message, bool) {
	var counts []store.IssueCount
	var system []store.Incident
	top, sos := "P4", false
	for _, in := range incs {
		if !isFindingKind(in.Kind) {
			system = append(system, in)
		}
		for _, c := range rows[in.ID] {
			if !quiet[c.AssetID] && !c.Backlog && issueInScope(r, c) && rightAwayIssue(r, c) {
				counts = append(counts, c)
				if c.Priority < top {
					top = c.Priority
				}
				sos = sos || c.SOS
			}
		}
	}
	for _, in := range system {
		if in.Priority < top {
			top = in.Priority
		}
		sos = sos || in.SOS
	}
	for _, c := range regressed {
		if c.Priority < top {
			top = c.Priority
		}
		sos = sos || c.SOS
	}
	// Routes sending every new issue say "new issues (3 urgent)"; others
	// send only urgent ones and say "new urgent issues".
	all := r.HasEvent(store.EventNewIssues)
	noun := "new urgent issue"
	isUrgent := func(store.IssueCount) bool { return true }
	if all {
		noun = "new issue"
		isUrgent = func(c store.IssueCount) bool { return urgentIssue(r, c) }
	}
	assets := byAsset(counts, nil, isUrgent)
	back := byAsset(regressed, nil, func(store.IssueCount) bool { return true })
	n, _ := total(assets)
	nBack, _ := total(back)
	if n == 0 && len(system) == 0 && nBack == 0 {
		return Message{}, false
	}
	pf := priorityFilter(newIssueThreshold(r))
	var sections []Section
	if len(assets) > 0 {
		var items []Item
		for i, a := range assets {
			if i == maxAssetItems {
				items = append(items, moreAssets(len(assets)-maxAssetItems, "with "+noun+"s", d.findingsURL(0, pf)))
				break
			}
			urgentPart := ""
			if all {
				urgentPart = countIf(a.Urgent, "urgent")
			}
			items = append(items, Item{
				Text:  fmt.Sprintf("%s: %s%s", a.Name, plural(a.Count, noun), detail(urgentPart, countIf(a.KEV, "known exploited"), countIf(a.SOS, "SOS"))),
				Link:  d.findingsURL(a.ID, pf),
				Items: d.fixItems(a.Fixes, infos, a.ID, true),
				asset: a.ID,
			})
		}
		sections = append(sections, Section{Items: items})
	}
	if len(back) > 0 {
		sections = append(sections, Section{Title: "Came back after a fix", Items: d.regressedItems(back, infos)})
	}
	if len(system) > 0 {
		sections = append(sections, Section{Title: "Stackurity needs attention", Items: d.systemItems(system)})
	}
	var title string
	switch {
	case len(assets) == 1:
		title = fmt.Sprintf("%s: %s", assets[0].Name, plural(n, noun))
	case len(assets) > 1:
		title = fmt.Sprintf("%s on %s", plural(n, noun), plural(len(assets), "asset"))
	case len(back) == 1:
		title = fmt.Sprintf("%s: %s", back[0].Name, cameBack(nBack))
	case len(back) > 1:
		title = fmt.Sprintf("%s on %s", cameBack(nBack), plural(len(back), "asset"))
	default:
		title = fmt.Sprintf("Stackurity needs attention: %s", plural(len(system), "problem"))
	}
	if len(assets) > 0 && nBack > 0 {
		title += fmt.Sprintf(", %s came back", thousands(nBack))
	}
	if (len(assets) > 0 || len(back) > 0) && len(system) > 0 {
		title += fmt.Sprintf(", %s", plural(len(system), "problem"))
	}
	m := d.grouped(r, EventUrgent, title, sections)
	m.Priority, m.SOS = top, sos
	m.Counts = map[string]int{"urgent": n, "assets": len(assets), "problems": len(system), "regressed": nBack}
	if all {
		_, nUrgent := total(assets)
		m.Counts["new"], m.Counts["urgent"] = n, nUrgent
	}
	return m, true
}

// cameBack: "1 issue came back after a fix", "3 issues came back after a fix".
func cameBack(n int) string { return plural(n, "issue") + " came back after a fix" }

// regressedItems lists, per asset, the issues that came back after a fix,
// with the fixes that clear them.
func (d *Dispatcher) regressedItems(back []*assetIssues, infos map[string]store.FixInfo) []Item {
	q := url.Values{"state": {"regressed"}}
	var items []Item
	for i, a := range back {
		if i == maxAssetItems {
			items = append(items, moreAssets(len(back)-maxAssetItems, "with issues that came back", d.findingsURL(0, q)))
			break
		}
		items = append(items, Item{
			Text:  fmt.Sprintf("%s: %s%s", a.Name, cameBack(a.Count), detail(countIf(a.KEV, "known exploited"), countIf(a.SOS, "SOS"))),
			Link:  d.findingsURL(a.ID, q),
			Items: d.fixItems(a.Fixes, infos, a.ID, true),
			asset: a.ID,
		})
	}
	return items
}

func (d *Dispatcher) systemItems(list []store.Incident) []Item {
	var items []Item
	for i, in := range list {
		if i == maxFixItems {
			items = append(items, Item{Text: fmt.Sprintf("+%s", plural(len(list)-maxFixItems, "more problem")), Link: d.url("/incidents", nil)})
			break
		}
		items = append(items, Item{Text: shorten(in.Title, 120), Link: d.url("/incidents/"+strconv.FormatInt(in.ID, 10), nil)})
	}
	return items
}

// --- connected

// fixesByAsset groups open fixes per asset.
func fixesByAsset(fixes []store.FixInfo) map[int64][]store.FixInfo {
	out := map[int64][]store.FixInfo{}
	for _, f := range fixes {
		out[f.AssetID] = append(out[f.AssetID], f)
	}
	return out
}

// connectedItem: "commmerceblog connected: 1,676 packages checked, 412
// issues found, 3 fixes need you", with its top fixes. The issues are the
// asset's backlog: they are counted here, never as new issues.
func (d *Dispatcher) connectedItem(a store.NewAsset, fixes []store.FixInfo) Item {
	name := shorten(a.Name, maxNameLen)
	text := fmt.Sprintf("%s connected: %s checked, ", name, plural(a.Packages, "package"))
	if a.Issues > 0 {
		text += plural(a.Issues, "issue") + " found, "
	}
	switch len(fixes) {
	case 0:
		text += "nothing needs fixing"
	case 1:
		text += "1 fix needs you"
	default:
		text += plural(len(fixes), "fix") + " need you"
	}
	it := Item{Text: text, Link: d.assetURL(a.ID), asset: a.ID}
	for i, f := range fixes {
		if i == maxFixItems {
			it.Items = append(it.Items, Item{Text: fmt.Sprintf("+%s", plural(len(fixes)-maxFixItems, "more fix")), Link: d.planURL(a.ID)})
			break
		}
		it.Items = append(it.Items, d.fixItem(fmt.Sprintf("%s (clears %s)", f.Title, plural(f.FindingCount, "issue")), f.ID, a.ID))
	}
	return it
}

func (d *Dispatcher) connectedItems(assets []store.NewAsset, fixes map[int64][]store.FixInfo) []Item {
	var items []Item
	for i, a := range assets {
		if i == maxAssetItems {
			items = append(items, moreAssets(len(assets)-maxAssetItems, "connected", d.url("/assets", nil)))
			break
		}
		items = append(items, d.connectedItem(a, fixes[a.ID]))
	}
	return items
}

func (d *Dispatcher) connectedMessage(r store.Route, assets []store.NewAsset, fixes map[int64][]store.FixInfo) Message {
	items := d.connectedItems(assets, fixes)
	title := items[0].Text
	if len(assets) > 1 {
		title = plural(len(assets), "asset") + " connected"
	}
	m := d.grouped(r, EventConnected, title, []Section{{Items: items}})
	issues := 0
	for _, a := range assets {
		issues += a.Issues
	}
	m.Counts = map[string]int{"assets": len(assets), "issues": issues}
	return m
}

// --- overdue

// overdueItems lists the fixes behind overdue issues, most overdue first.
func (d *Dispatcher) overdueFixItems(counts []store.IssueCount, keep func(store.IssueCount) bool, infos map[string]store.FixInfo) (items []Item, n, fixes int) {
	per := map[string]int{}
	for _, c := range counts {
		if !keep(c) {
			continue
		}
		n += c.Count
		if c.FixGroup != "" {
			per[c.FixGroup] += c.Count
		}
	}
	ids := make([]string, 0, len(per))
	for id := range per {
		if _, ok := infos[id]; ok {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		if per[ids[i]] != per[ids[j]] {
			return per[ids[i]] > per[ids[j]]
		}
		return infos[ids[i]].SortOrder < infos[ids[j]].SortOrder
	})
	for i, id := range ids {
		if i == maxFixItems {
			items = append(items, Item{Text: fmt.Sprintf("+%s", plural(len(ids)-maxFixItems, "more fix")), Link: d.findingsURL(0, url.Values{"overdue": {"true"}})})
			break
		}
		g := infos[id]
		items = append(items, d.fixItem(fmt.Sprintf("%s on %s: %s overdue", g.Title, shorten(g.AssetName, maxNameLen), thousands(per[id])), id, g.AssetID))
	}
	return items, n, len(ids)
}

func (d *Dispatcher) overdueMessage(r store.Route, counts []store.IssueCount, infos map[string]store.FixInfo) (Message, bool) {
	keep := func(c store.IssueCount) bool { return issueInScope(r, c) && overdueUrgent(c.Priority, c.SOS) }
	items, n, fixes := d.overdueFixItems(counts, keep, infos)
	if n == 0 {
		return Message{}, false
	}
	title := fmt.Sprintf("%s past their deadline", plural(n, "urgent issue"))
	if n == 1 {
		title = "1 urgent issue past its deadline"
	}
	if fixes > 0 {
		title += " across " + plural(fixes, "fix")
	}
	all := Item{Text: "See every overdue urgent issue", Link: d.findingsURL(0, url.Values{"overdue": {"true"}, "priority": {"P1"}})}
	m := d.grouped(r, EventOverdue, title, []Section{{Items: append(items, all)}})
	m.Priority = "P1"
	m.Counts = map[string]int{"overdue_urgent": n, "fixes": fixes}
	return m, true
}

// --- summaries

// summaryDue reports whether a route's summary is due at now: its last
// summary is older than the latest scheduled time (route-local). stamp
// names that scheduled time, for the delivery's dedupe key.
func summaryDue(r store.Route, weekly bool, now time.Time) (stamp string, due bool) {
	loc, err := time.LoadLocation(r.Timezone)
	if err != nil {
		loc = time.UTC
	}
	at, err := time.Parse("15:04", r.SummaryTime)
	if err != nil {
		at, _ = time.Parse("15:04", "09:00")
	}
	local := now.In(loc)
	cand := time.Date(local.Year(), local.Month(), local.Day(), at.Hour(), at.Minute(), 0, 0, loc)
	if cand.After(local) {
		cand = cand.AddDate(0, 0, -1)
	}
	last := r.LastSummaryAt
	if weekly {
		want := weekday(r.SummaryDay)
		for cand.Weekday() != want {
			cand = cand.AddDate(0, 0, -1)
		}
		last = lastWeekly(r)
	}
	return cand.Format("2006-01-02T15:04"), last.Before(cand)
}

func weekday(s string) time.Weekday {
	for i, d := range store.Weekdays {
		if strings.EqualFold(d, s) {
			return time.Weekday(i)
		}
	}
	return time.Monday
}

// summaryData is what summaries read, loaded once per planning pass.
type summaryData struct {
	d     *Dispatcher
	ctx   context.Context
	cache map[string][]store.IssueCount
	fixes []store.FixInfo
	infos map[string]store.FixInfo
	sys   []store.Incident
	ready bool
	// behind: installs with an update available, read once for the
	// routes whose summaries list them.
	behind      []store.BehindInstall
	behindReady bool
}

func (s *summaryData) updates() ([]store.BehindInstall, error) {
	if s.behindReady {
		return s.behind, nil
	}
	var err error
	if s.behind, err = s.d.Store.BehindInstalls(s.ctx, 0); err != nil {
		return nil, err
	}
	s.behindReady = true
	return s.behind, nil
}

func (s *summaryData) counts(set store.IssueSet, from, to time.Time) ([]store.IssueCount, error) {
	k := fmt.Sprintf("%d:%d:%d", set, from.UnixMicro(), to.UnixMicro())
	if c, ok := s.cache[k]; ok {
		return c, nil
	}
	c, err := s.d.Store.CountIssues(s.ctx, set, from, to)
	if err == nil {
		s.cache[k] = c
	}
	return c, err
}

func (s *summaryData) load() error {
	if s.ready {
		return nil
	}
	var err error
	if s.fixes, err = s.d.Store.OpenFixes(s.ctx, nil); err != nil {
		return err
	}
	s.infos = map[string]store.FixInfo{}
	for _, f := range s.fixes {
		s.infos[f.ID] = f
	}
	if s.sys, err = s.d.Store.OpenSystemIncidents(s.ctx); err != nil {
		return err
	}
	s.ready = true
	return nil
}

// lastWeekly is the end of the period the route's last weekly summary
// covered. A route built without events (not read from the database) keeps
// it in LastSummaryAt, as the weekly mode did.
func lastWeekly(r store.Route) time.Time {
	if r.Events == nil {
		return r.LastSummaryAt
	}
	return r.LastWeeklySummaryAt
}

// planSummaries queues the summaries that are due: daily and weekly ones
// are planned and recorded apart, so a route may send both.
func (d *Dispatcher) planSummaries(ctx context.Context, routes []store.Route, tracker map[int64]bool) error {
	now := d.now()
	data := &summaryData{d: d, ctx: ctx, cache: map[string][]store.IssueCount{}}
	overdue := d.overdueOn(ctx)
	for _, r := range routes {
		if !r.Enabled || tracker[r.ChannelID] {
			continue
		}
		for _, weekly := range []bool{false, true} {
			if err := d.planSummary(ctx, r, weekly, now, data, overdue); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *Dispatcher) planSummary(ctx context.Context, r store.Route, weekly bool, now time.Time, data *summaryData, overdue bool) error {
	if r.Events == nil && weekly != (r.Mode == store.ModeWeekly || r.Mode == store.ModeUrgentWeekly) {
		return nil // built without events: one summary, kept in LastSummaryAt
	}
	event, prev, claim := store.EventDailySummary, r.LastSummaryAt, d.Store.ClaimSummary
	if weekly {
		event, prev = store.EventWeeklySummary, lastWeekly(r)
		if r.Events != nil {
			claim = d.Store.ClaimWeeklySummary
		}
	}
	stamp, due := summaryDue(r, weekly, now)
	if !due {
		return nil
	}
	if !r.HasEvent(event) {
		// No summary, but the period moves on, so a route that adds the
		// summary later does not start with one covering months.
		_, err := claim(ctx, r.ID, prev, now)
		return err
	}
	msg, changed, err := d.summaryMessage(r, weekly, data, prev, now, overdue && r.Escalation)
	if err != nil {
		return err
	}
	held, byQuota, err := d.Store.HeldForRoute(ctx, r.ID)
	if err != nil {
		return err
	}
	if len(held) > 0 {
		msg.Counts["held"] = len(held)
		limit := "the hourly limit"
		switch {
		case byQuota == len(held):
			limit = "the email limit"
		case byQuota > 0:
			limit = "the hourly and email limits"
		}
		msg.Sections = append(msg.Sections, Section{Items: []Item{{
			Text: fmt.Sprintf("Includes %s held back by %s", plural(len(held), "urgent message"), limit),
			Link: d.url("/settings/notifications", url.Values{"tab": {"deliveries"}}),
		}}})
		msg.Summary = itemTexts(msg.Sections)
	}
	if changed || len(held) > 0 {
		key := fmt.Sprintf("summary:%d:%s", r.ID, stamp)
		if weekly {
			key = fmt.Sprintf("summary:%d:weekly:%s", r.ID, stamp)
		}
		if err := d.enqueueTo(ctx, r, r.ChannelFor(event), EventSummary, key, msg); err != nil {
			return err
		}
		if err := d.Store.MarkDigested(ctx, held, key); err != nil {
			return err
		}
	}
	_, err = claim(ctx, r.ID, prev, now)
	return err
}

// summaryMessage builds a route's summary of [from, to). changed is false
// when nothing happened worth a message.
func (d *Dispatcher) summaryMessage(r store.Route, weekly bool, data *summaryData, from, to time.Time, withOverdue bool) (Message, bool, error) {
	if err := data.load(); err != nil {
		return Message{}, false, err
	}
	news, err := data.counts(store.IssuesNew, from, to)
	if err != nil {
		return Message{}, false, err
	}
	fixed, err := data.counts(store.IssuesFixed, from, to)
	if err != nil {
		return Message{}, false, err
	}
	regressed, err := data.counts(store.IssuesRegressed, from, to)
	if err != nil {
		return Message{}, false, err
	}
	// Closed because an advisory was withdrawn or changed: not a fix, so
	// never counted as fixed; told apart in the Fixed section.
	gone, err := data.counts(store.IssuesNoLongerAffected, from, to)
	if err != nil {
		return Message{}, false, err
	}
	connected, err := d.Store.AssetsAnnounced(data.ctx, from, to)
	if err != nil {
		return Message{}, false, err
	}
	scope := func(c store.IssueCount) bool { return issueInScope(r, c) }
	urgent := func(c store.IssueCount) bool { return urgentIssue(r, c) }
	newAssets := byAsset(news, scope, urgent)
	fixedAssets := byAsset(fixed, scope, nil)
	nNew, nUrgent := total(newAssets)
	nFixed, _ := total(fixedAssets)
	backAssets := byAsset(regressed, scope, nil)
	if !assetsWanted(r) {
		backAssets = nil
	}
	nBack, _ := total(backAssets)
	nGone := 0
	for _, c := range gone {
		if scope(c) {
			nGone += c.Count
		}
	}
	if !r.SendResolved {
		nFixed, fixedAssets, nGone = 0, nil, 0
	}
	var conn []store.NewAsset
	if assetsWanted(r) {
		for _, a := range connected {
			if assetInScope(r, a.ID, a.Environment, a.OwnerTeamID) {
				conn = append(conn, a)
			}
		}
	}
	// The issues lists show the summary's period (in whole days).
	days := strconv.Itoa(max(1, int(to.Sub(from).Hours()/24+0.5)))
	newQ, fixedQ := url.Values{"new_within": {days}}, url.Values{"status": {"resolved"}, "resolved_within": {days}}
	connIssues := 0
	for _, a := range conn {
		connIssues += a.Issues
	}
	counts := map[string]int{"new": nNew, "new_urgent": nUrgent, "fixed": nFixed, "connected": len(conn), "connected_issues": connIssues, "regressed": nBack,
		"no_longer_affected": nGone}
	var sections []Section

	if len(backAssets) > 0 {
		var items []Item
		q := url.Values{"state": {"regressed"}}
		for i, a := range backAssets {
			if i == maxAssetItems {
				items = append(items, moreAssets(len(backAssets)-maxAssetItems, "with issues that came back", d.findingsURL(0, q)))
				break
			}
			items = append(items, Item{Text: fmt.Sprintf("%s: %s", a.Name, cameBack(a.Count)), Link: d.findingsURL(a.ID, q), asset: a.ID})
		}
		sections = append(sections, Section{Title: "Came back after a fix", Items: items})
	}

	if len(newAssets) > 0 {
		var items []Item
		for i, a := range newAssets {
			if i == maxAssetItems {
				items = append(items, moreAssets(len(newAssets)-maxAssetItems, "with new issues", d.findingsURL(0, newQ)))
				break
			}
			items = append(items, Item{Text: fmt.Sprintf("%s: %s%s", a.Name, plural(a.Count, "new issue"), detail(countIf(a.Urgent, "urgent"))),
				Link: d.findingsURL(a.ID, newQ), asset: a.ID})
		}
		sections = append(sections, Section{Title: "New issues", Items: items})
	}
	if len(conn) > 0 {
		var ids []int64
		for _, a := range conn {
			ids = append(ids, a.ID)
		}
		byA := map[int64][]store.FixInfo{}
		for _, f := range data.fixes {
			byA[f.AssetID] = append(byA[f.AssetID], f)
		}
		sections = append(sections, Section{Title: "Connected", Items: d.connectedItems(conn, byA)})
	}
	if len(fixedAssets) > 0 {
		var items []Item
		for i, a := range fixedAssets {
			if i == maxAssetItems {
				items = append(items, moreAssets(len(fixedAssets)-maxAssetItems, "with fixed issues", d.findingsURL(0, fixedQ)))
				break
			}
			items = append(items, Item{Text: fixedText(a), Link: d.findingsURL(a.ID, fixedQ), asset: a.ID})
		}
		sections = append(sections, Section{Title: "Fixed", Items: items})
	}
	if nGone > 0 {
		text := fmt.Sprintf("%s closed without a fix: the advisory was withdrawn or no longer lists the installed version", plural(nGone, "issue"))
		item := Item{Text: text, Link: d.findingsURL(0, fixedQ)}
		if len(sections) > 0 && sections[len(sections)-1].Title == "Fixed" {
			sections[len(sections)-1].Items = append(sections[len(sections)-1].Items, item)
		} else {
			sections = append(sections, Section{Title: "Fixed", Items: []Item{item}})
		}
	}

	// The top fixes still open, for this route's assets.
	var open []store.FixInfo
	for _, f := range data.fixes {
		if assetInScope(r, f.AssetID, f.Environment, f.OwnerTeamID) && (!r.SOSOnly || f.SOS) {
			open = append(open, f)
		}
	}
	counts["open_fixes"] = len(open)
	if len(open) > 0 && (assetsWanted(r) || r.SOSOnly) {
		var items []Item
		for i, f := range open {
			if i == maxFixItems {
				items = append(items, Item{Text: fmt.Sprintf("+%s", plural(len(open)-maxFixItems, "more fix")), Link: d.planURL(0)})
				break
			}
			items = append(items, d.fixItem(fmt.Sprintf("%s on %s (clears %s)", f.Title, shorten(f.AssetName, maxNameLen), plural(f.FindingCount, "issue")),
				f.ID, f.AssetID))
		}
		sections = append(sections, Section{Title: "Top fixes still open", Items: items})
	}

	newlyOverdue := 0
	if withOverdue {
		over, err := data.counts(store.IssuesOverdue, to, to)
		if err != nil {
			return Message{}, false, err
		}
		recent, err := data.counts(store.IssuesNewlyOverdue, from, to)
		if err != nil {
			return Message{}, false, err
		}
		ack, err := data.counts(store.IssuesAckOverdue, to, to)
		if err != nil {
			return Message{}, false, err
		}
		for _, c := range recent {
			if scope(c) {
				newlyOverdue += c.Count
			}
		}
		fixItems, n, _ := d.overdueFixItems(over, scope, data.infos)
		nUrg := 0
		for _, c := range over {
			if scope(c) && overdueUrgent(c.Priority, c.SOS) {
				nUrg += c.Count
			}
		}
		nAck := 0
		for _, c := range ack {
			if scope(c) {
				nAck += c.Count
			}
		}
		counts["overdue"], counts["overdue_urgent"], counts["ack_overdue"] = n, nUrg, nAck
		if n > 0 || nAck > 0 {
			var items []Item
			if n > 0 {
				items = append(items, Item{Text: fmt.Sprintf("%s past the fix deadline%s", plural(n, "issue"), detail(countIf(nUrg, "urgent"))),
					Link: d.findingsURL(0, url.Values{"overdue": {"true"}}), Items: fixItems})
			}
			if nAck > 0 {
				items = append(items, Item{Text: fmt.Sprintf("%s not acknowledged in time", plural(nAck, "issue")),
					Link: d.findingsURL(0, url.Values{"state": {"new"}})})
			}
			sections = append(sections, Section{Title: "Overdue", Items: items})
		}
	}

	// Problems with Stackurity's own data.
	var sys []store.Incident
	newSys := 0
	for _, in := range data.sys {
		if inScope(r, in) {
			sys = append(sys, in)
			if !in.CreatedAt.Before(from) {
				newSys++
			}
		}
	}
	if len(sys) > 0 {
		sections = append(sections, Section{Title: "Stackurity needs attention", Items: d.systemItems(sys)})
	}
	counts["problems"] = len(sys)

	// Updates available, for routes that asked: weekly summaries only,
	// after everything else, never a finding or an urgent item.
	nUpdates := 0
	if r.SummaryUpdates && weekly {
		all, err := data.updates()
		if err != nil {
			return Message{}, false, err
		}
		var mine []store.BehindInstall
		for _, b := range all {
			if assetInScope(r, b.AssetID, b.Environment, b.OwnerTeamID) {
				mine = append(mine, b)
			}
		}
		sum := store.SummarizeUpdates(mine, "", maxUpdateItems)
		nUpdates = sum.Counts["total"]
		for _, t := range store.UpdateTypes {
			counts["updates_"+t] = sum.Counts[t]
		}
		counts["updates"] = nUpdates
		if nUpdates > 0 {
			sections = append(sections, d.updatesSection(sum))
		}
	}

	period := "Daily"
	if weekly {
		period = "Weekly"
	}
	var parts []string
	if nBack > 0 {
		parts = append(parts, thousands(nBack)+" came back")
	}
	if nNew > 0 {
		parts = append(parts, plural(nNew, "new issue"))
	}
	if nFixed > 0 {
		parts = append(parts, thousands(nFixed)+" fixed")
	}
	if len(conn) > 0 {
		// A new asset's backlog is not news: "1 asset connected, 412 issues
		// found", never "412 new issues".
		p := plural(len(conn), "asset") + " connected"
		if connIssues > 0 {
			p += ", " + plural(connIssues, "issue") + " found"
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 && counts["overdue"] > 0 {
		parts = append(parts, thousands(counts["overdue"])+" overdue")
	}
	if len(parts) == 0 && nUpdates > 0 {
		parts = append(parts, plural(nUpdates, "update")+" available")
	}
	title := period + " summary"
	if len(parts) > 0 {
		title += ": " + strings.Join(parts, ", ")
	}
	if len(sections) == 0 {
		sections = []Section{{Items: []Item{{Text: "Nothing needs you right now", Link: d.homeURL()}}}}
	}
	m := d.grouped(r, EventSummary, title, sections)
	m.Period = &Period{From: from.UTC(), To: to.UTC()}
	m.Counts = counts
	changed := nNew > 0 || nFixed > 0 || nGone > 0 || len(conn) > 0 || newlyOverdue > 0 || newSys > 0 || nBack > 0
	// Updates are a standing list, not news: they send a weekly summary
	// on their own.
	changed = changed || nUpdates > 0
	return m, changed, nil
}

const maxUpdateItems = 10 // packages listed under Updates available

// updatesSection lists the updates available: counts by update type, then
// the packages with the most installs behind, each linking to its page.
func (d *Dispatcher) updatesSection(sum store.UpdatesSummary) Section {
	var kinds []string
	for _, t := range []string{"major", "minor", "patch"} {
		if n := sum.Counts[t]; n > 0 {
			kinds = append(kinds, thousands(n)+" "+t)
		}
	}
	items := []Item{{Text: fmt.Sprintf("%s behind the latest stable release (%s), in %s; none fixes a known vulnerability",
		plural(sum.Counts["total"], "install"), strings.Join(kinds, ", "), plural(sum.Components, "package")),
		Link: d.url("/components/updates", nil)}}
	for _, c := range sum.Top {
		items = append(items, Item{Text: updateText(c), Link: d.url("/components/"+strconv.FormatInt(c.ComponentID, 10), nil)})
	}
	if more := sum.Components - len(sum.Top); more > 0 {
		items = append(items, Item{Text: fmt.Sprintf("+%s", plural(more, "more package")), Link: d.url("/components/updates", nil)})
	}
	return Section{Title: "Updates available", Items: items}
}

// updateText: "bootstrap 5.3.3 → 5.3.8 (patch) on 4 assets", or with
// several versions "lodash 4.17.15, 4.17.20 → 4.17.21 (patch), 6 installs
// on 4 assets".
func updateText(c store.ComponentUpdate) string {
	name := c.Name
	if c.Namespace != "" {
		name = c.Namespace + "/" + c.Name
	}
	versions := strings.Join(firstN(c.InstalledVersions, 3), ", ")
	if n := len(c.InstalledVersions) - 3; n > 0 {
		versions += fmt.Sprintf(" +%d", n)
	}
	where := " on " + plural(c.Assets, "asset")
	if c.Installs != c.Assets {
		where = ", " + plural(c.Installs, "install") + where
	}
	return fmt.Sprintf("%s %s → %s (%s)%s", shorten(name, maxNameLen), versions, c.LatestStable, c.UpdateType, where)
}

// fixedText: "commmerceblog: 1,240 closed after Install security updates
// and reboot", naming the fix that closed most of them.
func fixedText(a *assetIssues) string {
	best, n := "", 0
	for t, c := range a.Titles {
		if c > n || c == n && t < best {
			best, n = t, c
		}
	}
	switch {
	case best == "":
		return fmt.Sprintf("%s: %s closed", a.Name, thousands(a.Count))
	case n == a.Count:
		return fmt.Sprintf("%s: %s closed after %s", a.Name, thousands(a.Count), best)
	default:
		return fmt.Sprintf("%s: %s closed, %s of them after %s", a.Name, thousands(a.Count), thousands(n), best)
	}
}
