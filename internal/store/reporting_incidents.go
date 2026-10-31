package store

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Reporting incidents (0.13.10) replace "Asset X has stopped reporting":
// one incident per cause (the agent, a scan, an upload), kind of asset,
// owner team and day the assets went quiet, keyed
// reporting:<cause>:<kind>:<YYYY-MM-DD>. Applications on a silent server are
// listed in the server's incident. An asset reported once by a scan or
// upload, or reported by an integration, never opens one.

// flapWindow: an asset that goes quiet again this soon after its incident
// closed reopens that incident rather than announcing a new one.
const flapWindow = 24 * time.Hour

// ReportingAsset is one asset in a reporting incident's detail.
type ReportingAsset struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Kind         string    `json:"kind"`
	Environment  string    `json:"environment,omitempty"`
	LastSeen     time.Time `json:"last_seen"`
	UsualSeconds int64     `json:"usual_seconds,omitempty"`
	Override     string    `json:"override,omitempty"`
	Production   bool      `json:"production,omitempty"`
	// OS is "windows" for a Windows agent, "linux" for a Linux one.
	OS string `json:"os,omitempty"`
	// Applications are the applications read on this server, silent with it.
	Applications []string `json:"applications,omitempty"`
}

type quietAsset struct {
	ReportingAsset
	team   *int64
	source string
	host   int64 // the stale server an application runs on
	appIDs []int64
}

// reportingProblems finds the assets that are overdue and groups them.
func (s *Store) reportingProblems(ctx context.Context) ([]SystemIncident, error) {
	due := strings.ReplaceAll(dueSQL, "$1", "$2")
	rows, err := s.Pool.Query(ctx, `SELECT a.id, a.kind, a.name, a.environment, a.owner_team_id, a.last_seen, a.report_source,
		  a.report_override, COALESCE(EXTRACT(epoch FROM a.report_usual)::bigint, 0), `+productionAsset+`,
		  COALESCE((SELECT c.collector_id FROM collections c WHERE c.asset_id = a.id ORDER BY c.received_at DESC, c.id DESC LIMIT 1), ''),
		  COALESCE((SELECT min(r.to_asset) FROM asset_relations r JOIN assets h ON h.id = r.to_asset
		    WHERE r.from_asset = a.id AND r.kind = 'runs_on' AND h.merged_into IS NULL AND h.collection_status = 'stale'
		      AND h.report_source = 'agent'), 0)
		FROM assets a
		WHERE a.merged_into IS NULL AND a.collection_status = 'stale' AND a.report_source IN ('agent', 'scan', 'manual')
		  AND `+due+` IS NOT NULL AND a.last_seen < now() - `+due+`
		ORDER BY a.last_seen, a.id`, defaultProductionEnvs(), s.staleAfter().Seconds())
	if err != nil {
		return nil, err
	}
	var all []*quietAsset
	byID := map[int64]*quietAsset{}
	for rows.Next() {
		a := &quietAsset{}
		var collector string
		if err := rows.Scan(&a.ID, &a.Kind, &a.Name, &a.Environment, &a.team, &a.LastSeen, &a.source, &a.Override,
			&a.UsualSeconds, &a.Production, &collector, &a.host); err != nil {
			rows.Close()
			return nil, err
		}
		if a.Override == ReportAuto {
			a.Override = ""
		}
		if a.source == SourceAgent {
			a.OS = "linux"
			if strings.HasPrefix(collector, "windows") {
				a.OS = "windows"
			}
		}
		all = append(all, a)
		byID[a.ID] = a
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Applications on a silent server are part of its incident.
	var members []*quietAsset
	for _, a := range all {
		if h := byID[a.host]; a.Kind == "application" && h != nil && h.Kind == "host" {
			h.Applications = append(h.Applications, a.Name)
			h.appIDs = append(h.appIDs, a.ID)
			continue
		}
		members = append(members, a)
	}
	if len(members) == 0 {
		return nil, nil
	}

	// An asset back for less than a day reopens its last incident.
	ids := make([]int64, len(members))
	for i, a := range members {
		ids[i] = a.ID
	}
	reopen := map[int64]struct {
		id  int64
		key string
	}{}
	rows, err = s.Pool.Query(ctx, `SELECT DISTINCT ON (m.id) m.id, i.id, i.key
		FROM unnest($1::bigint[]) AS m(id) JOIN assets a ON a.id = m.id
		JOIN incidents i ON i.kind = 'collection' AND i.status = 'resolved' AND i.key LIKE 'reporting:%'
		  AND i.resolved_at > now() - interval '30 days' AND NOT i.detail ? 'resolution'
		  AND i.detail->'asset_ids' @> to_jsonb(m.id) AND a.last_seen <= i.resolved_at + make_interval(secs => $2)
		ORDER BY m.id, i.resolved_at DESC`, ids, flapWindow.Seconds())
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var m, id int64
		var key string
		if err := rows.Scan(&m, &id, &key); err != nil {
			rows.Close()
			return nil, err
		}
		reopen[m] = struct {
			id  int64
			key string
		}{id, key}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	type group struct {
		key    string
		team   *int64
		cause  string
		kind   string
		reopen int64
		assets []*quietAsset
	}
	groups := map[string]*group{}
	var order []string
	for _, a := range members {
		cause := map[string]string{SourceAgent: "agent", SourceScan: "scan", SourceManual: "upload"}[a.source]
		key := fmt.Sprintf("reporting:%s:%s:%s", cause, a.Kind, a.LastSeen.UTC().Format("2006-01-02"))
		var re int64
		if r, ok := reopen[a.ID]; ok {
			key, re = r.key, r.id
		}
		gk := key + "|" + teamKey(a.team)
		g := groups[gk]
		if g == nil {
			g = &group{key: key, team: a.team, cause: cause, kind: a.Kind, reopen: re}
			groups[gk] = g
			order = append(order, gk)
		}
		g.assets = append(g.assets, a)
	}

	now := time.Now()
	var out []SystemIncident
	for _, gk := range order {
		g := groups[gk]
		pri, digest := "P4", true
		var list []ReportingAsset
		var assetIDs, memberIDs []int64
		envs := map[string]bool{}
		since := g.assets[0].LastSeen
		apps := 0
		for _, a := range g.assets {
			switch g.cause {
			case "agent":
				digest = false
				if a.Production {
					pri = "P3"
				}
			case "scan":
				// A learned cadence alone never makes it urgent: only a
				// production asset someone set to daily or weekly.
				if a.Production && (a.Override == ReportDaily || a.Override == ReportWeekly) {
					pri, digest = "P3", false
				}
			}
			if a.LastSeen.Before(since) {
				since = a.LastSeen
			}
			if a.Environment != "" {
				envs[a.Environment] = true
			}
			apps += len(a.Applications)
			list = append(list, a.ReportingAsset)
			assetIDs = append(append(assetIDs, a.ID), a.appIDs...)
			memberIDs = append(memberIDs, append([]int64{a.ID}, a.appIDs...)...)
		}
		var envList []string
		for e := range envs {
			envList = append(envList, e)
		}
		sort.Strings(envList)
		detail := map[string]any{
			"cause": g.cause, "asset_kind": g.kind, "since": since, "assets": list, "asset_ids": assetIDs,
			"environments": envList,
		}
		if digest {
			detail["digest_only"] = true
		}
		out = append(out, SystemIncident{Kind: "collection", Key: g.key, OwnerTeamID: g.team, Priority: pri,
			Title: ReportingTitle(g.cause, g.kind, list, since, apps, now), Detail: detail, Reopen: g.reopen, Members: memberIDs})
	}
	return out, nil
}

func teamKey(t *int64) string {
	if t == nil {
		return "0"
	}
	return strconv.FormatInt(*t, 10)
}

// AssetNoun is how a kind of asset is named to people: "server" for a host,
// "SBOM" for an SBOM.
func AssetNoun(kind string, n int) string {
	one, many := kind, kind+"s"
	switch kind {
	case "host":
		one, many = "server", "servers"
	case "repository":
		one, many = "repository", "repositories"
	case "sbom":
		one, many = "SBOM", "SBOMs"
	case "managed_service":
		one, many = "managed service", "managed services"
	}
	if n == 1 {
		return one
	}
	return many
}

func capitalize(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ReportDate is "26 Oct", with the year when it is not this one's.
func ReportDate(t, now time.Time) string {
	t = t.UTC()
	if t.Year() != now.UTC().Year() {
		return t.Format("2 Jan 2006")
	}
	return t.Format("2 Jan")
}

// ReportTime is "29 Oct 14:05 UTC".
func ReportTime(t, now time.Time) string {
	return ReportDate(t, now) + " " + t.UTC().Format("15:04") + " UTC"
}

// Every is a reporting cadence in words: "day", "6 hours", "week", "3 days".
func Every(d time.Duration) string {
	h := d.Hours()
	switch {
	case h >= 20 && h <= 28:
		return "day"
	case h < 36:
		n := int(h + 0.5)
		if n <= 1 {
			return "hour"
		}
		return fmt.Sprintf("%d hours", n)
	}
	days := int(h/24 + 0.5)
	switch {
	case days == 7:
		return "week"
	case days%7 == 0:
		return fmt.Sprintf("%d weeks", days/7)
	}
	return fmt.Sprintf("%d days", days)
}

// ReportingTitle titles a reporting incident. It names the kind of asset
// (server, repository, image), never "asset".
func ReportingTitle(cause, kind string, list []ReportingAsset, since time.Time, apps int, now time.Time) string {
	n := len(list)
	noun := AssetNoun(kind, n)
	switch cause {
	case "agent":
		who := ""
		if n == 1 {
			who = capitalize(noun) + " " + list[0].Name
		} else {
			who = fmt.Sprintf("%d %s", n, noun)
		}
		if apps > 0 {
			their := "its"
			if n > 1 {
				their = "their"
			}
			who += fmt.Sprintf(" and %s %d %s", their, apps, AssetNoun("application", apps))
		}
		when := ReportDate(since, now)
		if n == 1 {
			when = ReportTime(since, now)
		}
		if kind == "host" {
			return fmt.Sprintf("%s: the Stackurity agent hasn't reported since %s", who, when)
		}
		it := "it"
		if n > 1 {
			it = "them"
		}
		return fmt.Sprintf("%s: the Stackurity agent hasn't reported %s since %s", who, it, when)
	default:
		verb := "scanned"
		if cause == "upload" {
			verb = "uploaded"
		}
		if n > 1 {
			return fmt.Sprintf("%d %s haven't been %s since %s", n, noun, verb, ReportDate(since, now))
		}
		a := list[0]
		t := fmt.Sprintf("%s %s hasn't been %s since %s", capitalize(noun), a.Name, verb, ReportDate(since, now))
		switch {
		case a.Override == ReportDaily:
			t += " (expected daily)"
		case a.Override == ReportWeekly:
			t += " (expected weekly)"
		case a.UsualSeconds > 0:
			t += " (usually every " + Every(time.Duration(a.UsualSeconds)*time.Second) + ")"
		}
		return t
	}
}

// settleLegacyReporting runs inside SyncSystemIncidents. Open per-asset
// incidents from before 0.13.10 (collection, asset:<id>) are replaced by the
// reporting incident that now lists their asset, closed with "replaced"
// (Jira, PagerDuty and ServiceNow say "Replaced by incident #N"); those of
// assets no longer expected to report (one-off, an integration's) close
// with that reason. When every asset of a new reporting incident had
// already been announced that way, people are not told again
// (people_announced), though a tracker still gets its issue.
func settleLegacyReporting(ctx context.Context, tx pgx.Tx, c SystemIncident, id int64, inserted bool) error {
	if len(c.Members) == 0 {
		return nil
	}
	legacy := make([]string, len(c.Members))
	for i, m := range c.Members {
		legacy[i] = "asset:" + strconv.FormatInt(m, 10)
	}
	// Applications folded into a server had no incident of their own
	// before only if their server's covered them; the servers decide.
	var servers []string
	if list, ok := c.Detail["assets"].([]ReportingAsset); ok {
		for _, a := range list {
			servers = append(servers, "asset:"+strconv.FormatInt(a.ID, 10))
		}
	}
	if inserted && len(servers) > 0 {
		var announced int
		if err := tx.QueryRow(ctx, `SELECT count(DISTINCT key) FROM incidents
			WHERE status = 'open' AND kind = 'collection' AND key = ANY($1) AND notified_at IS NOT NULL`, servers).Scan(&announced); err != nil {
			return err
		}
		if announced == len(servers) {
			if _, err := tx.Exec(ctx, `UPDATE incidents SET detail = detail || '{"people_announced": true}' WHERE id = $1`, id); err != nil {
				return err
			}
		}
	}
	_, err := tx.Exec(ctx, `UPDATE incidents SET status = 'resolved', resolved_at = now(), updated_at = now(), resolved_notified = true,
		detail = detail || jsonb_build_object('resolution', 'replaced', 'replaced_by', $2::bigint)
		WHERE status = 'open' AND kind = 'collection' AND key = ANY($1)`, legacy, id)
	return err
}
