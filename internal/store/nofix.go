package store

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/stackurity/stackurity/internal/fixplan"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/version"
)

// NoFixContext returns what the planner says about application-package
// findings with no fixed version (fixplan.AdviseNoFix): where each was
// found, the package's release data, another package its advisories list
// with a fixed version, and the advisories' own workaround. All of it is
// stored data; nothing is fetched.
func (s *Store) NoFixContext(ctx context.Context, findingIDs []int64) ([]fixplan.NoFixFinding, error) {
	if len(findingIDs) == 0 {
		return nil, nil
	}
	rows, err := s.Pool.Query(ctx, `SELECT f.id, f.key, c.type,
		  CASE WHEN c.namespace = '' THEN c.name ELSE c.namespace || '/' || c.name END, i.version, i.location, i.direct, i.purl,
		  COALESCE(f.evidence->>'target_ecosystem', ''), COALESCE(f.evidence->>'osv_package', ''), f.sources,
		  a.kind, a.name, COALESCE(a.attributes->>'host', ''), COALESCE(a.attributes->>'app_dir', ''),
		  COALESCE(a.attributes->>'app_version', ''),
		  COALESCE(r.deprecated, ''), COALESCE(r.latest_stable, ''), r.latest_published
		FROM findings f JOIN inventory i ON i.id = f.inventory_id JOIN components c ON c.id = f.component_id
		JOIN assets a ON a.id = f.asset_id
		LEFT JOIN package_releases r ON r.component_id = f.component_id
		WHERE f.id = ANY($1) ORDER BY f.id`, findingIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type extra struct {
		eco, osvName string
		sources      []string
	}
	var out []fixplan.NoFixFinding
	var extras []extra
	for rows.Next() {
		var f fixplan.NoFixFinding
		var e extra
		var purl, assetKind, assetName, host string
		if err := rows.Scan(&f.FindingID, &f.Key, &f.PurlType, &f.Component, &f.Version, &f.Location, &f.Direct, &purl,
			&e.eco, &e.osvName, &e.sources, &assetKind, &assetName, &host, &f.AppDir, &f.AppVersion,
			&f.Deprecated, &f.LatestStable, &f.LatestPublished); err != nil {
			return nil, err
		}
		if e.eco == "" || e.osvName == "" {
			if t, ok := osv.TargetFor(purl, f.Version, nil); ok {
				e.eco, e.osvName = t.Ecosystem, t.Name
			}
		}
		if assetKind == "application" {
			f.App = appLabel(assetName, host)
		} else {
			f.AppDir = ""
		}
		out = append(out, f)
		extras = append(extras, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()

	// The other packages the findings' advisories list, in the same base
	// ecosystems, and the advisories' workarounds.
	var ids []string
	bases := map[string]bool{}
	for _, e := range extras {
		ids = append(ids, e.sources...)
		if e.eco != "" {
			bases[osv.BaseEcosystem(e.eco)] = true
		}
	}
	type pkg struct {
		base, name string
		affected   osv.Affected
	}
	byAdvisory := map[string][]pkg{}
	workaround := map[string]string{}
	if len(ids) > 0 {
		pr, err := s.Pool.Query(ctx, `SELECT p.advisory_id, p.base_ecosystem, p.name, `+affectedColumn+`
			FROM advisory_packages p `+affectedJoin+`
			WHERE p.advisory_id = ANY($1) AND p.base_ecosystem = ANY($2) ORDER BY p.advisory_id, p.ctid`, ids, sortedSet(bases))
		if err != nil {
			return nil, err
		}
		for pr.Next() {
			var id string
			var p pkg
			var aff []byte
			if err := pr.Scan(&id, &p.base, &p.name, &aff); err != nil {
				pr.Close()
				return nil, err
			}
			if json.Unmarshal(aff, &p.affected) == nil {
				byAdvisory[id] = append(byAdvisory[id], p)
			}
		}
		pr.Close()
		if err := pr.Err(); err != nil {
			return nil, err
		}
		wr, err := s.Pool.Query(ctx, `SELECT id, details FROM advisories WHERE id = ANY($1) AND details <> '' AND withdrawn IS NULL`, ids)
		if err != nil {
			return nil, err
		}
		for wr.Next() {
			var id, d string
			if err := wr.Scan(&id, &d); err != nil {
				wr.Close()
				return nil, err
			}
			workaround[id] = d
		}
		wr.Close()
		if err := wr.Err(); err != nil {
			return nil, err
		}
	}
	for i := range out {
		f, e := &out[i], extras[i]
		srcs := append([]string(nil), e.sources...)
		sort.Strings(srcs)
		for _, id := range srcs {
			if w := workaround[id]; w != "" && f.Workaround == "" {
				f.Workaround, f.Advisory = w, id
			}
		}
		if e.eco == "" {
			continue
		}
		base := osv.BaseEcosystem(e.eco)
		cmp := version.For(version.ForPurlType(f.PurlType))
		pre := func(v string) bool { return version.Prerelease(version.ForPurlType(f.PurlType), v) }
		bestRank := -1
		for _, id := range srcs {
			for _, p := range byAdvisory[id] {
				if p.base != base || sameName(p.name, e.osvName) {
					continue
				}
				fixed := highestFixed(p.affected, cmp, pre)
				if fixed == "" {
					continue
				}
				r := nameRank(p.name, e.osvName)
				if r > bestRank || (r == bestRank && p.name < f.MoveTo) {
					bestRank, f.MoveTo, f.FixedIn = r, p.name, fixed
				}
			}
		}
	}
	// The application's own newest release, when release data has one for a
	// package of its name.
	type appKey struct{ typ, name string }
	latest := map[appKey]string{}
	for _, f := range out {
		k := appKey{f.PurlType, f.App}
		if _, done := latest[k]; done || f.App == "" {
			continue
		}
		ns, name := "", f.App
		if i := strings.LastIndex(f.App, "/"); i > 0 {
			ns, name = f.App[:i], f.App[i+1:]
		}
		var v string
		err := s.Pool.QueryRow(ctx, `SELECT COALESCE(max(r.latest_stable), '') FROM components c
			JOIN package_releases r ON r.component_id = c.id WHERE c.type = $1 AND c.namespace = $2 AND c.name = $3`,
			f.PurlType, ns, name).Scan(&v)
		if err != nil {
			return nil, err
		}
		latest[k] = v
	}
	for i := range out {
		out[i].AppLatest = latest[appKey{out[i].PurlType, out[i].App}]
	}
	return out, nil
}

// appLabel is the application's name as the agent gave it: the asset's
// name without " on <host>" and the " (/path)" that tells copies apart.
func appLabel(name, host string) string {
	if host != "" {
		name = strings.TrimSuffix(name, " on "+host)
	}
	if i := strings.LastIndex(name, " (/"); i > 0 && strings.HasSuffix(name, ")") {
		name = name[:i]
	}
	return name
}

// highestFixed is the highest fixed version an affected entry lists,
// preferring releases over pre-releases ("7.23.2" over "8.0.0-alpha.4").
func highestFixed(a osv.Affected, cmp version.Comparator, pre func(string) bool) string {
	best, bestPre := "", false
	for _, r := range a.Ranges {
		if r.Type == "GIT" {
			continue
		}
		for _, ev := range r.Events {
			v := ev.Fixed
			if v == "" {
				continue
			}
			p := pre(v)
			switch {
			case best == "":
			case bestPre && !p:
			case p && !bestPre:
				continue
			default:
				if c, err := cmp(v, best); err != nil || c <= 0 {
					continue
				}
			}
			best, bestPre = v, p
		}
	}
	return best
}

// normName folds the separators package names differ by: @babel/traverse
// and babel-traverse, lodash.pick and lodash-pick.
func normName(s string) string {
	s = strings.ToLower(strings.TrimPrefix(s, "@"))
	return strings.NewReplacer("/", "-", ".", "-", "_", "-", ":", "-").Replace(s)
}

func sameName(a, b string) bool { return strings.EqualFold(a, b) }

// nameRank prefers the package that is plainly the same project under a
// new name: the same name once separators are folded (babel-traverse,
// @babel/traverse), then one the other name starts with (lodash for
// lodash.pick), then any other.
func nameRank(candidate, own string) int {
	c, o := normName(candidate), normName(own)
	switch {
	case c == o:
		return 2
	case strings.HasPrefix(o, c+"-") || strings.HasPrefix(c, o+"-"):
		return 1
	}
	return 0
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
