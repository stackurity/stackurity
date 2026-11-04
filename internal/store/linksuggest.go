package store

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Suggested links between a deployed application and the repository it
// was probably built from, for applications no built_from relation links
// yet (no Git checkout on the server, or a repository scanned without its
// remote). Nothing is linked until someone confirms a suggestion.
//
// A suggestion is scored from what the server already holds:
//
//   - the same package name: a name the application's manifests give it
//     (or its Flutter build's package name) is one the repository's
//     manifests give it (the package_names attribute), weight 0.6. Generic
//     names ("app", "server", "frontend"...) do not count;
//   - the share of direct dependencies that match: over the union of the
//     direct dependencies both have, a component both have at a common
//     version counts 1 and one both have at different versions 0.5,
//     weight 0.5. It counts only when at least 3 components match at the
//     same version, so a handful of common libraries is not a match;
//   - name similarity, weight 0.1: the share of name words (from the
//     asset names, the application's directory, the repository's remote
//     and the package names) they have in common. It only breaks ties.
//
// A suggestion is shown at a score of 0.45 or more (LinkSuggestionMin):
// the same package name alone, or at least 90% of direct dependencies
// matching (70% when the names are alike too). Name similarity alone
// never is. On the test data (linksuggest_test.go, modelled on a real
// estate) the right pairs score 0.5 to 0.65 and the closest wrong pair
// 0.12. An application gets at most 3 suggestions, best first.
const (
	LinkSuggestionMin  = 0.45
	MaxLinkSuggestions = 3
	// linkMinShared is how many components must match at the same version
	// before the dependency share counts.
	linkMinShared = 3
	// linkCandidates bounds the applications considered on a
	// repository's page.
	linkCandidates = 50
)

// LinkSuggestion proposes that Application is built from Repository.
type LinkSuggestion struct {
	Application LinkAsset `json:"application"`
	Repository  LinkAsset `json:"repository"`
	// Score is between 0 and 1; see LinkSuggestionMin.
	Score float64 `json:"score"`
	// SamePackageName is the name both give themselves ("npm:shop"), or
	// "" when they share none.
	SamePackageName string `json:"same_package_name,omitempty"`
	// DependencyMatchPercent is the share of direct dependencies that
	// match (0 when too few match to count); DependenciesMatched is how
	// many components match at the same version, of DependenciesCompared
	// (the union of both sides' direct dependencies).
	DependencyMatchPercent int  `json:"dependency_match_percent"`
	DependenciesMatched    int  `json:"dependencies_matched"`
	DependenciesCompared   int  `json:"dependencies_compared"`
	SimilarName            bool `json:"similar_name"`
}

// LinkAsset names one side of a suggestion.
type LinkAsset struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// linkSide is what scoring needs of one asset.
type linkSide struct {
	id      int64
	name    string
	attrs   map[string]string
	deps    map[int64]map[string]bool // direct component -> versions
	removed bool
}

// linkScore is the score of one application and repository pair.
type linkScore struct {
	score             float64
	samePackage       string
	depRatio          float64
	matched, compared int
	nameSim           float64
}

// genericNames are package or directory names too common to identify a
// project by.
var genericNames = map[string]bool{
	"app": true, "apps": true, "application": true, "web": true, "www": true, "site": true, "website": true,
	"server": true, "service": true, "services": true, "api": true, "backend": true, "frontend": true,
	"client": true, "ui": true, "src": true, "main": true, "root": true, "project": true, "my-app": true,
	"my-project": true, "test": true, "demo": true, "example": true, "html": true, "public": true,
	"current": true, "release": true, "releases": true, "build": true, "dist": true, "code": true, "repo": true,
	"on": true, "the": true, "git": true, "com": true, "www-data": true, "opt": true, "var": true, "srv": true,
}

// packageNames splits a package_names attribute.
func packageNames(attrs map[string]string) []string {
	var out []string
	for _, n := range strings.Split(attrs["package_names"], ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// distinctive reports whether a "type:name" package name can identify a
// project: not a generic one.
func distinctive(typed string) bool {
	_, name, _ := strings.Cut(typed, ":")
	return !genericNames[path.Base(name)]
}

var nameSplit = regexp.MustCompile(`[^a-z0-9]+`)

// nameWords are the distinctive words an asset is known by.
func nameWords(s linkSide, app bool) map[string]bool {
	words := map[string]bool{}
	add := func(v string) {
		for _, w := range nameSplit.Split(strings.ToLower(v), -1) {
			if len(w) >= 3 && !genericNames[w] {
				words[w] = true
			}
		}
	}
	name := s.name
	if app {
		// "shop on web-1" and "ghost (/6.52.0) on blog": the host and the
		// path that tells duplicates apart are not the application's name.
		if h := s.attrs["host"]; h != "" {
			name = strings.TrimSuffix(name, " on "+h)
		}
		if i := strings.Index(name, " ("); i > 0 {
			name = name[:i]
		}
		if d := s.attrs["app_dir"]; d != "" {
			add(path.Base(d))
		}
	} else if u := s.attrs["git_url"]; u != "" {
		add(path.Base(u))
	}
	add(name)
	for _, n := range packageNames(s.attrs) {
		_, pn, _ := strings.Cut(n, ":")
		add(path.Base(pn))
	}
	return words
}

// scoreLink scores the pair: app is probably built from repo when the
// score reaches LinkSuggestionMin.
func scoreLink(app, repo linkSide) linkScore {
	var r linkScore
	repoNames := map[string]bool{}
	for _, n := range packageNames(repo.attrs) {
		repoNames[n] = true
	}
	for _, n := range packageNames(app.attrs) {
		if repoNames[n] && distinctive(n) {
			r.samePackage = n
			break
		}
	}
	shared, sum := 0, 0.0
	for c, av := range app.deps {
		rv, ok := repo.deps[c]
		if !ok {
			continue
		}
		same := false
		for v := range av {
			same = same || rv[v]
		}
		if same {
			r.matched++
			sum++
		} else {
			sum += 0.5
		}
		shared++
	}
	r.compared = len(app.deps) + len(repo.deps) - shared
	if r.matched >= linkMinShared && r.compared > 0 {
		r.depRatio = sum / float64(r.compared)
	}
	aw, rw := nameWords(app, true), nameWords(repo, false)
	common := 0
	for w := range aw {
		if rw[w] {
			common++
		}
	}
	if union := len(aw) + len(rw) - common; union > 0 {
		r.nameSim = float64(common) / float64(union)
	}
	if r.samePackage != "" {
		r.score += 0.6
	}
	r.score += 0.5*r.depRatio + 0.1*r.nameSim
	r.score = math.Round(r.score*1000) / 1000
	return r
}

// LinkSuggestions returns the suggested built_from links for an asset: for
// an application without one, the repositories it is probably built from;
// for a repository, the applications without one that it is among the
// suggestions of. Dismissed pairs are left out. Row-level security
// narrows both sides to what the caller may see.
func (s *Store) LinkSuggestions(ctx context.Context, assetID int64) ([]LinkSuggestion, error) {
	var kind string
	if err := s.Pool.QueryRow(ctx, `SELECT kind FROM assets WHERE id = $1 AND merged_into IS NULL`, assetID).Scan(&kind); err != nil {
		return nil, notFound(err)
	}
	out := []LinkSuggestion{}
	switch kind {
	case "application":
		return s.appSuggestions(ctx, assetID)
	case "repository":
		apps, err := s.linkCandidates(ctx, assetID, "application")
		if err != nil {
			return nil, err
		}
		for _, a := range apps {
			sugg, err := s.appSuggestions(ctx, a)
			if err != nil {
				return nil, err
			}
			for _, sg := range sugg {
				if sg.Repository.ID == assetID {
					out = append(out, sg)
				}
			}
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	}
	return out, nil
}

// appSuggestions are the repositories an application is probably built
// from, best first; none when a built_from relation links it already.
func (s *Store) appSuggestions(ctx context.Context, appID int64) ([]LinkSuggestion, error) {
	out := []LinkSuggestion{}
	var linked bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM asset_relations WHERE from_asset = $1 AND kind = 'built_from')`,
		appID).Scan(&linked); err != nil || linked {
		return out, err
	}
	repos, err := s.linkCandidates(ctx, appID, "repository")
	if err != nil || len(repos) == 0 {
		return out, err
	}
	sides, err := s.linkSides(ctx, append([]int64{appID}, repos...))
	if err != nil {
		return nil, err
	}
	app := sides[appID]
	if app == nil || app.removed {
		return out, nil
	}
	for _, id := range repos {
		repo := sides[id]
		if repo == nil || repo.removed {
			continue
		}
		sc := scoreLink(*app, *repo)
		if sc.score < LinkSuggestionMin {
			continue
		}
		out = append(out, LinkSuggestion{
			Application: LinkAsset{ID: app.id, Name: app.name}, Repository: LinkAsset{ID: repo.id, Name: repo.name},
			Score: sc.score, SamePackageName: sc.samePackage, DependencyMatchPercent: int(math.Round(sc.depRatio * 100)),
			DependenciesMatched: sc.matched, DependenciesCompared: sc.compared, SimilarName: sc.nameSim >= 0.5,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Repository.ID < out[j].Repository.ID
	})
	if len(out) > MaxLinkSuggestions {
		out = out[:MaxLinkSuggestions]
	}
	return out, nil
}

// linkCandidates are the assets of the other kind that could pair with
// assetID: those sharing a direct dependency with it, or a package name,
// not dismissed with it, and for applications, not linked to a repository
// already. Anything else cannot reach the threshold.
func (s *Store) linkCandidates(ctx context.Context, assetID int64, kind string) ([]int64, error) {
	appSide := "c.id"
	repoSide := "$1::bigint"
	if kind == "repository" {
		appSide, repoSide = "$1::bigint", "c.id"
	}
	rows, err := s.Pool.Query(ctx, fmt.Sprintf(`
		WITH me AS (SELECT attributes FROM assets WHERE id = $1),
		mine AS (SELECT DISTINCT component_id FROM inventory WHERE asset_id = $1 AND direct AND removed_at IS NULL)
		SELECT c.id FROM assets c
		WHERE c.kind = $2 AND c.merged_into IS NULL AND c.collection_status <> 'removed' AND c.id <> $1
		  AND (EXISTS (SELECT 1 FROM inventory i JOIN mine m ON m.component_id = i.component_id
		               WHERE i.asset_id = c.id AND i.direct AND i.removed_at IS NULL)
		    OR string_to_array(NULLIF(c.attributes->>'package_names', ''), ',')
		       && string_to_array(NULLIF((SELECT attributes->>'package_names' FROM me), ''), ','))
		  AND NOT EXISTS (SELECT 1 FROM link_suggestion_dismissals d WHERE d.app_id = %s AND d.repo_id = %s)
		  AND ($2 <> 'application' OR NOT EXISTS (SELECT 1 FROM asset_relations r WHERE r.from_asset = c.id AND r.kind = 'built_from'))
		ORDER BY c.id LIMIT %d`, appSide, repoSide, linkCandidates), assetID, kind)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// linkSides loads the names, attributes and direct dependencies of assets.
func (s *Store) linkSides(ctx context.Context, ids []int64) (map[int64]*linkSide, error) {
	out := map[int64]*linkSide{}
	rows, err := s.Pool.Query(ctx, `SELECT id, name, attributes, collection_status = 'removed' FROM assets WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ls linkSide
		var attrs []byte
		if err := rows.Scan(&ls.id, &ls.name, &attrs, &ls.removed); err != nil {
			rows.Close()
			return nil, err
		}
		ls.attrs = map[string]string{}
		_ = json.Unmarshal(attrs, &ls.attrs)
		ls.deps = map[int64]map[string]bool{}
		out[ls.id] = &ls
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = s.Pool.Query(ctx, `SELECT DISTINCT asset_id, component_id, version FROM inventory
		WHERE asset_id = ANY($1) AND direct AND removed_at IS NULL`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a, c int64
		var v string
		if err := rows.Scan(&a, &c, &v); err != nil {
			return nil, err
		}
		if side := out[a]; side != nil {
			if side.deps[c] == nil {
				side.deps[c] = map[string]bool{}
			}
			side.deps[c][v] = true
		}
	}
	return out, rows.Err()
}

// LinkPair orders two assets as (application, repository), or fails when
// they are not one of each.
func (s *Store) LinkPair(ctx context.Context, a, b int64) (app, repo int64, err error) {
	kinds := map[int64]string{}
	rows, err := s.Pool.Query(ctx, `SELECT id, kind FROM assets WHERE id = ANY($1) AND merged_into IS NULL`, []int64{a, b})
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var k string
		if err := rows.Scan(&id, &k); err != nil {
			return 0, 0, err
		}
		kinds[id] = k
	}
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	if len(kinds) != 2 {
		return 0, 0, ErrNotFound
	}
	switch {
	case kinds[a] == "application" && kinds[b] == "repository":
		return a, b, nil
	case kinds[a] == "repository" && kinds[b] == "application":
		return b, a, nil
	}
	return 0, 0, fmt.Errorf("a suggested link joins an application and a repository: %w", ErrInvalid)
}

// AcceptLinkSuggestion links an application to its repository
// (built_from), recorded as confirmed by who, and forgets any dismissal
// of the pair.
func (s *Store) AcceptLinkSuggestion(ctx context.Context, app, repo int64, who string) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO asset_relations (from_asset, to_asset, kind, source) VALUES ($1, $2, 'built_from', $3)
			ON CONFLICT DO NOTHING`, app, repo, "confirmed:"+who); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM link_suggestion_dismissals WHERE app_id = $1 AND repo_id = $2`, app, repo)
		return err
	})
}

// DismissLinkSuggestion records that an application is not built from a
// repository, so the pair is not suggested again.
func (s *Store) DismissLinkSuggestion(ctx context.Context, app, repo int64, userID *int64) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO link_suggestion_dismissals (app_id, repo_id, dismissed_by) VALUES ($1, $2, $3)
		ON CONFLICT (workspace_id, app_id, repo_id) DO NOTHING`, app, repo, userID)
	return err
}
