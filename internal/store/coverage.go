package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Asset coverage states: whether an asset's lack of findings can be trusted.
// One vocabulary is used by the API, the dashboard and the docs
// (docs/compatibility.md, "Coverage states"). An asset can be in several;
// the headline is the most severe, in this order.
const (
	StateFailedCollection     = "failed_collection"
	StateStaleIntelligence    = "stale_intelligence"
	StatePartiallyEvaluated   = "partially_evaluated"
	StateUnsupported          = "unsupported"
	StateAwaitingVerification = "awaiting_verification"
	StateHealthy              = "healthy"
)

// StateLabels are the words shown for each state.
var StateLabels = map[string]string{
	StateFailedCollection:     "Failed collection",
	StateStaleIntelligence:    "Stale intelligence",
	StatePartiallyEvaluated:   "Partially evaluated",
	StateUnsupported:          "Unsupported",
	StateAwaitingVerification: "Awaiting verification",
	StateHealthy:              "Healthy and recently evaluated",
}

var stateOrder = []string{StateFailedCollection, StateStaleIntelligence, StatePartiallyEvaluated,
	StateUnsupported, StateAwaitingVerification, StateHealthy}

// RecentEvaluation is how old an asset's last evaluation may be for it to
// count as recently evaluated. Every asset is evaluated at least daily.
const RecentEvaluation = 48 * time.Hour

type CoverageState struct {
	State  string `json:"state"`
	Label  string `json:"label"`
	Detail string `json:"detail"`
}

// ComponentCoverage counts an asset's components by row coverage.
type ComponentCoverage struct {
	Total             int64 `json:"total"`
	Evaluated         int64 `json:"evaluated"`
	StaleIntelligence int64 `json:"stale_intelligence"`
	NotEvaluated      int64 `json:"not_evaluated"`
	Unsupported       int64 `json:"unsupported"`
	Awaiting          int64 `json:"awaiting"`
}

type CollectionCoverage struct {
	Status            string     `json:"status"` // ok, partial, stale
	LastSeen          time.Time  `json:"last_seen"`
	LastCollection    *time.Time `json:"last_collection"`
	FailedScopes      int64      `json:"failed_scopes"`
	PartialScopes     int64      `json:"partial_scopes"`
	UnsupportedScopes int64      `json:"unsupported_scopes"` // unsupported or skipped
}

type GapReason struct {
	Reason     string `json:"reason"`
	Coverage   string `json:"coverage"` // unsupported or not_evaluated
	Components int64  `json:"components"`
}

// CoverageSummary says how far an asset's findings can be trusted.
type CoverageSummary struct {
	AssetID       int64              `json:"asset_id"`
	State         string             `json:"state"` // the most severe of States
	Label         string             `json:"label"`
	States        []CoverageState    `json:"states"`
	Components    ComponentCoverage  `json:"components"`
	Collection    CollectionCoverage `json:"collection"`
	LastEvaluated *time.Time         `json:"last_evaluated"`
	GapReasons    []GapReason        `json:"gap_reasons"`
	StaleFeeds    []string           `json:"stale_feeds"`
}

// AssetCoverage summarises one asset's coverage.
func (s *Store) AssetCoverage(ctx context.Context, assetID int64) (*CoverageSummary, error) {
	sums, err := s.coverageSummaries(ctx, assetID)
	if err != nil {
		return nil, err
	}
	if len(sums) == 0 {
		return nil, ErrNotFound
	}
	sum := &sums[0]
	rows, err := s.Pool.Query(ctx, `SELECT i.coverage_reason, i.coverage, count(DISTINCT i.component_id) FROM inventory i
		WHERE i.asset_id = $1 AND i.removed_at IS NULL AND i.coverage IN ('unsupported', 'not_evaluated')
		GROUP BY 1, 2 ORDER BY 3 DESC, 1 LIMIT 20`, assetID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var g GapReason
		if err := rows.Scan(&g.Reason, &g.Coverage, &g.Components); err != nil {
			rows.Close()
			return nil, err
		}
		sum.GapReasons = append(sum.GapReasons, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	err = s.Pool.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT i.coverage_feed ORDER BY i.coverage_feed), '{}') FROM inventory i
		WHERE i.asset_id = $1 AND i.removed_at IS NULL AND (`+rowCoverageSQL+`) = 'stale_intelligence'`, assetID).Scan(&sum.StaleFeeds)
	if err != nil {
		return nil, err
	}
	sum.derive(time.Now())
	return sum, nil
}

// AssetCoverageCounts counts assets by their headline coverage state.
func (s *Store) AssetCoverageCounts(ctx context.Context) (map[string]int64, error) {
	sums, err := s.coverageSummaries(ctx, 0)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := map[string]int64{}
	for i := range sums {
		sums[i].derive(now)
		out[sums[i].State]++
	}
	return out, nil
}

func (s *Store) coverageSummaries(ctx context.Context, assetID int64) ([]CoverageSummary, error) {
	rows, err := s.Pool.Query(ctx, `WITH a AS (
		  SELECT id, collection_status, last_seen FROM assets WHERE merged_into IS NULL AND ($1 = 0 OR id = $1)),
		inv AS (
		  SELECT i.asset_id, i.component_id, i.evaluated_at, `+rowCoverageSQL+` AS cov
		  FROM inventory i WHERE i.removed_at IS NULL AND i.asset_id IN (SELECT id FROM a)),
		c AS (
		  SELECT asset_id, count(DISTINCT component_id) AS total,
		    count(DISTINCT component_id) FILTER (WHERE cov = 'evaluated') AS evaluated,
		    count(DISTINCT component_id) FILTER (WHERE cov = 'stale_intelligence') AS stale,
		    count(DISTINCT component_id) FILTER (WHERE cov = 'not_evaluated') AS not_evaluated,
		    count(DISTINCT component_id) FILTER (WHERE cov = 'unsupported') AS unsupported,
		    count(DISTINCT component_id) FILTER (WHERE cov = 'awaiting') AS awaiting,
		    max(evaluated_at) AS last_evaluated
		  FROM inv GROUP BY asset_id),
		cv AS (
		  SELECT asset_id, count(*) FILTER (WHERE status = 'failed') AS failed,
		    count(*) FILTER (WHERE status = 'partial') AS partial,
		    count(*) FILTER (WHERE status IN ('unsupported', 'skipped')) AS unsupported
		  FROM coverage WHERE asset_id IN (SELECT id FROM a) GROUP BY asset_id),
		col AS (SELECT asset_id, max(received_at) AS last FROM collections WHERE asset_id IN (SELECT id FROM a) GROUP BY asset_id)
		SELECT a.id, a.collection_status, a.last_seen, col.last, c.last_evaluated,
		  COALESCE(c.total, 0), COALESCE(c.evaluated, 0), COALESCE(c.stale, 0), COALESCE(c.not_evaluated, 0),
		  COALESCE(c.unsupported, 0), COALESCE(c.awaiting, 0),
		  COALESCE(cv.failed, 0), COALESCE(cv.partial, 0), COALESCE(cv.unsupported, 0)
		FROM a LEFT JOIN c ON c.asset_id = a.id LEFT JOIN cv ON cv.asset_id = a.id LEFT JOIN col ON col.asset_id = a.id
		ORDER BY a.id`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CoverageSummary
	for rows.Next() {
		var c CoverageSummary
		cc, cl := &c.Components, &c.Collection
		if err := rows.Scan(&c.AssetID, &cl.Status, &cl.LastSeen, &cl.LastCollection, &c.LastEvaluated,
			&cc.Total, &cc.Evaluated, &cc.StaleIntelligence, &cc.NotEvaluated, &cc.Unsupported, &cc.Awaiting,
			&cl.FailedScopes, &cl.PartialScopes, &cl.UnsupportedScopes); err != nil {
			return nil, err
		}
		c.GapReasons, c.StaleFeeds = []GapReason{}, []string{}
		out = append(out, c)
	}
	return out, rows.Err()
}

// derive works out the states from the counts. Missing data never leaves an
// asset "healthy": each way data can be missing maps to a state.
func (c *CoverageSummary) derive(now time.Time) {
	cc, cl := c.Components, c.Collection
	found := map[string][]string{}
	add := func(state, detail string) { found[state] = append(found[state], detail) }
	if cl.FailedScopes > 0 {
		add(StateFailedCollection, plural(cl.FailedScopes, "collector scope")+" failed; components there are not in the inventory")
	}
	if cl.Status == "stale" {
		add(StateFailedCollection, "no collection since "+cl.LastSeen.UTC().Format("2006-01-02 15:04 UTC")+"; the inventory may be out of date")
	}
	if cc.StaleIntelligence > 0 {
		d := plural(cc.StaleIntelligence, "component") + " checked against intelligence that is stale or failing to update"
		if len(c.StaleFeeds) > 0 {
			d += " (" + strings.Join(c.StaleFeeds, ", ") + ")"
		}
		add(StateStaleIntelligence, d)
	}
	if cc.NotEvaluated > 0 {
		add(StatePartiallyEvaluated, plural(cc.NotEvaluated, "component")+" could not be checked")
	}
	if cl.Status == "partial" {
		add(StatePartiallyEvaluated, "the last collection was incomplete, so components may be missing")
	}
	if cl.PartialScopes > 0 {
		add(StatePartiallyEvaluated, plural(cl.PartialScopes, "collector scope")+" only partly checked")
	}
	if cc.Unsupported > 0 {
		verb := " have"
		if cc.Unsupported == 1 {
			verb = " has"
		}
		add(StateUnsupported, plural(cc.Unsupported, "component")+verb+" no vulnerability source")
	}
	if cl.UnsupportedScopes > 0 {
		add(StateUnsupported, plural(cl.UnsupportedScopes, "collector scope")+" unsupported or skipped")
	}
	if cc.Awaiting > 0 {
		add(StateAwaitingVerification, plural(cc.Awaiting, "component")+" not evaluated yet")
	}
	switch {
	case cc.Total == 0 && cl.LastCollection == nil:
		add(StateAwaitingVerification, "nothing has been collected yet")
	case cc.Total > 0 && cc.Awaiting < cc.Total && (c.LastEvaluated == nil || now.Sub(*c.LastEvaluated) > RecentEvaluation):
		add(StateAwaitingVerification, "not evaluated in the last "+fmt.Sprint(int(RecentEvaluation.Hours()))+" hours")
	}
	c.States = c.States[:0]
	for _, st := range stateOrder {
		if d, ok := found[st]; ok {
			c.States = append(c.States, CoverageState{State: st, Label: StateLabels[st], Detail: strings.Join(d, "; ")})
		}
	}
	if len(c.States) == 0 {
		d := "every component was checked against current intelligence"
		if cc.Total == 0 {
			d = "the last collection reported no components"
		}
		c.States = []CoverageState{{State: StateHealthy, Label: StateLabels[StateHealthy], Detail: d}}
	}
	c.State, c.Label = c.States[0].State, c.States[0].Label
}

func plural(n int64, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
