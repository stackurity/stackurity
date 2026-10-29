package store

import (
	"context"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/intel/eoloverlay"
)

// UpgradeIssue is one distinct open issue on an installed version of a
// component, with what an upgrade recommendation needs.
type UpgradeIssue struct {
	Version      string
	Distro       string // the inventory purl's distro qualifier, for OS packages
	Kind         string
	Key          string
	FixedVersion string
	Subscription string // paid channel the fix needs
	Product      string // endoflife.date product, for end-of-life findings
	FindingID    int64  // the lowest id among the findings with this issue
	Findings     int64  // open findings with this issue (one per asset and location)
}

// upgradeIssueLimit bounds the distinct issues read for one component.
const upgradeIssueLimit = 5000

// UpgradeIssues returns the distinct open issues on one inventory row, or on
// every current inventory row of a component (inventoryID 0), aggregated in
// the database so a package on thousands of hosts stays cheap. Suppressed and
// accepted findings are included: an upgrade resolves them too.
func (s *Store) UpgradeIssues(ctx context.Context, componentID, inventoryID int64) ([]UpgradeIssue, error) {
	w := &where{}
	w.conds = append(w.conds, "f.status = 'open'", "a.merged_into IS NULL")
	if inventoryID > 0 {
		w.add("f.inventory_id = ?", inventoryID)
	}
	if componentID > 0 {
		w.add("f.component_id = ?", componentID)
	}
	rows, err := s.Pool.Query(ctx, `SELECT i.version, COALESCE(substring(i.purl from '[?&]distro=([^&#]+)'), ''), f.kind, f.key,
		f.fixed_version, COALESCE(f.evidence->>'requires_subscription',
		  CASE WHEN (f.evidence->>'requires_ubuntu_pro')::boolean THEN 'Ubuntu Pro' ELSE '' END),
		CASE WHEN f.kind = 'end_of_life' THEN COALESCE(f.evidence->>'product', '') ELSE '' END, min(f.id), count(*)
		FROM findings f JOIN inventory i ON i.id = f.inventory_id JOIN assets a ON a.id = f.asset_id`+w.sql()+`
		GROUP BY 1, 2, 3, 4, 5, 6, 7 ORDER BY 1, 2, 4 LIMIT `+strconv.Itoa(upgradeIssueLimit), w.args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[UpgradeIssue])
}

// UpgradeAssetCounts returns, per installed version and distro of a
// component (keyed version + "\x00" + distro), how many assets have open
// findings on it.
func (s *Store) UpgradeAssetCounts(ctx context.Context, componentID int64) (map[string]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT i.version, COALESCE(substring(i.purl from '[?&]distro=([^&#]+)'), ''),
		count(DISTINCT f.asset_id)
		FROM findings f JOIN inventory i ON i.id = f.inventory_id JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		WHERE f.status = 'open' AND f.component_id = $1 GROUP BY 1, 2`, componentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var v, d string
		var n int64
		if err := rows.Scan(&v, &d, &n); err != nil {
			return nil, err
		}
		out[v+"\x00"+d] = n
	}
	return out, rows.Err()
}

// LifecycleProductFor returns the endoflife.date product for a component, as
// the matcher finds it: by purl (endoflife.date's identifiers and the
// lifecycle overlay, see eoloverlay), or for pkg:generic/<name> by product
// name. It returns "" when there is none.
func (s *Store) LifecycleProductFor(ctx context.Context, purlKey string) (string, error) {
	var lookupErr error
	edl := func(key string) string {
		var product string
		err := s.Pool.QueryRow(ctx, `SELECT product FROM lifecycle_products
			WHERE EXISTS (SELECT 1 FROM unnest(purls) p WHERE lower(p) = $1) ORDER BY product LIMIT 1`, key).Scan(&product)
		if err != nil && err != pgx.ErrNoRows && lookupErr == nil {
			lookupErr = err
		}
		return product
	}
	m, ok := eoloverlay.Default().Product(purlKey, edl)
	if lookupErr != nil {
		return "", lookupErr
	}
	product := ""
	if ok {
		product = m.Product
	} else if name, generic := strings.CutPrefix(purlKey, "pkg:generic/"); generic {
		product = name
	} else {
		return "", nil
	}
	var exists bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM lifecycle_products WHERE product = $1)`, product).Scan(&exists); err != nil || !exists {
		return "", err
	}
	return product, nil
}
