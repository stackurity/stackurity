package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// UpgradeFinding is an open finding with what an upgrade recommendation
// needs.
type UpgradeFinding struct {
	FindingID    int64
	InventoryID  int64
	AssetID      int64
	ComponentID  int64
	PurlType     string
	PurlKey      string
	Version      string
	Distro       string // the inventory purl's distro qualifier, for OS packages
	Kind         string
	Key          string
	FixedVersion string
	Subscription string // paid channel the fix needs
	Product      string // endoflife.date product, for end-of-life findings
}

// UpgradeFindings returns the open findings on one inventory row, or on
// every current inventory row of a component (inventoryID 0). Suppressed and
// accepted findings are included: an upgrade resolves them too.
func (s *Store) UpgradeFindings(ctx context.Context, componentID, inventoryID int64) ([]UpgradeFinding, error) {
	w := &where{}
	w.conds = append(w.conds, "f.status = 'open'", "a.merged_into IS NULL")
	if inventoryID > 0 {
		w.add("f.inventory_id = ?", inventoryID)
	}
	if componentID > 0 {
		w.add("f.component_id = ?", componentID)
	}
	rows, err := s.Pool.Query(ctx, `SELECT f.id, f.inventory_id, f.asset_id, f.component_id, c.type, c.purl_key, i.version,
		COALESCE(substring(i.purl from '[?&]distro=([^&#]+)'), ''), f.kind, f.key, f.fixed_version,
		COALESCE(f.evidence->>'requires_subscription',
		  CASE WHEN (f.evidence->>'requires_ubuntu_pro')::boolean THEN 'Ubuntu Pro' ELSE '' END),
		CASE WHEN f.kind = 'end_of_life' THEN COALESCE(f.evidence->>'product', '') ELSE '' END
		FROM findings f JOIN inventory i ON i.id = f.inventory_id JOIN components c ON c.id = f.component_id
		JOIN assets a ON a.id = f.asset_id`+w.sql()+` ORDER BY i.version, f.key, f.id LIMIT 5000`, w.args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[UpgradeFinding])
}

// LifecycleProductFor returns the endoflife.date product for a component, as
// the matcher finds it: by purl, or for pkg:generic/<name> by product name.
// It returns "" when there is none.
func (s *Store) LifecycleProductFor(ctx context.Context, purlKey string) (string, error) {
	var product string
	err := s.Pool.QueryRow(ctx, `SELECT product FROM lifecycle_products
		WHERE EXISTS (SELECT 1 FROM unnest(purls) p WHERE lower(p) = lower($1))
		   OR ($1 LIKE 'pkg:generic/%' AND product = substring($1 from 13))
		ORDER BY (product = substring($1 from 13)), product LIMIT 1`, purlKey).Scan(&product)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	return product, err
}
