package store

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/model"
)

// CreateAssetToken issues a collector token bound to one asset (a host enrolled
// for remediation): it can only report for, and fetch changes for, that asset.
func (s *Store) CreateAssetToken(ctx context.Context, assetID int64, name string, createdBy int64) (*Token, string, error) {
	t, secret, err := s.CreateToken(ctx, name, "collector", nil, createdBy, 0)
	if err != nil {
		return nil, "", err
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE api_tokens SET asset_id = $2 WHERE id = $1`, t.ID, assetID); err != nil {
		return nil, "", err
	}
	return t, secret, nil
}

func (s *Store) TokenAsset(ctx context.Context, tokenID int64) (*int64, error) {
	var a *int64
	err := s.Pool.QueryRow(ctx, `SELECT asset_id FROM api_tokens WHERE id = $1`, tokenID).Scan(&a)
	return a, err
}

// AssetByIdentifier resolves an asset by one identifier.
func (s *Store) AssetByIdentifier(ctx context.Context, scheme, value string) (int64, error) {
	var id int64
	err := s.Pool.QueryRow(ctx, `SELECT COALESCE(a.merged_into, a.id) FROM asset_identifiers i JOIN assets a ON a.id = i.asset_id
		WHERE i.scheme = $1 AND i.value = $2`, scheme, value).Scan(&id)
	return id, notFound(err)
}

// AssetsReportingThrough keeps the ids a token bound to asset bound may
// report for, by the rule ingest applies: the bound asset itself (or an
// asset merged into it), and applications whose path identity is scoped to
// it ("host:<bound>:<path>", see bindAppIdentity in the API).
func (s *Store) AssetsReportingThrough(ctx context.Context, bound int64, ids []int64) ([]int64, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := s.Pool.Query(ctx, `SELECT a.id FROM assets a WHERE a.id = ANY($1) AND (
		  COALESCE(a.merged_into, a.id) = $2
		  OR EXISTS (SELECT 1 FROM asset_identifiers i JOIN assets t ON t.id = i.asset_id
		    WHERE COALESCE(t.merged_into, t.id) = COALESCE(a.merged_into, a.id)
		      AND i.scheme = $3 AND starts_with(i.value, 'host:' || $2::bigint || ':')))`,
		ids, bound, model.AppPathScheme)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}
