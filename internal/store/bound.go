package store

import (
	"context"
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
