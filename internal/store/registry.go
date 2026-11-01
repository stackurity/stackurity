package store

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/model"
)

// RegistryImage is one image (a digest) a connected registry tracks
// (migration 0077).
type RegistryImage struct {
	ID            int64      `json:"id"`
	IntegrationID int64      `json:"integration_id"`
	Repository    string     `json:"repository"`
	Digest        string     `json:"digest"`
	ImageRef      string     `json:"image_ref"`
	Tags          []string   `json:"tags"`
	PushedAt      *time.Time `json:"pushed_at"`
	AssetID       *int64     `json:"asset_id"`
	Tracked       bool       `json:"tracked"`
	FirstSeen     time.Time  `json:"first_seen"`
	LastSeen      time.Time  `json:"last_seen"`
	RemovedAt     *time.Time `json:"removed_at"`
}

const registryImageCols = `id, integration_id, repository, digest, image_ref, tags, pushed_at, asset_id, tracked, first_seen, last_seen, removed_at`

// RegistryImages lists an integration's images, the tracked ones first,
// most recently pushed first.
func (s *Store) RegistryImages(ctx context.Context, integrationID int64) ([]RegistryImage, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+registryImageCols+` FROM registry_images WHERE integration_id = $1
		ORDER BY removed_at IS NOT NULL, NOT tracked, repository, pushed_at DESC NULLS LAST, id`, integrationID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[RegistryImage])
}

// TrackRegistryImage records that the integration tracks an image now:
// its tags and push time are updated, and an image removed or untracked
// before is tracked again. The asset's tags attribute follows.
func (s *Store) TrackRegistryImage(ctx context.Context, im RegistryImage) (RegistryImage, error) {
	if im.Tags == nil {
		im.Tags = []string{}
	}
	rows, err := s.Pool.Query(ctx, `INSERT INTO registry_images (integration_id, repository, digest, image_ref, tags, pushed_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (integration_id, repository, digest) DO UPDATE SET image_ref = EXCLUDED.image_ref, tags = EXCLUDED.tags,
		  pushed_at = COALESCE(EXCLUDED.pushed_at, registry_images.pushed_at), tracked = true, removed_at = NULL, last_seen = now()
		RETURNING `+registryImageCols, im.IntegrationID, im.Repository, im.Digest, im.ImageRef, im.Tags, im.PushedAt)
	if err != nil {
		return RegistryImage{}, err
	}
	out, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[RegistryImage])
	if err != nil {
		return RegistryImage{}, err
	}
	if out.AssetID != nil {
		// An image pushed again after it was removed is waiting for its
		// scan, not removed.
		if _, err := s.Pool.Exec(ctx, `UPDATE assets SET attributes = attributes || jsonb_build_object('tags', $2::text),
			collection_status = CASE WHEN collection_status = 'removed' THEN 'partial' ELSE collection_status END
			WHERE id = $1 AND (attributes->>'tags' IS DISTINCT FROM $2::text OR collection_status = 'removed')`,
			*out.AssetID, strings.Join(out.Tags, ", ")); err != nil {
			return out, err
		}
	}
	return out, nil
}

// SetRegistryImageAsset links an image to the asset it was stored as.
func (s *Store) SetRegistryImageAsset(ctx context.Context, id, assetID int64) error {
	_, err := s.Pool.Exec(ctx, `UPDATE registry_images SET asset_id = $2 WHERE id = $1`, id, assetID)
	return err
}

// UntrackRegistryImages stops tracking images that are still in the
// registry but no longer chosen (a newer tag took their place). Their
// assets are left as they are: the image may still run somewhere.
func (s *Store) UntrackRegistryImages(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.Pool.Exec(ctx, `UPDATE registry_images SET tracked = false WHERE id = ANY($1) AND removed_at IS NULL`, ids)
	return err
}

// RegistryCollector is the collector id of a connected registry's
// reference-only reports (an image's name and digest, before its scan).
const RegistryCollector = "container-registry"

// RemoveRegistryImages marks images the registry no longer has as
// removed. Each one's asset, unless another integration still tracks the
// image, gets a complete, empty collection (so its issues resolve as
// removed on the next evaluation; its history stays), a coverage note
// saying why, and collection status "removed". The image scanner's last
// success is forgotten, so an image pushed again is scanned again.
func (s *Store) RemoveRegistryImages(ctx context.Context, ids []int64, version string) ([]int64, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var removed []int64
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE registry_images SET removed_at = now(), tracked = false
			WHERE id = ANY($1) AND removed_at IS NULL RETURNING asset_id, image_ref`, ids)
		if err != nil {
			return err
		}
		type gone struct {
			asset *int64
			ref   string
		}
		var list []gone
		for rows.Next() {
			var g gone
			if err := rows.Scan(&g.asset, &g.ref); err != nil {
				rows.Close()
				return err
			}
			list = append(list, g)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		now := time.Now()
		for _, g := range list {
			if g.asset == nil {
				continue
			}
			var stillTracked bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM registry_images WHERE asset_id = $1 AND removed_at IS NULL)`,
				*g.asset).Scan(&stillTracked); err != nil {
				return err
			}
			if stillTracked {
				continue
			}
			var coll int64
			if err := tx.QueryRow(ctx, `INSERT INTO collections
				(asset_id, collector_id, collector_version, method, observed_at, complete, observation_count, proves_absence)
				SELECT a.id, $2, $3, 'scanner', $4, true, 0, true FROM assets a WHERE a.id = $1 AND a.merged_into IS NULL
				RETURNING id`, *g.asset, ImageScanCollector, version, now).Scan(&coll); err != nil {
				if err == pgx.ErrNoRows {
					continue // merged into another asset meanwhile
				}
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE inventory SET removed_at = $2 WHERE asset_id = $1 AND removed_at IS NULL`, *g.asset, now); err != nil {
				return err
			}
			reason := "deleted from the registry: none of its tags is there any more"
			scope := "image:" + g.ref
			if len(scope) > model.MaxFieldLen {
				scope = scope[:model.MaxFieldLen]
			}
			if _, err := tx.Exec(ctx, `INSERT INTO coverage (asset_id, collector_id, scope, status, reason, tool_version, last_attempt)
				VALUES ($1, $2, $3, 'skipped', $4, $5, $6)
				ON CONFLICT (asset_id, collector_id, scope) DO UPDATE SET status = EXCLUDED.status, reason = EXCLUDED.reason,
				  tool_version = EXCLUDED.tool_version, last_attempt = EXCLUDED.last_attempt, last_success = NULL`,
				*g.asset, ImageScanCollector, scope, reason, version, now); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO coverage_history (collection_id, scope, status, reason) VALUES ($1, $2, 'skipped', $3)`,
				coll, scope, reason); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE assets SET collection_status = $2 WHERE id = $1`, *g.asset, AssetRemoved); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO jobs (kind, payload, dedupe_key, run_at)
				VALUES ('evaluate', jsonb_build_object('asset_id', $1::bigint), 'evaluate:asset:' || $1::bigint, now() + interval '5 seconds')
				ON CONFLICT (COALESCE(workspace_id, 0), dedupe_key) WHERE dedupe_key IS NOT NULL AND done_at IS NULL AND failed_at IS NULL
				DO UPDATE SET requeue = true WHERE jobs.locked_at IS NOT NULL`, *g.asset); err != nil {
				return err
			}
			removed = append(removed, *g.asset)
		}
		return nil
	})
	return removed, err
}
