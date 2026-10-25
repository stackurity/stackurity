package store

import (
	"context"
	"fmt"
	"time"
)

// ImageScanCollector is the collector id the image scanner reports under;
// its coverage scope for an image is "image:" + the reference.
const ImageScanCollector = "image-scanner"

// ImageScan asks for one image, already stored as an asset (e.g. reported
// running by the Kubernetes plugin), to be inventoried by the image scanner.
type ImageScan struct {
	AssetID  int64  `json:"asset_id"`
	Image    string `json:"image"`
	Platform string `json:"platform,omitempty"`
}

// ImageScanStats says what QueueImageScans did.
type ImageScanStats struct {
	Queued  int `json:"queued"`
	Fresh   int `json:"fresh"`    // scanned successfully within the freshness window
	Pending int `json:"pending"`  // already queued
	Limited int `json:"deferred"` // over the per-run limit, left for a later run
}

// QueueImageScans queues "image.scan" jobs for images in order, at most
// limit of them, skipping images scanned successfully within fresh and
// images already queued. The same reference (a digest, for running images)
// is therefore read once, however many workloads and runs report it.
//
// An image is never shown as clean before its packages have been read:
// until a scan succeeds it carries a coverage item saying why it has no
// inventory yet, and its collection status is partial.
func (s *Store) QueueImageScans(ctx context.Context, images []ImageScan, limit int, fresh time.Duration) (ImageScanStats, error) {
	var st ImageScanStats
	for _, im := range images {
		scope := "image:" + im.Image
		var lastSuccess *time.Time
		err := s.Pool.QueryRow(ctx, `SELECT max(last_success) FROM coverage WHERE asset_id = $1 AND collector_id = $2 AND scope = $3`,
			im.AssetID, ImageScanCollector, scope).Scan(&lastSuccess)
		if err != nil {
			return st, err
		}
		if lastSuccess != nil && time.Since(*lastSuccess) < fresh {
			st.Fresh++
			continue
		}
		reason := "queued for scanning"
		if st.Queued >= limit {
			st.Limited++
			reason = fmt.Sprintf("not scanned yet: at most %d images are scanned per run; it is scanned on a later run", limit)
		} else {
			id, err := s.Enqueue(ctx, "image.scan", im, "image-scan:"+im.Image, time.Time{})
			if err != nil {
				return st, err
			}
			if id == 0 {
				st.Pending++
			} else {
				st.Queued++
			}
		}
		if lastSuccess != nil {
			continue // keep the last scan's result until the new one arrives
		}
		// A failed scan keeps its reason; only a placeholder is replaced.
		if _, err := s.Pool.Exec(ctx, `INSERT INTO coverage (asset_id, collector_id, scope, status, reason, last_attempt)
			VALUES ($1, $2, $3, 'skipped', $4, now())
			ON CONFLICT (asset_id, collector_id, scope) DO UPDATE SET reason = EXCLUDED.reason
			WHERE coverage.status = 'skipped'`, im.AssetID, ImageScanCollector, scope, reason); err != nil {
			return st, err
		}
		if _, err := s.Pool.Exec(ctx, `UPDATE assets SET collection_status = 'partial' WHERE id = $1 AND collection_status = 'ok'`,
			im.AssetID); err != nil {
			return st, err
		}
	}
	return st, nil
}
