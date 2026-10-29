package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/tenant"
)

type IngestResult struct {
	AssetID      int64   `json:"asset_id"`
	CollectionID int64   `json:"collection_id"`
	Observations int     `json:"observations"`
	Removed      int64   `json:"removed"`
	NewAsset     bool    `json:"new_asset"`
	Conflict     []int64 `json:"identity_conflict,omitempty"`
	// ProjectID is the project the upload asked for (project_id) and the
	// server accepted; 0 when it named none. InProject says whether the
	// asset is in that project after the upload: a collector token files
	// only the assets it creates, so an existing asset may not be.
	ProjectID int64 `json:"project_id,omitempty"`
	InProject *bool `json:"in_project,omitempty"`
	// AppsRemoved lists the applications on this host that the batch's
	// app list (apps.dirs) no longer names, marked removed.
	AppsRemoved []int64 `json:"apps_removed,omitempty"`
	// VEX is what importing the VEX embedded in an uploaded CycloneDX SBOM
	// did (POST /sbom/import), and VEXNote why it was not imported.
	VEX     *VEXImportResult `json:"vex,omitempty"`
	VEXNote string           `json:"vex_note,omitempty"`
}

// AssetInProject reports whether an asset is in a project.
func (s *Store) AssetInProject(ctx context.Context, projectID, assetID int64) (bool, error) {
	var ok bool
	err := s.Pool.QueryRow(tenant.WithoutProject(ctx), `SELECT EXISTS (SELECT 1 FROM project_assets WHERE project_id = $1 AND asset_id = $2)`,
		projectID, assetID).Scan(&ok)
	return ok, err
}

// Ingest stores a validated batch in one transaction. tokenID is the API
// token that submitted it, or 0.
func (s *Store) Ingest(ctx context.Context, b *model.ObservationBatch, tokenID int64) (*IngestResult, error) {
	// A read-only organisation keeps what it has; nothing new is
	// collected, for existing assets either.
	if err := s.CheckWritable(ctx); err != nil {
		return nil, err
	}
	res := &IngestResult{Observations: len(b.Observations)}
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		assetID, isNew, conflict, err := resolveAsset(ctx, tx, b)
		if errors.Is(err, ErrAssetLimit) {
			return err
		}
		if err != nil {
			return fmt.Errorf("resolve asset: %w", err)
		}
		res.AssetID, res.NewAsset, res.Conflict = assetID, isNew, conflict
		// A token made for a project (in the first-run flow, or an
		// enrollment code naming one) adds the assets it creates to it.
		if isNew && tokenID > 0 {
			if _, err := tx.Exec(ctx, `INSERT INTO project_assets (project_id, asset_id)
				SELECT t.project_id, $2 FROM api_tokens t JOIN projects p ON p.id = t.project_id AND p.archived_at IS NULL
				WHERE t.id = $1 ON CONFLICT DO NOTHING`, tokenID, assetID); err != nil {
				return fmt.Errorf("add to project: %w", err)
			}
		}

		var tok *int64
		if tokenID > 0 {
			tok = &tokenID
		}
		err = tx.QueryRow(ctx, `INSERT INTO collections
			(asset_id, collector_id, collector_version, method, observed_at, complete, observation_count, submitted_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
			assetID, b.Collector.ID, b.Collector.Version, b.Collector.Method, b.ObservedAt, b.Complete, len(b.Observations), tok,
		).Scan(&res.CollectionID)
		if err != nil {
			return err
		}
		if err := loadObservations(ctx, tx, b); err != nil {
			return fmt.Errorf("load observations: %w", err)
		}
		// The component catalogue is shared between workspaces, so it is written
		// in system scope; inventory rows still take this workspace's id.
		err = asSystem(ctx, tx, func() error {
			if _, err := tx.Exec(ctx, `INSERT INTO components (purl_key, type, namespace, name)
				SELECT DISTINCT ON (purl_key) purl_key, type, namespace, name FROM obs_in
				ON CONFLICT (purl_key) DO NOTHING`); err != nil {
				return err
			}
			// Duplicate rows within one batch (e.g. the same npm package nested
			// twice in one lockfile) collapse to one inventory row; any direct
			// occurrence wins.
			if _, err := tx.Exec(ctx, `INSERT INTO inventory AS i
				(asset_id, component_id, purl, version, location, collector_id, direct, scope, confidence, evidence,
				 first_seen, last_seen, last_collection_id)
				SELECT DISTINCT ON (c.id, o.version, o.location)
				       $1, c.id, o.purl, o.version, o.location, $2, o.direct, o.scope, o.confidence, o.evidence,
				       $3, $3, $4
				FROM obs_in o JOIN components c USING (purl_key)
				ORDER BY c.id, o.version, o.location, o.direct DESC NULLS LAST
				ON CONFLICT (asset_id, component_id, version, location, collector_id) DO UPDATE SET
				  purl = EXCLUDED.purl, direct = EXCLUDED.direct, scope = EXCLUDED.scope,
				  confidence = EXCLUDED.confidence, evidence = EXCLUDED.evidence,
				  last_seen = GREATEST(i.last_seen, EXCLUDED.last_seen),
				  last_collection_id = EXCLUDED.last_collection_id, removed_at = NULL`,
				assetID, b.Collector.ID, b.ObservedAt, res.CollectionID); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
		// A complete collection proves that whatever it left out is gone.
		// An incomplete one proves it outside the paths it could not read
		// (an unreadable cache directory must not keep an upgraded
		// application's old libraries open forever).
		if blind, ok := blindPaths(b); ok {
			tag, err := tx.Exec(ctx, `UPDATE inventory SET removed_at = $3
				WHERE asset_id = $1 AND collector_id = $2 AND removed_at IS NULL AND last_collection_id <> $4
				  AND (cardinality($5::text[]) = 0 OR (location LIKE '/%' AND NOT EXISTS (SELECT 1 FROM unnest($5::text[]) p
				    WHERE location = p OR starts_with(location, rtrim(p, '/') || '/'))))`,
				assetID, b.Collector.ID, b.ObservedAt, res.CollectionID, blind)
			if err != nil {
				return err
			}
			res.Removed = tag.RowsAffected()
			if _, err := tx.Exec(ctx, `UPDATE collections SET proves_absence = true WHERE id = $1`, res.CollectionID); err != nil {
				return err
			}
		}
		if err := writeCoverage(ctx, tx, assetID, res.CollectionID, b); err != nil {
			return err
		}
		if b.Relations != nil {
			if err := writeRelations(ctx, tx, assetID, b); err != nil {
				return fmt.Errorf("relations: %w", err)
			}
		}
		if b.Apps != nil && b.Asset.Kind == model.AssetHost {
			if res.AppsRemoved, err = removeGoneApps(ctx, tx, assetID, b, tok); err != nil {
				return fmt.Errorf("removed applications: %w", err)
			}
		}
		status := "ok"
		if !b.Complete {
			status = "partial"
		}
		if _, err = tx.Exec(ctx, `UPDATE assets SET collection_status = $2 WHERE id = $1`, assetID, status); err != nil {
			return err
		}
		// Queue re-evaluation of this asset against current intelligence. A
		// short delay lets several batches for one asset share one run; a run
		// already in progress may not see this batch, so it is asked to repeat.
		_, err = tx.Exec(ctx, `INSERT INTO jobs (kind, payload, dedupe_key, run_at)
			VALUES ('evaluate', jsonb_build_object('asset_id', $1::bigint), 'evaluate:asset:' || $1::bigint, now() + interval '5 seconds')
			ON CONFLICT (COALESCE(workspace_id, 0), dedupe_key) WHERE dedupe_key IS NOT NULL AND done_at IS NULL AND failed_at IS NULL
			DO UPDATE SET requeue = true WHERE jobs.locked_at IS NOT NULL`, assetID)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrAssetLimit) {
			// Remembered for the Usage page; the refusal stands either way.
			_ = s.recordRefused(ctx, b)
		}
		return nil, err
	}
	return res, nil
}

func loadObservations(ctx context.Context, tx pgx.Tx, b *model.ObservationBatch) error {
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE obs_in (
		purl_key text, type text, namespace text, name text, purl text, version text,
		location text, direct boolean, scope text, confidence text, evidence jsonb) ON COMMIT DROP`); err != nil {
		return err
	}
	rows := make([][]any, 0, len(b.Observations))
	for _, o := range b.Observations {
		key, typ, ns, name, err := model.ComponentKey(o.Purl)
		if err != nil {
			return err // Validate() already rejected bad purls
		}
		ev := o.Evidence
		if ev == nil {
			ev = map[string]string{}
		}
		evJSON, _ := json.Marshal(ev)
		rows = append(rows, []any{key, typ, ns, name, o.Purl, o.Version, o.Location, o.Direct, o.Scope, string(o.Confidence), evJSON})
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"obs_in"},
		[]string{"purl_key", "type", "namespace", "name", "purl", "version", "location", "direct", "scope", "confidence", "evidence"},
		pgx.CopyFromRows(rows))
	return err
}

func writeCoverage(ctx context.Context, tx pgx.Tx, assetID, collectionID int64, b *model.ObservationBatch) error {
	for _, c := range b.Coverage {
		if _, err := tx.Exec(ctx, `INSERT INTO coverage (asset_id, collector_id, scope, status, reason, tool_version, last_attempt, last_success)
			VALUES ($1,$2,$3,$4,$5,$6,$7, CASE WHEN $4 = 'checked' THEN $7::timestamptz END)
			ON CONFLICT (asset_id, collector_id, scope) DO UPDATE SET
			  status = EXCLUDED.status, reason = EXCLUDED.reason, tool_version = EXCLUDED.tool_version,
			  last_attempt = EXCLUDED.last_attempt,
			  last_success = COALESCE(EXCLUDED.last_success, coverage.last_success)`,
			assetID, b.Collector.ID, c.Scope, c.Status, c.Reason, b.Collector.Version, b.ObservedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO coverage_history (collection_id, scope, status, reason) VALUES ($1,$2,$3,$4)`,
			collectionID, c.Scope, c.Status, c.Reason); err != nil {
			return err
		}
	}
	return nil
}

// writeRelations replaces the relations this collector reported for the
// asset. Targets are found by identifier; unknown targets are skipped and
// picked up on a later collection. Relations added by hand are kept.
func writeRelations(ctx context.Context, tx pgx.Tx, assetID int64, b *model.ObservationBatch) error {
	source := "collector:" + b.Collector.ID
	keep := map[[2]any]bool{}
	for _, rel := range b.Relations {
		for _, id := range rel.To {
			var target int64
			err := tx.QueryRow(ctx, `SELECT COALESCE(a.merged_into, a.id) FROM asset_identifiers i JOIN assets a ON a.id = i.asset_id
				WHERE i.scheme = $1 AND i.value = $2`, id.Scheme, id.Value).Scan(&target)
			if err == pgx.ErrNoRows {
				continue
			}
			if err != nil {
				return err
			}
			if target == assetID {
				break
			}
			keep[[2]any{target, rel.Kind}] = true
			if _, err := tx.Exec(ctx, `INSERT INTO asset_relations (from_asset, to_asset, kind, source) VALUES ($1,$2,$3,$4)
				ON CONFLICT DO NOTHING`, assetID, target, rel.Kind, source); err != nil {
				return err
			}
			break
		}
	}
	rows, err := tx.Query(ctx, `SELECT to_asset, kind FROM asset_relations WHERE from_asset = $1 AND source = $2`, assetID, source)
	if err != nil {
		return err
	}
	var stale [][2]any
	for rows.Next() {
		var to int64
		var kind string
		if err := rows.Scan(&to, &kind); err != nil {
			rows.Close()
			return err
		}
		if !keep[[2]any{to, kind}] {
			stale = append(stale, [2]any{to, kind})
		}
	}
	rows.Close()
	for _, st := range stale {
		if _, err := tx.Exec(ctx, `DELETE FROM asset_relations WHERE from_asset = $1 AND to_asset = $2 AND kind = $3 AND source = $4`,
			assetID, st[0], st[1], source); err != nil {
			return err
		}
	}
	return rows.Err()
}

// resolveAsset maps batch identifiers to one asset, creating it if needed.
// When identifiers point at several assets the oldest wins and a conflict
// is recorded for an administrator.
func resolveAsset(ctx context.Context, tx pgx.Tx, b *model.ObservationBatch) (int64, bool, []int64, error) {
	schemes := make([]string, len(b.Asset.Identifiers))
	values := make([]string, len(b.Asset.Identifiers))
	for i, id := range b.Asset.Identifiers {
		schemes[i], values[i] = id.Scheme, id.Value
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT COALESCE(a.merged_into, a.id)
		FROM asset_identifiers ai JOIN assets a ON a.id = ai.asset_id
		JOIN unnest($1::text[], $2::text[]) AS x(scheme, value) ON x.scheme = ai.scheme AND x.value = ai.value`,
		schemes, values)
	if err != nil {
		return 0, false, nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return 0, false, nil, err
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	attrs, _ := json.Marshal(nonNil(b.Asset.Attributes))
	var assetID int64
	isNew := false
	var conflict []int64
	if len(ids) == 0 {
		if err := checkNewAsset(ctx, tx, b); err != nil {
			return 0, false, nil, err
		}
		isNew = true
		name, err := appName(ctx, tx, b, 0)
		if err != nil {
			return 0, false, nil, err
		}
		err = tx.QueryRow(ctx, `INSERT INTO assets (kind, name, environment, provider, region, attributes, first_seen, last_seen)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$7) RETURNING id`,
			b.Asset.Kind, name, b.Asset.Environment, b.Asset.Provider, b.Asset.Region, attrs, b.ObservedAt).Scan(&assetID)
		if err != nil {
			return 0, false, nil, err
		}
	} else {
		assetID = ids[0]
		if _, err := appName(ctx, tx, b, assetID); err != nil {
			return 0, false, nil, err
		}
		if len(ids) > 1 {
			conflict = ids
			idsJSON, _ := json.Marshal(b.Asset.Identifiers)
			if _, err := tx.Exec(ctx, `INSERT INTO identity_conflicts (asset_ids, identifiers)
				SELECT $1, $2 WHERE NOT EXISTS (
				  SELECT 1 FROM identity_conflicts WHERE asset_ids = $1 AND resolved_at IS NULL)`, ids, idsJSON); err != nil {
				return 0, false, nil, err
			}
		}
		// Collected attributes are merged; operator-set fields are only
		// filled when still empty.
		if _, err := tx.Exec(ctx, `UPDATE assets SET
			attributes = attributes || $2::jsonb,
			last_seen = GREATEST(last_seen, $3),
			environment = CASE WHEN environment = '' THEN $4 ELSE environment END,
			provider = CASE WHEN provider = '' THEN $5 ELSE provider END,
			region = CASE WHEN region = '' THEN $6 ELSE region END
			WHERE id = $1`, assetID, attrs, b.ObservedAt, b.Asset.Environment, b.Asset.Provider, b.Asset.Region); err != nil {
			return 0, false, nil, err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO asset_identifiers (scheme, value, asset_id)
		SELECT * FROM unnest($1::text[], $2::text[]), (SELECT $3::bigint) AS a
		ON CONFLICT (workspace_id, scheme, value) DO NOTHING`, schemes, values, assetID); err != nil {
		return 0, false, nil, err
	}
	return assetID, isNew, conflict, nil
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// MarkStaleAssets flags assets not seen within maxAge (FR-03: stale data is
// visible, never healthy). Returns the number newly marked.
func (s *Store) MarkStaleAssets(ctx context.Context, maxAge time.Duration) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE assets SET collection_status = 'stale'
		WHERE merged_into IS NULL AND collection_status NOT IN ('stale', 'removed') AND last_seen < now() - make_interval(secs => $1)`,
		maxAge.Seconds())
	return tag.RowsAffected(), err
}
