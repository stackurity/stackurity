package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"

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
	// ImagesRemoved lists the container images on this host that the
	// batch's image list (images.refs) no longer names, marked removed.
	ImagesRemoved []int64 `json:"images_removed,omitempty"`
	// LeaksFound is the number of leaked keys the batch reported, and
	// LeaksGone the open ones on the asset its complete scan no longer
	// saw, now resolved.
	LeaksFound int   `json:"leaks_found,omitempty"`
	LeaksGone  int64 `json:"leaks_gone,omitempty"`
	// ConfigFound is the number of config findings the batch reported, and
	// ConfigGone the open ones on the asset its complete checks no longer
	// saw, now resolved.
	ConfigFound int   `json:"config_found,omitempty"`
	ConfigGone  int64 `json:"config_gone,omitempty"`
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
	if err := checkSelftestScheme(ctx, b); err != nil {
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
		// Assets only in projects over the plan's project limit collect
		// nothing new (docs/asset-limits.md, "Plan limits").
		if ws, ok := tenant.Workspace(ctx); ok {
			if err := checkAssetCollecting(ctx, tx, ws, assetID); err != nil {
				return err
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
		trust, err := reachTrust(ctx, tx, tokenID, assetID, b.Asset.Kind)
		if err != nil {
			return err
		}
		if err := loadObservations(ctx, tx, b, trust); err != nil {
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
			// occurrence wins, then the safer reachability (reachable, then
			// unknown, before a claim that it is not reached).
			if _, err := tx.Exec(ctx, `INSERT INTO inventory AS i
				(asset_id, component_id, purl, version, location, collector_id, direct, scope, confidence, evidence,
				 reachability, reachability_evidence, first_seen, last_seen, last_collection_id)
				SELECT DISTINCT ON (c.id, o.version, o.location)
				       $1, c.id, o.purl, o.version, o.location, $2, o.direct, o.scope, o.confidence, o.evidence,
				       o.reachability, o.reachability_evidence, $3, $3, $4
				FROM obs_in o JOIN components c USING (purl_key)
				ORDER BY c.id, o.version, o.location, o.direct DESC NULLS LAST,
				  CASE o.reachability WHEN 'reachable' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END
				ON CONFLICT (asset_id, component_id, version, location, collector_id) DO UPDATE SET
				  purl = EXCLUDED.purl, direct = EXCLUDED.direct, scope = EXCLUDED.scope,
				  confidence = EXCLUDED.confidence, evidence = EXCLUDED.evidence,
				  reachability = EXCLUDED.reachability, reachability_evidence = EXCLUDED.reachability_evidence,
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
		// application's old libraries open forever). Rows in a file whose
		// coverage is "limited" stay: its format cannot show everything, so
		// a missing entry proves nothing (a scope ends with ":" and the
		// file's location, as pack and lockfile scopes do). A repository
		// scan that did not look for copied front-end libraries keeps the
		// rows another scan found (webAssetsUnchecked).
		if blind, ok := blindPaths(b); ok {
			tag, err := tx.Exec(ctx, `UPDATE inventory SET removed_at = $3
				WHERE asset_id = $1 AND collector_id = $2 AND removed_at IS NULL AND last_collection_id <> $4
				  AND (cardinality($5::text[]) = 0 OR (location LIKE '/%' AND NOT EXISTS (SELECT 1 FROM unnest($5::text[]) p
				    WHERE location = p OR starts_with(location, rtrim(p, '/') || '/'))))
				  AND NOT EXISTS (SELECT 1 FROM unnest($6::text[]) s
				    WHERE location <> '' AND right(s, length(location) + 1) = ':' || location)
				  AND NOT ($7 AND COALESCE(evidence->>'source', '') = ANY($8::text[]))`,
				assetID, b.Collector.ID, b.ObservedAt, res.CollectionID, blind, limitedScopes(b), webAssetsUnchecked(b), webAssetSources)
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
		if b.Images != nil && b.Asset.Kind == model.AssetHost {
			if res.ImagesRemoved, err = removeGoneImages(ctx, tx, assetID, b, tok); err != nil {
				return fmt.Errorf("removed images: %w", err)
			}
		}
		if b.Leaks != nil {
			if res.LeaksFound, res.LeaksGone, err = writeLeaks(ctx, tx, assetID, res.CollectionID, b); err != nil {
				return fmt.Errorf("leaks: %w", err)
			}
		}
		if b.ConfigFindings != nil {
			if res.ConfigFound, res.ConfigGone, err = writeConfigFindings(ctx, tx, assetID, res.CollectionID, b); err != nil {
				return fmt.Errorf("config findings: %w", err)
			}
		}
		status := "ok"
		if !b.Complete {
			status = "partial"
		}
		if _, err = tx.Exec(ctx, `UPDATE assets SET collection_status = $2 WHERE id = $1`, assetID, status); err != nil {
			return err
		}
		if err := recordReport(ctx, tx, assetID, reportSourceOf(ctx, b, tokenID), s.staleAfter()); err != nil {
			return fmt.Errorf("reporting: %w", err)
		}
		// Queue re-evaluation of this asset against current intelligence. A
		// short delay lets several batches for one asset share one run; a run
		// already in progress may not see this batch, so it is asked to repeat.
		_, err = tx.Exec(ctx, `INSERT INTO jobs (workspace_id, kind, payload, dedupe_key, run_at)
			SELECT a.workspace_id, 'evaluate', jsonb_build_object('asset_id', a.id), 'evaluate:asset:' || a.id, now() + interval '5 seconds'
			FROM assets a WHERE a.id = $1::bigint
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
	if s.AfterLeakScan != nil && (b.Leaks != nil || b.ConfigFindings != nil) {
		s.AfterLeakScan(ctx, res.AssetID)
	}
	return res, nil
}

type serverCollectionKey struct{}

// AsServerCollection marks ctx as the server's own collection (a
// repository it cloned and scanned), whose not imported claims it trusts.
func AsServerCollection(ctx context.Context) context.Context {
	return context.WithValue(ctx, serverCollectionKey{}, true)
}

// reachTrust says, from the server's records, which not-reached claims a
// batch about assetID may make. An agent's token may report processes for
// its own host only: a token bound to the host, or an enrollment token
// pinned to the first host it reported (the agent reports its host first;
// the pin is set here). Any other token, or the server's own scan, may
// report imports. A batch with no token (a signed-in browser's upload)
// may make neither.
func reachTrust(ctx context.Context, tx pgx.Tx, tokenID, assetID int64, kind model.AssetKind) (model.ReachTrust, error) {
	if ctx.Value(serverCollectionKey{}) != nil {
		return model.ReachTrust{Imports: true}, nil
	}
	if tokenID <= 0 {
		return model.ReachTrust{}, nil
	}
	if kind == model.AssetHost {
		if _, err := tx.Exec(ctx, `UPDATE enrollment_uses SET asset_id = $2 WHERE token_id = $1 AND asset_id IS NULL`, tokenID, assetID); err != nil {
			return model.ReachTrust{}, err
		}
	}
	var agent, own bool
	err := tx.QueryRow(ctx, `SELECT t.asset_id IS NOT NULL OR EXISTS (SELECT 1 FROM enrollment_uses u WHERE u.token_id = t.id),
		COALESCE(t.asset_id = $2, false) OR EXISTS (SELECT 1 FROM enrollment_uses u WHERE u.token_id = t.id AND u.asset_id = $2)
		FROM api_tokens t WHERE t.id = $1`, tokenID, assetID).Scan(&agent, &own)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.ReachTrust{}, nil
	}
	return model.ReachTrust{Processes: agent && own, Imports: !agent}, err
}

func loadObservations(ctx context.Context, tx pgx.Tx, b *model.ObservationBatch, trust model.ReachTrust) error {
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE obs_in (
		purl_key text, type text, namespace text, name text, purl text, version text,
		location text, direct boolean, scope text, confidence text, evidence jsonb,
		reachability text, reachability_evidence jsonb) ON COMMIT DROP`); err != nil {
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
		// Not assessed is unknown, never the status an earlier batch sent.
		// A claim the batch's collector cannot make is unknown too.
		reach, reachEv := model.ReachUnknown, []byte(nil)
		if r := b.TrustedReach(&o, trust); r != nil {
			reach = r.Status
			if len(r.Evidence) > 0 {
				reachEv, _ = json.Marshal(r.Evidence)
			}
		}
		rows = append(rows, []any{key, typ, ns, name, o.Purl, o.Version, o.Location, o.Direct, o.Scope, string(o.Confidence), evJSON,
			reach, reachEv})
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"obs_in"},
		[]string{"purl_key", "type", "namespace", "name", "purl", "version", "location", "direct", "scope", "confidence", "evidence",
			"reachability", "reachability_evidence"},
		pgx.CopyFromRows(rows))
	return err
}

// writeCoverage records the batch's coverage scopes and deletes the
// collector's earlier scopes on the asset that the batch left out. A batch
// lists every scope its run tried, so an omitted scope is one the collector
// no longer reads (an agent upgrade stopped reporting it, a file was
// removed): left in place it would count as a current gap on the trust
// badge, the Coverage page and the coverage-gap report forever. Only rows
// last attempted no later than this batch go, so a delayed older batch
// cannot delete a newer one's scopes. Other collectors' scopes on the asset
// are theirs to replace. coverage_history keeps every report.
func writeCoverage(ctx context.Context, tx pgx.Tx, assetID, collectionID int64, b *model.ObservationBatch) error {
	scopes := make([]string, 0, len(b.Coverage))
	for _, c := range b.Coverage {
		scopes = append(scopes, c.Scope)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM coverage WHERE asset_id = $1 AND collector_id = $2
		AND NOT (scope = ANY($3::text[])) AND last_attempt <= $4`,
		assetID, b.Collector.ID, scopes, b.ObservedAt); err != nil {
		return err
	}
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

// machineSchemes are the identifiers a host agent reads from the machine
// itself. They tell machines apart; the hostname, which agents send next to
// them, does not: two machines can share one (#565).
var machineSchemes = map[string]bool{"machine-id": true, "macos-platform-uuid": true, "windows-machine-guid": true}

// matchIdentifiers returns the assets a batch's identifiers point at,
// oldest first. The hostname only counts when the batch has no machine
// identifier, or for an asset that has none of its own (one created before
// its agent sent one): an asset with another machine's identifier is a
// different machine with the same name, and the batch gets its own asset.
//
// It also undoes merges made that way before this rule: when the batch's
// machine identifier was added to an asset after another identifier of the
// same scheme, the batch's machine was folded into that asset by hostname.
// Its identifier is removed there, so the batch gets its own asset and the
// asset keeps the machine it had first.
func matchIdentifiers(ctx context.Context, tx pgx.Tx, idents []model.Identifier) ([]int64, error) {
	var strongS, strongV []string
	var hostname, machineScheme, machineValue string
	for _, id := range idents {
		switch {
		case id.Scheme == "hostname":
			hostname = id.Value
			continue
		case machineSchemes[id.Scheme] && machineScheme == "":
			machineScheme, machineValue = id.Scheme, id.Value
		}
		strongS, strongV = append(strongS, id.Scheme), append(strongV, id.Value)
	}

	if machineScheme != "" {
		// Folded in by hostname earlier: an older identifier of the same
		// scheme on the asset that holds this one.
		if _, err := tx.Exec(ctx, `DELETE FROM asset_identifiers mine
			WHERE mine.scheme = $1 AND mine.value = $2 AND EXISTS (
			  SELECT 1 FROM asset_identifiers other
			  WHERE other.asset_id = mine.asset_id AND other.scheme = mine.scheme AND other.value <> mine.value
			    AND other.first_seen < mine.first_seen)`, machineScheme, machineValue); err != nil {
			return nil, err
		}
	}

	query := func(schemes, values []string, onlyWithoutMachine bool) ([]int64, error) {
		rows, err := tx.Query(ctx, `SELECT DISTINCT COALESCE(a.merged_into, a.id)
			FROM asset_identifiers ai JOIN assets a ON a.id = ai.asset_id
			JOIN unnest($1::text[], $2::text[]) AS x(scheme, value) ON x.scheme = ai.scheme AND x.value = ai.value
			WHERE NOT $3 OR NOT EXISTS (
			  SELECT 1 FROM asset_identifiers m WHERE m.asset_id = ai.asset_id AND m.scheme = $4)`,
			schemes, values, onlyWithoutMachine, machineScheme)
		if err != nil {
			return nil, err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			return nil, err
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		return ids, nil
	}

	var ids []int64
	if len(strongS) > 0 {
		var err error
		if ids, err = query(strongS, strongV, false); err != nil {
			return nil, err
		}
	}
	if hostname == "" {
		return ids, nil
	}
	// The hostname adds assets that have no machine identifier (the same
	// machine before its agent sent one: a conflict to merge when the
	// identifiers also matched another asset), or all of them for a batch
	// without one.
	byName, err := query([]string{"hostname"}, []string{hostname}, machineScheme != "")
	if err != nil {
		return nil, err
	}
	for _, id := range byName {
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
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
	ids, err := matchIdentifiers(ctx, tx, b.Asset.Identifiers)
	if err != nil {
		return 0, false, nil, err
	}

	if len(ids) == 0 {
		// A release layout reported by its own directory for the first
		// time keeps the asset of its release (appadopt.go).
		pred, err := releasePredecessor(ctx, tx, b)
		if err != nil {
			return 0, false, nil, err
		}
		if pred != 0 {
			ids = []int64{pred}
			if _, err := tx.Exec(ctx, `UPDATE assets SET name = $2 WHERE id = $1 AND NOT name_by_person`, pred, b.Asset.Name); err != nil {
				return 0, false, nil, err
			}
		}
	}

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
