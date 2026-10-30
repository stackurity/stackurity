package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Coverage-gap report queries. They run in system scope for instance
// administrators and return counts and type names only: never asset or
// workspace names, file paths, or package lists.

// GapTotals counts what the report covers: active workspaces and current
// assets.
func (s *Store) GapTotals(ctx context.Context) (workspaces, assets int64, err error) {
	err = s.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM workspaces WHERE disabled_at IS NULL),
		(SELECT count(*) FROM assets a JOIN workspaces w ON w.id = a.workspace_id WHERE a.merged_into IS NULL AND w.disabled_at IS NULL)`).
		Scan(&workspaces, &assets)
	return workspaces, assets, err
}

// GapRow is one kind of gap: how many assets, workspaces and (for
// components) distinct components it affects.
type GapRow struct {
	Kind       string
	Assets     int64
	Workspaces int64
	Components int64
}

// UnreadFileGaps counts files a scan found but no reader or stack pack could
// read, by kind ("hex:mix.lock"): collector coverage scopes reported as
// unsupported. A scope is "<kind>:<path>"; only kinds in known are named (the
// path is never read), any other unsupported scope counts as "other".
func (s *Store) UnreadFileGaps(ctx context.Context, known []string) ([]GapRow, error) {
	rows, err := s.Pool.Query(ctx, `SELECT k.kind, count(DISTINCT a.id), count(DISTINCT a.workspace_id), 0::bigint
		FROM coverage c
		JOIN assets a ON a.id = c.asset_id AND a.merged_into IS NULL
		JOIN workspaces w ON w.id = a.workspace_id AND w.disabled_at IS NULL
		CROSS JOIN LATERAL (SELECT COALESCE(
		  (SELECT kn FROM unnest($1::text[]) kn WHERE c.scope = kn OR left(c.scope, length(kn) + 1) = kn || ':' LIMIT 1),
		  'other') AS kind) k
		WHERE c.status = 'unsupported'
		GROUP BY 1 ORDER BY 2 DESC, 1`, known)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[GapRow])
}

// VulnerabilitySourceGaps counts current components with no vulnerability
// source (coverage unsupported), by purl type and a reason category derived
// from the reasons the matcher writes (intel.Evaluator), never the reason
// text itself. Vendor builds are counted per repository, which the reason
// names from the lifecycle overlay ("built by MongoDB's repository
// (repo.mongodb.org), not by ...").
func (s *Store) VulnerabilitySourceGaps(ctx context.Context) ([]GapRow, error) {
	rows, err := s.Pool.Query(ctx, `SELECT x.kind, count(DISTINCT x.asset_id), count(DISTINCT x.workspace_id), count(DISTINCT x.component_id)
		FROM (SELECT i.asset_id, a.workspace_id, i.component_id, c.type || '|' || CASE
		    WHEN c.purl_key = 'pkg:generic/windows' AND i.coverage_reason ILIKE '%hotpatch%' THEN 'windows_hotpatch'
		    WHEN c.purl_key = 'pkg:generic/windows' AND i.coverage_reason LIKE '%Extended Security Updates%' THEN 'windows_esu'
		    WHEN c.purl_key = 'pkg:generic/windows' THEN 'windows_release'
		    WHEN c.type = 'generic' AND i.evidence->>'registry_view' IS NOT NULL AND i.coverage_reason LIKE 'recognised as %' THEN 'windows_program_unmatched'
		    WHEN c.type = 'generic' AND i.evidence->>'registry_view' IS NOT NULL THEN 'windows_program'
		    WHEN i.coverage_reason LIKE 'built by %, not by the distribution%' THEN 'vendor_build|' || substring(i.coverage_reason from '^built by (.*?), not by the distribution')
		    WHEN i.coverage_reason LIKE 'runtime installed outside a package manager%' THEN 'runtime'
		    WHEN i.coverage_reason LIKE 'Kubernetes component%' THEN 'kubernetes'
		    WHEN i.coverage_reason LIKE 'managed service%' THEN 'managed_service'
		    WHEN i.coverage_reason LIKE '%have no vulnerability source%' OR i.coverage_reason LIKE '%has no vulnerability source%' THEN 'distribution'
		    WHEN i.coverage_reason LIKE 'no vulnerability source for %' THEN 'ecosystem'
		    ELSE 'other' END AS kind
		  FROM inventory i
		  JOIN components c ON c.id = i.component_id
		  JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL
		  JOIN workspaces w ON w.id = a.workspace_id AND w.disabled_at IS NULL
		  WHERE i.removed_at IS NULL AND i.coverage = 'unsupported') x
		GROUP BY 1 ORDER BY 2 DESC, 1`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[GapRow])
}

// LifecycleCandidate is one installed version of a component that may have
// lifecycle data, with the assets and workspaces it is on (ids only, for
// counting; they are never returned by the report).
type LifecycleCandidate struct {
	Type       string
	PurlKey    string
	Version    string
	Kind       string // evidence kind of generic rows
	Assets     []int64
	Workspaces []int64
}

// LifecycleCandidates returns current inventory that the lifecycle matcher
// could map: components whose versionless purl is one of keys, matches a
// LIKE pattern in likes or the regular expression re, and generic runtime,
// operating-system, Kubernetes and managed-service rows.
func (s *Store) LifecycleCandidates(ctx context.Context, keys, likes []string, re string) ([]LifecycleCandidate, error) {
	rows, err := s.Pool.Query(ctx, `SELECT c.type, c.purl_key, i.version, COALESCE(i.evidence->>'kind', ''),
		  array_agg(DISTINCT i.asset_id ORDER BY i.asset_id), array_agg(DISTINCT a.workspace_id ORDER BY a.workspace_id)
		FROM inventory i
		JOIN components c ON c.id = i.component_id
		JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL
		JOIN workspaces w ON w.id = a.workspace_id AND w.disabled_at IS NULL
		WHERE i.removed_at IS NULL AND (
		  lower(c.purl_key) = ANY($1) OR lower(c.purl_key) LIKE ANY($2) OR c.purl_key ~ $3
		  OR (c.type = 'generic' AND i.evidence->>'kind' IN ('runtime', 'operating-system', 'kubernetes', 'managed-service')))
		GROUP BY 1, 2, 3, 4`, keys, likes, re)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[LifecycleCandidate])
}
