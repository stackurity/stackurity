package store

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/model"
)

// AppsCollectorID is the agent's collector for deployed applications
// (cmd/stackurity, "linux-apps").
const AppsCollectorID = "linux-apps"

// blindPaths says what a collection can prove absent. A complete batch
// proves everything it left out is gone: ok with no paths. An incomplete
// one still proves it outside the places it could not read, when each
// coverage item that is not "checked" names an absolute path (an
// unreadable directory, a lockfile that failed to parse, an installed tree
// read in part): ok with those paths, and rows located there, or with no
// absolute location, stay. When any such item covers no path ("walk",
// "depth", "dpkg", "invalid-entries"), nothing can be proven: ok is false.
//
// Production case: phpMyAdmin's tmp/twig cache directory belongs to the
// web server user, so the agent could not read it, every collection of the
// application was incomplete, and the libraries of the version it replaced
// stayed installed (and their issues open) for good.
func blindPaths(b *model.ObservationBatch) ([]string, bool) {
	if b.Complete {
		return []string{}, true
	}
	out := []string{}
	for _, c := range b.Coverage {
		if c.Status == "checked" {
			continue
		}
		p, ok := coveragePath(c.Scope)
		if !ok {
			return nil, false
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		// Incomplete without saying where: nothing is proven.
		return nil, false
	}
	return out, true
}

// coveragePath is the host path a coverage scope is about:
// "path:/srv/app/tmp", "lockfile:/srv/app/yarn.lock", "pack:java:/srv/app/x.jar",
// "npm-installed:/srv/app/node_modules". Composer's installed.json stands
// for the vendor directory it describes. Relative scopes (a repository
// scan) and scopes without a path give false.
func coveragePath(scope string) (string, bool) {
	i := strings.Index(scope, ":/")
	if i < 0 {
		return "", false
	}
	p := path.Clean(scope[i+1:])
	if p == "/" {
		return "", false // the whole filesystem: nothing is proven
	}
	if strings.HasPrefix(scope, "composer-installed:") && strings.HasSuffix(p, "/composer/installed.json") {
		p = path.Dir(path.Dir(p))
	}
	return p, true
}

// AssetRemoved is the collection status of an application whose host's
// agent no longer reports its directory.
const AssetRemoved = "removed"

// removeGoneApps marks the applications on a host that its agent's app
// list no longer names: each gets a complete, empty collection (so its
// issues resolve as removed on the next evaluation, and a check waiting on
// it completes), a coverage note saying why, and collection status
// "removed". An application that reports again later is present again.
func removeGoneApps(ctx context.Context, tx pgx.Tx, hostID int64, b *model.ObservationBatch, tok *int64) ([]int64, error) {
	listed := map[string]bool{}
	for _, d := range b.Apps.Dirs {
		listed[path.Clean(d)] = true
	}
	prefix := fmt.Sprintf("host:%d:", hostID)
	rows, err := tx.Query(ctx, `SELECT a.id, substr(ai.value, length($2) + 1) FROM asset_identifiers ai JOIN assets a ON a.id = ai.asset_id
		WHERE ai.scheme = $1 AND left(ai.value, length($2)) = $2 AND a.kind = 'application' AND a.merged_into IS NULL
		  AND a.collection_status <> $3
		ORDER BY a.id FOR UPDATE OF a`, model.AppPathScheme, prefix, AssetRemoved)
	if err != nil {
		return nil, err
	}
	type gone struct {
		id  int64
		dir string
	}
	var list []gone
	for rows.Next() {
		var g gone
		if err := rows.Scan(&g.id, &g.dir); err != nil {
			rows.Close()
			return nil, err
		}
		if !listed[path.Clean(g.dir)] {
			list = append(list, g)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var ids []int64
	for _, g := range list {
		var coll int64
		if err := tx.QueryRow(ctx, `INSERT INTO collections
			(asset_id, collector_id, collector_version, method, observed_at, complete, observation_count, submitted_by, proves_absence)
			VALUES ($1, $2, $3, $4, $5, true, 0, $6, true) RETURNING id`,
			g.id, AppsCollectorID, b.Collector.Version, b.Collector.Method, b.ObservedAt, tok).Scan(&coll); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE inventory SET removed_at = $2 WHERE asset_id = $1 AND removed_at IS NULL`, g.id, b.ObservedAt); err != nil {
			return nil, err
		}
		reason := "no longer reported by the host's agent: the directory was removed, is not the current release, or is no longer configured"
		scope := "app:" + g.dir
		if len(scope) > model.MaxFieldLen {
			scope = scope[:model.MaxFieldLen]
		}
		if _, err := tx.Exec(ctx, `INSERT INTO coverage (asset_id, collector_id, scope, status, reason, tool_version, last_attempt)
			VALUES ($1, $2, $3, 'skipped', $4, $5, $6)
			ON CONFLICT (asset_id, collector_id, scope) DO UPDATE SET status = EXCLUDED.status, reason = EXCLUDED.reason,
			  tool_version = EXCLUDED.tool_version, last_attempt = EXCLUDED.last_attempt`,
			g.id, AppsCollectorID, scope, reason, b.Collector.Version, b.ObservedAt); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO coverage_history (collection_id, scope, status, reason) VALUES ($1, $2, 'skipped', $3)`,
			coll, scope, reason); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE assets SET collection_status = $2 WHERE id = $1`, g.id, AssetRemoved); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO jobs (kind, payload, dedupe_key, run_at)
			VALUES ('evaluate', jsonb_build_object('asset_id', $1::bigint), 'evaluate:asset:' || $1::bigint, now() + interval '5 seconds')
			ON CONFLICT (COALESCE(workspace_id, 0), dedupe_key) WHERE dedupe_key IS NOT NULL AND done_at IS NULL AND failed_at IS NULL
			DO UPDATE SET requeue = true WHERE jobs.locked_at IS NOT NULL`, g.id); err != nil {
			return nil, err
		}
		ids = append(ids, g.id)
	}
	return ids, nil
}
