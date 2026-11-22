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

// limitedScopes are the scopes of the batch's "limited" coverage items:
// files read in full whose format cannot list everything (a build.gradle
// without a lockfile: a dependency moved to a version catalog or a variable
// is not seen). What such a file no longer shows is not proven gone, so the
// rows located in it are never removed for being missing, even by a
// complete collection.
func limitedScopes(b *model.ObservationBatch) []string {
	out := []string{}
	for _, c := range b.Coverage {
		if c.Status == "limited" {
			out = append(out, c.Scope)
		}
	}
	return out
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
	return removeGone(ctx, tx, hostID, b, tok, goneKind{
		scheme: model.AppPathScheme, kind: model.AssetApplication, collector: AppsCollectorID, scope: "app:",
		listed: func(v string) bool { return listed[path.Clean(v)] },
		reason: "no longer reported by the host's agent: the directory was removed, is not the current release, or is no longer configured",
	})
}

// DockerCollectorID is the agent's collector for the images of a host's
// running containers (internal/collect/docker, "linux-docker").
const DockerCollectorID = "linux-docker"

// removeGoneImages marks the container images on a host that its agent's
// image list no longer names, as removeGoneApps does for applications: no
// container on the host runs them any more. History is kept; an image that
// runs again is present again.
func removeGoneImages(ctx context.Context, tx pgx.Tx, hostID int64, b *model.ObservationBatch, tok *int64) ([]int64, error) {
	listed := map[string]bool{}
	for _, r := range b.Images.Refs {
		listed[r] = true
	}
	return removeGone(ctx, tx, hostID, b, tok, goneKind{
		scheme: model.HostImageScheme, kind: model.AssetImage, collector: DockerCollectorID, scope: "image:",
		listed: func(v string) bool { return listed[v] },
		reason: "no longer reported by the host's agent: no running container uses this image",
	})
}

// goneKind describes host-scoped assets an agent lists on its host's batch.
type goneKind struct {
	scheme    string
	kind      model.AssetKind
	collector string
	scope     string // coverage scope prefix
	listed    func(value string) bool
	reason    string
}

// removeGone marks the host's assets of one kind that the agent's list no
// longer names: each gets a complete, empty collection (so its issues
// resolve as removed on the next evaluation, and a check waiting on it
// completes), a coverage note saying why, and collection status "removed".
func removeGone(ctx context.Context, tx pgx.Tx, hostID int64, b *model.ObservationBatch, tok *int64, k goneKind) ([]int64, error) {
	prefix := fmt.Sprintf("host:%d:", hostID)
	rows, err := tx.Query(ctx, `SELECT a.id, substr(ai.value, length($2) + 1) FROM asset_identifiers ai JOIN assets a ON a.id = ai.asset_id
		WHERE ai.scheme = $1 AND left(ai.value, length($2)) = $2 AND a.kind = $4 AND a.merged_into IS NULL
		  AND a.collection_status <> $3
		ORDER BY a.id FOR UPDATE OF a`, k.scheme, prefix, AssetRemoved, string(k.kind))
	if err != nil {
		return nil, err
	}
	type gone struct {
		id    int64
		value string
	}
	// An asset with several identifiers (a release layout's asset keeps its
	// old release's next to its own directory, appadopt.go) is present
	// while the list names any of them.
	var list []gone
	present := map[int64]bool{}
	for rows.Next() {
		var g gone
		if err := rows.Scan(&g.id, &g.value); err != nil {
			rows.Close()
			return nil, err
		}
		if k.listed(g.value) {
			present[g.id] = true
		} else if len(list) == 0 || list[len(list)-1].id != g.id {
			list = append(list, g)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	kept := list[:0]
	for _, g := range list {
		if !present[g.id] {
			kept = append(kept, g)
		}
	}
	list = kept
	var ids []int64
	for _, g := range list {
		var coll int64
		if err := tx.QueryRow(ctx, `INSERT INTO collections
			(asset_id, collector_id, collector_version, method, observed_at, complete, observation_count, submitted_by, proves_absence)
			VALUES ($1, $2, $3, $4, $5, true, 0, $6, true) RETURNING id`,
			g.id, k.collector, b.Collector.Version, b.Collector.Method, b.ObservedAt, tok).Scan(&coll); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE inventory SET removed_at = $2 WHERE asset_id = $1 AND removed_at IS NULL`, g.id, b.ObservedAt); err != nil {
			return nil, err
		}
		scope := k.scope + g.value
		if len(scope) > model.MaxFieldLen {
			scope = scope[:model.MaxFieldLen]
		}
		if _, err := tx.Exec(ctx, `INSERT INTO coverage (asset_id, collector_id, scope, status, reason, tool_version, last_attempt)
			VALUES ($1, $2, $3, 'skipped', $4, $5, $6)
			ON CONFLICT (asset_id, collector_id, scope) DO UPDATE SET status = EXCLUDED.status, reason = EXCLUDED.reason,
			  tool_version = EXCLUDED.tool_version, last_attempt = EXCLUDED.last_attempt`,
			g.id, k.collector, scope, k.reason, b.Collector.Version, b.ObservedAt); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO coverage_history (collection_id, scope, status, reason) VALUES ($1, $2, 'skipped', $3)`,
			coll, scope, k.reason); err != nil {
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

// webAssetSources are the evidence sources of front-end libraries found
// outside a package manager (collect/apps: webassets.go, bundles.go).
var webAssetSources = []string{"vendored", "cdn", "bundle", "source-map", "flutter-build"}

// webAssetsUnchecked reports whether a repository batch does not prove the
// front-end libraries found outside a package manager gone: it has no
// "web-assets:" coverage item marked "checked". A CI scan by a CLI older
// than the server's repository scan (or pkg/engine) reports the same
// repository under the same collector without looking; a scan that hit a
// read limit, an unreadable path or its time limit looked in part. Either
// way the rows of copies found before stay (their findings neither close
// nor reopen), while the batch still proves its lockfile rows gone.
func webAssetsUnchecked(b *model.ObservationBatch) bool {
	if b.Asset.Kind != model.AssetRepository {
		return false
	}
	for _, c := range b.Coverage {
		if strings.HasPrefix(c.Scope, "web-assets:") && c.Status == "checked" {
			return false
		}
	}
	return true
}
