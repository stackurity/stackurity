package store

import (
	"context"
	"errors"
	"path"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/model"
)

// An agent from 0.20.24 on reports an application deployed in a release
// layout (releases/ or versions/ plus a current link: Capistrano, Deployer,
// Envoyer, Ghost-CLI) by the layout's own directory, with app_home set,
// where older agents reported its current release
// (/var/www/ghost/versions/6.52.0). The first such report would make a new
// asset and remove the old one: its issues resolved as removed and came
// back as new ones, and its projects, snoozes and assignments stayed
// behind. Instead the report is taken by the asset of a release in that
// layout on the same host: it gets the new identifier and keeps its
// history.

// releasePredecessor returns the asset a release-layout report takes over,
// or 0: an application on the same host identified by a release in the
// batch's layout, the release the batch scanned first (app_dir), else the
// one seen last.
func releasePredecessor(ctx context.Context, tx pgx.Tx, b *model.ObservationBatch) (int64, error) {
	if b.Asset.Kind != model.AssetApplication || len(b.Asset.Identifiers) != 1 || b.Asset.Identifiers[0].Scheme != model.AppPathScheme {
		return 0, nil
	}
	home := b.Asset.Attributes["app_home"]
	value := b.Asset.Identifiers[0].Value // host:<id>:<path>, set by the API
	rest, ok := strings.CutPrefix(value, "host:")
	if home == "" || !ok {
		return 0, nil
	}
	hostID, dir, ok := strings.Cut(rest, ":")
	if !ok || !path.IsAbs(dir) || path.Clean(dir) != path.Clean(home) {
		return 0, nil
	}
	prefix := "host:" + hostID + ":" + path.Clean(dir)
	current := "host:" + hostID + ":" + path.Clean(b.Asset.Attributes["app_dir"])
	var id int64
	err := tx.QueryRow(ctx, `SELECT a.id FROM asset_identifiers ai JOIN assets a ON a.id = ai.asset_id
		WHERE ai.scheme = $1 AND a.kind = 'application' AND a.merged_into IS NULL
		  AND (left(ai.value, length($2)) = $2 OR left(ai.value, length($3)) = $3)
		ORDER BY ai.value = $4 DESC, a.last_seen DESC, a.id
		LIMIT 1`, model.AppPathScheme, prefix+"/releases/", prefix+"/versions/", current).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return id, err
}
