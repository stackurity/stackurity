package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// InstalledPack is a stack pack installed on this server. The archive is
// fetched separately.
type InstalledPack struct {
	ID              string          `json:"id"`
	Version         string          `json:"version"`
	Manifest        json.RawMessage `json:"manifest"`
	SHA256          string          `json:"sha256"`
	Trust           string          `json:"trust"`
	Enabled         bool            `json:"enabled"`
	InstalledBy     *int64          `json:"installed_by"`
	InstalledAt     time.Time       `json:"installed_at"`
	PreviousVersion *string         `json:"previous_version"`
}

const packCols = `id, version, manifest, sha256, trust, enabled, installed_by, installed_at, previous_version`

func (s *Store) ListPacks(ctx context.Context) ([]InstalledPack, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+packCols+` FROM packs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[InstalledPack])
}

func (s *Store) GetPack(ctx context.Context, id string) (*InstalledPack, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+packCols+` FROM packs WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	p, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[InstalledPack])
	return p, notFound(err)
}

// PackArchive returns the installed archive and its trust.
func (s *Store) PackArchive(ctx context.Context, id string) ([]byte, string, error) {
	var b []byte
	var trust string
	err := s.Pool.QueryRow(ctx, `SELECT archive, trust FROM packs WHERE id = $1`, id).Scan(&b, &trust)
	return b, trust, notFound(err)
}

// InstallPack installs or upgrades a pack, keeping the version it replaces.
func (s *Store) InstallPack(ctx context.Context, id, version string, manifest json.RawMessage, archive []byte, sha, trust string, by int64) error {
	var who *int64
	if by > 0 {
		who = &by
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO packs (id, version, manifest, archive, sha256, trust, installed_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (id) DO UPDATE SET
		  previous_version = CASE WHEN packs.sha256 = EXCLUDED.sha256 THEN packs.previous_version ELSE packs.version END,
		  previous_archive = CASE WHEN packs.sha256 = EXCLUDED.sha256 THEN packs.previous_archive ELSE packs.archive END,
		  previous_trust = CASE WHEN packs.sha256 = EXCLUDED.sha256 THEN packs.previous_trust ELSE packs.trust END,
		  version = EXCLUDED.version, manifest = EXCLUDED.manifest, archive = EXCLUDED.archive, sha256 = EXCLUDED.sha256,
		  trust = EXCLUDED.trust, enabled = true, installed_by = EXCLUDED.installed_by, installed_at = now()`,
		id, version, manifest, archive, sha, trust, who)
	return err
}

// PreviousPackArchive returns the version a rollback would restore.
func (s *Store) PreviousPackArchive(ctx context.Context, id string) ([]byte, string, error) {
	var b []byte
	var trust *string
	err := s.Pool.QueryRow(ctx, `SELECT previous_archive, previous_trust FROM packs WHERE id = $1`, id).Scan(&b, &trust)
	if err != nil {
		return nil, "", notFound(err)
	}
	if b == nil || trust == nil {
		return nil, "", ErrNotFound
	}
	return b, *trust, nil
}

func (s *Store) SetPackEnabled(ctx context.Context, id string, on bool) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE packs SET enabled = $2 WHERE id = $1`, id, on)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) DeletePack(ctx context.Context, id string) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM packs WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// UnsupportedFiles counts files reported as unsupported, by their scope's
// first part ("maven", "cargo"): what packs could read. In workspace scope it
// counts that workspace's assets; in system scope, every workspace's.
func (s *Store) UnsupportedFiles(ctx context.Context) (map[string]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT split_part(c.scope, ':', 1), count(*) FROM coverage c
		JOIN assets a ON a.id = c.asset_id AND a.merged_into IS NULL
		WHERE c.status = 'unsupported' GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// RescanTargets lists git integrations whose repository has unsupported files
// of the given kinds, so installing a pack can re-scan them at once.
func (s *Store) RescanTargets(ctx context.Context, kinds []string) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT i.id FROM integrations i
		JOIN coverage c ON c.asset_id = i.asset_id
		WHERE i.enabled AND c.status = 'unsupported' AND split_part(c.scope, ':', 1) = ANY($1)`, kinds)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}
