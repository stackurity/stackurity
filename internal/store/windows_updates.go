package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// WindowsUpdate is one Windows update as Microsoft's Security Update Guide
// lists it: the update (KB) that brings an update line to a build.
type WindowsUpdate struct {
	Line     string    // "Server 2022", "11 24H2"
	Build    string    // "10.0.20348.4294"
	KB       string    // "5066782"
	Kind     string    // Microsoft's subtype: "Security Update", "Standalone Security Update", ...
	Hotpatch bool      // a hotpatch build: applies only to hosts enrolled in hotpatching
	Monthly  bool      // the document's own Patch Tuesday update for the line
	Released time.Time // initial release of the monthly document that lists it
	Document string    // "2025-Oct"
}

// ReplaceWindowsUpdates stores the updates one monthly document lists,
// replacing what it listed before.
func (s *Store) ReplaceWindowsUpdates(ctx context.Context, document string, ups []WindowsUpdate) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM windows_updates WHERE document = $1`, document); err != nil {
			return err
		}
		seen := map[[3]string]bool{}
		rows := make([][]any, 0, len(ups))
		for _, u := range ups {
			k := [3]string{u.Line, u.Build, u.KB}
			if seen[k] {
				continue
			}
			seen[k] = true
			rows = append(rows, []any{u.Line, u.Build, u.KB, u.Kind, u.Hotpatch, u.Monthly, u.Released, document})
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"windows_updates"},
			[]string{"line", "build", "kb", "kind", "hotpatch", "monthly", "released", "document"}, pgx.CopyFromRows(rows))
		return err
	})
}

// WindowsUpdates returns the updates of an update line, oldest first.
func (s *Store) WindowsUpdates(ctx context.Context, line string) ([]WindowsUpdate, error) {
	rows, err := s.Pool.Query(ctx, `SELECT line, build, kb, kind, hotpatch, monthly, released, document FROM windows_updates
		WHERE line = $1 ORDER BY released, build, kb`, line)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[WindowsUpdate])
}

// AdvisoryIDs returns the ids of a feed's advisories that start with
// prefix and are not withdrawn.
func (s *Store) AdvisoryIDs(ctx context.Context, feed, prefix string) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id FROM advisories WHERE feed = $1 AND starts_with(id, $2) AND withdrawn IS NULL ORDER BY id`,
		feed, prefix)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// ComponentsWithPurlKey returns ids of components with current inventory
// whose versionless purl is key.
func (s *Store) ComponentsWithPurlKey(ctx context.Context, key string) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT c.id FROM components c WHERE c.purl_key = $1
		AND EXISTS (SELECT 1 FROM inventory i WHERE i.component_id = c.id AND i.removed_at IS NULL)`, key)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}
