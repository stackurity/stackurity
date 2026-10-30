package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// WindowsProgram is one installed program as the Windows agent reports it
// (an Add/Remove Programs entry): the component, its DisplayName and its
// Publisher.
type WindowsProgram struct {
	ComponentID int64
	Name        string
	Publisher   string
	Version     string
}

// WindowsPrograms returns the distinct programs with current inventory that
// the Windows agent read from the registry (inventory evidence
// registry_view), in the caller's scope.
func (s *Store) WindowsPrograms(ctx context.Context) ([]WindowsProgram, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT c.id, c.name, COALESCE(i.evidence->>'publisher', ''), i.version
		FROM inventory i JOIN components c ON c.id = i.component_id
		WHERE i.removed_at IS NULL AND c.type = 'generic' AND i.evidence->>'registry_view' IS NOT NULL
		ORDER BY 1, 3, 4`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[WindowsProgram])
}
