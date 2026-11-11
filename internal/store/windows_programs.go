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

// NamedPackage is one installed deb or rpm package whose name matched a
// pattern: the component and the installed version.
type NamedPackage struct {
	ComponentID int64
	Type        string
	PurlKey     string
	Purl        string
	Name        string
	Version     string
}

// PackagesNamed returns the distinct deb and rpm packages with current
// inventory whose name matches pattern (a POSIX regular expression, without
// regard to case), in the caller's scope: the vendor build catalogue's
// candidates (internal/vendorbuilds NamePattern).
func (s *Store) PackagesNamed(ctx context.Context, pattern string) ([]NamedPackage, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT c.id, c.type, c.purl_key, i.purl, c.name, i.version
		FROM inventory i JOIN components c ON c.id = i.component_id
		WHERE i.removed_at IS NULL AND c.type IN ('deb', 'rpm') AND c.name ~* $1
		ORDER BY 1, 4, 6`, pattern)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[NamedPackage])
}
