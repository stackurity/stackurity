package store

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// A project's notes for Ask Stackurity (migration 0119): a short text the
// project's admins write about it ("this is our payments API; host X is a
// staging box"). Ask reads it as background about the organisation, never
// as instructions (internal/ask/prompt.go).

// MaxProjectAskNotes is the longest a project's notes may be, in characters.
const MaxProjectAskNotes = 2000

// ProjectAskNotes is one project's notes.
type ProjectAskNotes struct {
	ProjectID int64      `json:"project_id"`
	Name      string     `json:"name"`
	Notes     string     `json:"notes"`
	UpdatedAt *time.Time `json:"updated_at"`
}

// cleanAskNotes trims notes and checks their length; line breaks are kept,
// other control characters are dropped.
func cleanAskNotes(notes string) (string, error) {
	if !utf8.ValidString(notes) {
		return "", fmt.Errorf("the notes are not valid text: %w", ErrInvalid)
	}
	notes = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r == '\r' || r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 {
			return -1
		}
		return r
	}, notes)
	notes = strings.TrimSpace(notes)
	if utf8.RuneCountInString(notes) > MaxProjectAskNotes {
		return "", fmt.Errorf("the notes are limited to %d characters: %w", MaxProjectAskNotes, ErrInvalid)
	}
	return notes, nil
}

// GetProjectAskNotes returns project id's notes, if the caller can see it.
func (s *Store) GetProjectAskNotes(ctx context.Context, id int64) (*ProjectAskNotes, error) {
	n := ProjectAskNotes{ProjectID: id}
	err := s.Pool.QueryRow(tenant.WithoutProject(ctx), `SELECT name, ask_notes, ask_notes_updated_at FROM projects WHERE id = $1`, id).
		Scan(&n.Name, &n.Notes, &n.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &n, nil
}

// SetProjectAskNotes replaces project id's notes and returns the notes it
// had before. The caller checks the role.
func (s *Store) SetProjectAskNotes(ctx context.Context, id int64, notes string) (previous string, err error) {
	notes, err = cleanAskNotes(notes)
	if err != nil {
		return "", err
	}
	ctx = tenant.WithoutProject(ctx)
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var archived bool
		if err := tx.QueryRow(ctx, `SELECT ask_notes, archived_at IS NOT NULL FROM projects WHERE id = $1 FOR UPDATE`, id).Scan(&previous, &archived); err != nil {
			return notFound(err)
		}
		if archived {
			return fmt.Errorf("this project is archived; restore it to change its notes: %w", ErrInvalid)
		}
		_, err := tx.Exec(ctx, `UPDATE projects SET ask_notes = $2, ask_notes_updated_at = now() WHERE id = $1`, id, notes)
		return err
	})
	return previous, err
}

// maxAskNotesProjects is the most projects whose notes go with one question.
const maxAskNotesProjects = 3

// ProjectAskNotesFor returns the notes of the projects a question is
// about, for Ask: the projects named in ids, or, with no ids, every
// project the caller can see (row-level security narrows a member with
// project access to theirs). Archived projects and empty notes are left
// out; at most three, by name.
func (s *Store) ProjectAskNotesFor(ctx context.Context, ids []int64) ([]ProjectAskNotes, error) {
	var filter any
	if len(ids) > 0 {
		filter = ids
	}
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `SELECT id, name, ask_notes, ask_notes_updated_at FROM projects
		WHERE archived_at IS NULL AND ask_notes <> '' AND ($1::bigint[] IS NULL OR id = ANY($1))
		ORDER BY lower(name), id LIMIT $2`, filter, maxAskNotesProjects)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProjectAskNotes
	for rows.Next() {
		var n ProjectAskNotes
		if err := rows.Scan(&n.ProjectID, &n.Name, &n.Notes, &n.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
