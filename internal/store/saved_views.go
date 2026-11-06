package store

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// SavedView is a person's named filter on a dashboard page: the page's
// query string, as the page puts it in its address.
type SavedView struct {
	ID        int64     `json:"id"`
	Page      string    `json:"page"`
	Name      string    `json:"name"`
	Query     string    `json:"query"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SavedViewsMax is how many views one person keeps per page.
const SavedViewsMax = 50

// SavedViewPages are the pages that have saved views.
var SavedViewPages = []string{"fixes"}

var savedViewPage = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,39}$`)

const savedViewCols = `id, page, name, query, created_at, updated_at`

func scanSavedView(r pgx.CollectableRow) (SavedView, error) {
	var v SavedView
	err := r.Scan(&v.ID, &v.Page, &v.Name, &v.Query, &v.CreatedAt, &v.UpdatedAt)
	return v, err
}

// ListSavedViews returns the user's views on page, by name.
func (s *Store) ListSavedViews(ctx context.Context, userID int64, page string) ([]SavedView, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+savedViewCols+` FROM saved_views
		WHERE workspace_id = stackurity_ws() AND user_id = $1 AND page = $2 ORDER BY lower(name), id`, userID, page)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanSavedView)
}

// SaveView stores the user's view on page under name, replacing the query
// of one with the same name. A page keeps at most SavedViewsMax views.
func (s *Store) SaveView(ctx context.Context, userID int64, page, name, query string) (*SavedView, error) {
	name = strings.TrimSpace(name)
	query = strings.TrimPrefix(strings.TrimSpace(query), "?")
	switch {
	case !savedViewPage.MatchString(page) || !containsString(SavedViewPages, page):
		return nil, fmt.Errorf("page must be one of %s: %w", strings.Join(SavedViewPages, ", "), ErrInvalid)
	case name == "" || utf8.RuneCountInString(name) > 60:
		return nil, fmt.Errorf("name must be 1 to 60 characters: %w", ErrInvalid)
	case len(query) > 2000:
		return nil, fmt.Errorf("query must be at most 2000 characters: %w", ErrInvalid)
	case strings.ContainsAny(query, "#\n\r"):
		return nil, fmt.Errorf("query must be a query string (no # or line breaks): %w", ErrInvalid)
	}
	var out *SavedView
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		// One person saving twice at once: the count below sees the other.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('saved_views:' || stackurity_ws() || ':' || $1::bigint, 0))`, userID); err != nil {
			return err
		}
		var n int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM saved_views WHERE workspace_id = stackurity_ws() AND user_id = $1 AND page = $2 AND name <> $3`,
			userID, page, name).Scan(&n); err != nil {
			return err
		}
		if n >= SavedViewsMax {
			return fmt.Errorf("you can keep %d views on a page; delete one first: %w", SavedViewsMax, ErrInvalid)
		}
		rows, err := tx.Query(ctx, `INSERT INTO saved_views (user_id, page, name, query) VALUES ($1, $2, $3, $4)
			ON CONFLICT (workspace_id, user_id, page, name) DO UPDATE SET query = EXCLUDED.query, updated_at = now()
			RETURNING `+savedViewCols, userID, page, name, query)
		if err != nil {
			return err
		}
		v, err := pgx.CollectExactlyOneRow(rows, scanSavedView)
		if err != nil {
			return err
		}
		out = &v
		return nil
	})
	return out, err
}

// DeleteSavedView deletes the user's view id; another person's is not found.
func (s *Store) DeleteSavedView(ctx context.Context, userID, id int64) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM saved_views WHERE id = $1 AND user_id = $2 AND workspace_id = stackurity_ws()`, id, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
