package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Project limits, the read-only state and the report mode of an
// organisation (docs/asset-limits.md). Like the monitored-asset limit,
// each is unset on a self-hosted install: nothing in the core sets them.
// An instance administrator may, and a hosted edition's billing does.

// ErrProjectLimit matches a *ProjectLimitError with errors.Is.
var ErrProjectLimit = errors.New("project limit reached")

// ProjectLimitError means a new project was refused because the
// organisation has as many active projects as its limit allows.
type ProjectLimitError struct {
	Limit    int64
	Projects int64
}

func (e *ProjectLimitError) Error() string {
	return fmt.Sprintf("this organisation has %d of %d projects allowed, so no new project can be made. "+
		"Existing projects are kept. Archive a project you no longer need, or ask an admin to raise the limit", e.Projects, e.Limit)
}

func (e *ProjectLimitError) Is(target error) bool { return target == ErrProjectLimit }

// ErrReadOnly matches a *ReadOnlyError with errors.Is.
var ErrReadOnly = errors.New("organisation is read-only")

// ReadOnlyError means the organisation is read-only: what it has can be
// seen, but nothing new is collected.
type ReadOnlyError struct {
	Since  time.Time
	Reason string
}

func (e *ReadOnlyError) Error() string {
	msg := "this organisation is read-only, so nothing new is collected: everything already here can still be viewed"
	if e.Reason != "" {
		msg += ". " + strings.TrimSuffix(e.Reason, ".")
	}
	return msg
}

func (e *ReadOnlyError) Is(target error) bool { return target == ErrReadOnly }

// Report modes.
const (
	ReportFull  = "full"
	ReportTrial = "trial"
)

// projectLimitLock serialises the check-and-create of projects within one
// workspace, like assetLimitLock.
const projectLimitLock = 726_354_141

// readOnly returns a *ReadOnlyError when workspace ws is read-only.
func readOnly(ctx context.Context, db q, ws int64) error {
	var since *time.Time
	var reason string
	err := db.QueryRow(ctx, `SELECT read_only_at, read_only_reason FROM workspaces WHERE id = $1`, ws).Scan(&since, &reason)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && since == nil {
		return nil
	}
	if err != nil {
		return err
	}
	return &ReadOnlyError{Since: *since, Reason: reason}
}

// CheckWritable returns a *ReadOnlyError when the current workspace is
// read-only, else nil. System work (no workspace) is never read-only.
func (s *Store) CheckWritable(ctx context.Context) error {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil
	}
	return readOnly(tenant.System(ctx), s.Pool, ws)
}

// SetReadOnly makes workspace ws read-only from since with a reason for
// its members, or writable again when since is nil. A workspace already
// read-only keeps its earlier time (the reason is updated), so how long it
// has been read-only is not reset by setting it again. For instance
// administration and a hosted edition's billing.
func (s *Store) SetReadOnly(ctx context.Context, ws int64, since *time.Time, reason string) error {
	if len(reason) > 500 {
		reason = reason[:500]
	}
	tag, err := s.Pool.Exec(tenant.System(ctx), `UPDATE workspaces
		SET read_only_at = CASE WHEN $2::timestamptz IS NULL THEN NULL ELSE COALESCE(read_only_at, $2) END,
		    read_only_reason = CASE WHEN $2::timestamptz IS NULL THEN '' ELSE $3 END
		WHERE id = $1`, ws, since, reason)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetProjectLimit sets workspace ws's project limit; nil removes it.
func (s *Store) SetProjectLimit(ctx context.Context, ws int64, limit *int64) error {
	if limit != nil && (*limit < 0 || *limit > 1_000_000) {
		return fmt.Errorf("project limit must be between 0 and 1000000: %w", ErrInvalid)
	}
	tag, err := s.Pool.Exec(tenant.System(ctx), `UPDATE workspaces SET project_limit = $2 WHERE id = $1`, ws, limit)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetReportMode sets workspace ws's report mode: full or trial.
func (s *Store) SetReportMode(ctx context.Context, ws int64, mode string) error {
	if mode != ReportFull && mode != ReportTrial {
		return fmt.Errorf("report mode must be full or trial: %w", ErrInvalid)
	}
	tag, err := s.Pool.Exec(tenant.System(ctx), `UPDATE workspaces SET report_mode = $2 WHERE id = $1`, ws, mode)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ReportMode is the current workspace's report mode; full outside any
// workspace.
func (s *Store) ReportMode(ctx context.Context) (string, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return ReportFull, nil
	}
	mode := ReportFull
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT report_mode FROM workspaces WHERE id = $1`, ws).Scan(&mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return ReportFull, nil
	}
	return mode, err
}

// ReadOnlyState is shown to an organisation's members while it is
// read-only.
type ReadOnlyState struct {
	Since  time.Time `json:"since"`
	Reason string    `json:"reason"`
}

// WorkspaceState is what the dashboard shows every member about the
// organisation's state.
type WorkspaceState struct {
	ReadOnly   *ReadOnlyState `json:"read_only"`
	ReportMode string         `json:"report_mode"`
}

// GetWorkspaceState reads workspace ws's read-only state and report mode.
func (s *Store) GetWorkspaceState(ctx context.Context, ws int64) (*WorkspaceState, error) {
	var since *time.Time
	st := &WorkspaceState{}
	var reason string
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT read_only_at, read_only_reason, report_mode FROM workspaces WHERE id = $1`, ws).
		Scan(&since, &reason, &st.ReportMode)
	if err != nil {
		return nil, notFound(err)
	}
	if since != nil {
		st.ReadOnly = &ReadOnlyState{Since: *since, Reason: reason}
	}
	return st, nil
}

// projectLimit reads a workspace's project limit; nil means none.
func projectLimit(ctx context.Context, db q, ws int64) (*int64, error) {
	var limit *int64
	err := db.QueryRow(ctx, `SELECT project_limit FROM workspaces WHERE id = $1`, ws).Scan(&limit)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return limit, err
}

// activeProjects counts workspace ws's projects that are not archived.
func activeProjects(ctx context.Context, db q, ws int64) (int64, error) {
	var n int64
	err := db.QueryRow(ctx, `SELECT count(*) FROM projects WHERE workspace_id = $1 AND archived_at IS NULL`, ws).Scan(&n)
	return n, err
}

// checkNewProject is called in the transaction that adds an active project
// (a new one, or one taken out of the archive). It returns a
// *ProjectLimitError when the workspace may not have another; the lock is
// held until the transaction ends, so two admins cannot both take the last
// place.
func checkNewProject(ctx context.Context, tx pgx.Tx) error {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil
	}
	sys := tenant.System(ctx)
	limit, err := projectLimit(sys, tx, ws)
	if err != nil || limit == nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, $2::int)`, projectLimitLock, ws); err != nil {
		return err
	}
	var n int64
	err = asSystem(ctx, tx, func() error {
		n, err = activeProjects(ctx, tx, ws)
		return err
	})
	if err != nil {
		return err
	}
	if n >= *limit {
		return &ProjectLimitError{Limit: *limit, Projects: n}
	}
	return nil
}

// CollectingWorkspaceIDs lists enabled workspaces that are not read-only:
// those background collection, evaluation and notifications run for.
func (s *Store) CollectingWorkspaceIDs(ctx context.Context) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id FROM workspaces WHERE disabled_at IS NULL AND read_only_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// DeletedWorkspace describes a workspace DeleteWorkspace removed.
type DeletedWorkspace struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Assets int64  `json:"assets"`
	// Users are the accounts removed with it: members with no other
	// workspace who are not instance administrators.
	Users []string `json:"users"`
}

// DeleteWorkspace permanently removes workspace ws and everything in it
// (every tenant table cascades from workspaces), and the accounts of its
// members that belong to no other workspace and are not instance
// administrators. The default workspace cannot be deleted. Nothing in the
// core calls it; a hosted edition does, for organisations whose data its
// terms say is removed. One transaction: all of it goes, or none.
//
// guard, when not nil, runs in that transaction once the workspace row is
// locked (FOR UPDATE), before anything is deleted: an error from it stops
// the deletion and is returned. A caller re-checks there what must still
// hold (the workspace is still read-only, nothing was paid), and removes
// rows of its own tables that do not cascade.
func (s *Store) DeleteWorkspace(ctx context.Context, ws int64, guard func(ctx context.Context, tx pgx.Tx) error) (*DeletedWorkspace, error) {
	if ws == tenant.DefaultWorkspace {
		return nil, fmt.Errorf("the default workspace cannot be deleted: %w", ErrConflict)
	}
	sys := tenant.System(ctx)
	d := &DeletedWorkspace{ID: ws, Users: []string{}}
	err := pgx.BeginFunc(sys, s.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(sys, `SELECT name, slug FROM workspaces WHERE id = $1 FOR UPDATE`, ws).Scan(&d.Name, &d.Slug); err != nil {
			return notFound(err)
		}
		if guard != nil {
			if err := guard(sys, tx); err != nil {
				return err
			}
		}
		if err := tx.QueryRow(sys, `SELECT count(*) FROM assets WHERE workspace_id = $1 AND merged_into IS NULL`, ws).Scan(&d.Assets); err != nil {
			return err
		}
		rows, err := tx.Query(sys, `SELECT u.id, u.email FROM users u JOIN workspace_members m ON m.user_id = u.id AND m.workspace_id = $1
			WHERE NOT u.instance_admin AND NOT EXISTS (SELECT 1 FROM workspace_members o WHERE o.user_id = u.id AND o.workspace_id <> $1)
			ORDER BY u.id`, ws)
		if err != nil {
			return err
		}
		type user struct {
			ID    int64
			Email string
		}
		users, err := pgx.CollectRows(rows, pgx.RowToStructByPos[user])
		if err != nil {
			return err
		}
		if _, err := tx.Exec(sys, `DELETE FROM workspaces WHERE id = $1`, ws); err != nil {
			return err
		}
		for _, u := range users {
			// The one reference to users that does not cascade or clear
			// itself: a conflict they resolved in a workspace they left.
			if _, err := tx.Exec(sys, `UPDATE identity_conflicts SET resolved_by = NULL WHERE resolved_by = $1`, u.ID); err != nil {
				return err
			}
			if _, err := tx.Exec(sys, `DELETE FROM users WHERE id = $1`, u.ID); err != nil {
				return err
			}
			d.Users = append(d.Users, u.Email)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return d, nil
}
