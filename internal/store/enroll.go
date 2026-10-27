package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

type Enrollment struct {
	ID           int64      `json:"id"`
	Prefix       string     `json:"prefix"`
	Label        string     `json:"label"`
	Environment  string     `json:"environment"`
	AppDirs      []string   `json:"app_dirs"`
	DiscoverApps bool       `json:"discover_apps"`
	UsesLeft     int        `json:"uses_left"`
	CreatedBy    *int64     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	LastUsedAt   *time.Time `json:"last_used_at"`
	RevokedAt    *time.Time `json:"revoked_at"`
	WorkspaceID  int64      `json:"workspace_id"`
	// ProjectID: hosts enrolled with this code (and the assets their agent
	// reports) are added to this project.
	ProjectID *int64 `json:"project_id"`
}

const enrollmentCols = `id, prefix, label, environment, app_dirs, discover_apps, uses_left, created_by, created_at,
	expires_at, last_used_at, revoked_at, workspace_id, project_id`

// ErrEnrollmentInvalid hides whether a code is unknown, used up, expired or
// revoked, so the public endpoint reveals nothing about codes.
var ErrEnrollmentInvalid = errors.New("enrollment code is invalid or expired")

// CreateEnrollment stores a new code and returns it once.
func (s *Store) CreateEnrollment(ctx context.Context, e Enrollment, ttl time.Duration, createdBy int64) (*Enrollment, string, error) {
	secret, prefix, err := auth.NewToken("enr")
	if err != nil {
		return nil, "", err
	}
	if e.AppDirs == nil {
		e.AppDirs = []string{}
	}
	var by *int64
	if createdBy > 0 {
		by = &createdBy
	}
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `INSERT INTO enrollments (prefix, code_hash, label, environment, app_dirs, discover_apps, uses_left, created_by, expires_at, project_id)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8, now() + make_interval(secs => $9), $10
		WHERE $10::bigint IS NULL OR EXISTS (SELECT 1 FROM projects WHERE id = $10 AND archived_at IS NULL)
		RETURNING `+enrollmentCols,
		prefix, auth.HashToken(secret), e.Label, e.Environment, e.AppDirs, e.DiscoverApps, e.UsesLeft, by, ttl.Seconds(), e.ProjectID)
	if err != nil {
		return nil, "", err
	}
	out, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Enrollment])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", fmt.Errorf("no such project: %w", ErrInvalid)
	}
	return out, secret, err
}

// ListEnrollments returns codes that can still be used, newest first.
func (s *Store) ListEnrollments(ctx context.Context) ([]Enrollment, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+enrollmentCols+` FROM enrollments
		WHERE revoked_at IS NULL AND expires_at > now() AND uses_left > 0 ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Enrollment])
}

func (s *Store) RevokeEnrollment(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE enrollments SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// RedeemEnrollment uses up one use of a code and issues a collector token
// for the host, returning the settings chosen for it. The caller is not
// signed in, so the code is found in system scope and the token is issued in
// the code's workspace.
func (s *Store) RedeemEnrollment(ctx context.Context, code, hostname string) (*Enrollment, string, error) {
	ctx = tenant.System(ctx)
	var e *Enrollment
	var secret string
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE enrollments SET uses_left = uses_left - 1, last_used_at = now()
			WHERE code_hash = $1 AND revoked_at IS NULL AND expires_at > now() AND uses_left > 0
			RETURNING `+enrollmentCols, auth.HashToken(code))
		if err != nil {
			return err
		}
		e, err = pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Enrollment])
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrEnrollmentInvalid
		}
		if err != nil {
			return err
		}
		// At the limit the code is not used up: the host could not be
		// monitored, and the code works once the organisation has room.
		if err := s.workspaceAtLimit(ctx, tx, e.WorkspaceID); err != nil {
			return err
		}
		token, prefix, err := auth.NewToken("stk")
		if err != nil {
			return err
		}
		name := fmt.Sprintf("agent on %s (enrollment %s)", hostname, e.Prefix)
		_, err = tx.Exec(ctx, `INSERT INTO api_tokens (name, prefix, token_hash, role, created_by, workspace_id, project_id) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			name, prefix, auth.HashToken(token), auth.RoleCollector, e.CreatedBy, e.WorkspaceID, e.ProjectID)
		secret = token
		return err
	})
	if err != nil {
		return nil, "", err
	}
	return e, secret, nil
}
