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
	// Fleet: made to add many servers in one rollout (up to
	// MaxFleetUses servers, up to MaxFleetTTL), with the count and expiry
	// chosen explicitly.
	Fleet bool `json:"fleet"`
	// MaxUses is how many servers the code could enroll when it was made;
	// nil for codes made before it was recorded.
	MaxUses *int `json:"max_uses"`
}

const enrollmentCols = `id, prefix, label, environment, app_dirs, discover_apps, uses_left, created_by, created_at,
	expires_at, last_used_at, revoked_at, workspace_id, project_id, fleet, max_uses`

// Limits of the two kinds of code. A standard code is the default (one
// server, 24 hours) and can be raised to MaxCodeUses servers and
// MaxCodeTTL; a fleet code goes further, and its count and expiry must be
// given explicitly.
const (
	MaxCodeUses  = 500
	MaxCodeTTL   = 30 * 24 * time.Hour
	MaxFleetUses = 1000
	MaxFleetTTL  = 90 * 24 * time.Hour
)

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
	maxUses, maxTTL := MaxCodeUses, MaxCodeTTL
	if e.Fleet {
		maxUses, maxTTL = MaxFleetUses, MaxFleetTTL
	}
	if e.UsesLeft < 1 || e.UsesLeft > maxUses || ttl < time.Minute || ttl > maxTTL {
		return nil, "", fmt.Errorf("a code enrolls 1 to %d servers for at most %s: %w", maxUses, maxTTL, ErrInvalid)
	}
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `INSERT INTO enrollments (prefix, code_hash, label, environment, app_dirs, discover_apps, uses_left, created_by, expires_at, project_id, fleet, max_uses)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8, now() + make_interval(secs => $9), $10, $11, $7
		WHERE $10::bigint IS NULL OR EXISTS (SELECT 1 FROM projects WHERE id = $10 AND archived_at IS NULL)
		RETURNING `+enrollmentCols,
		prefix, auth.HashToken(secret), e.Label, e.Environment, e.AppDirs, e.DiscoverApps, e.UsesLeft, by, ttl.Seconds(), e.ProjectID, e.Fleet)
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

// ListFleetEnrollments returns fleet codes in every state (usable, used up,
// expired, revoked) made in the last 180 days, newest first, so their usage
// stays visible after a rollout.
func (s *Store) ListFleetEnrollments(ctx context.Context) ([]Enrollment, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+enrollmentCols+` FROM enrollments
		WHERE fleet AND created_at > now() - interval '180 days' ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Enrollment])
}

// EnrollmentUse is one host that used a code.
type EnrollmentUse struct {
	ID         int64     `json:"id"`
	Hostname   string    `json:"hostname"`
	RemoteAddr string    `json:"remote_addr"`
	UsedAt     time.Time `json:"used_at"`
	// TokenPrefix identifies the collector token the host received (under
	// Integrations > API tokens); empty once that token is deleted.
	TokenPrefix string `json:"token_prefix"`
	// TokenRevoked: that token has been revoked since.
	TokenRevoked bool `json:"token_revoked"`
}

// EnrollmentUses lists the hosts that used code id, newest first (at most
// limit). It returns ErrNotFound when the workspace has no such code.
func (s *Store) EnrollmentUses(ctx context.Context, id int64, limit int) ([]EnrollmentUse, error) {
	var ok bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM enrollments WHERE id = $1)`, id).Scan(&ok); err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFound
	}
	rows, err := s.Pool.Query(ctx, `SELECT u.id, u.hostname, u.remote_addr, u.used_at, COALESCE(t.prefix, ''), COALESCE(t.revoked_at IS NOT NULL, false)
		FROM enrollment_uses u LEFT JOIN api_tokens t ON t.id = u.token_id
		WHERE u.enrollment_id = $1 ORDER BY u.used_at DESC, u.id DESC LIMIT $2`, id, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[EnrollmentUse])
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
	return s.RedeemEnrollmentFor(ctx, code, hostname, 0)
}

// ErrEnrollmentProject: the redeemer asked for a project (stackurity enroll
// --project) and the code adds hosts to another project, or to none. The
// code is not used up. Only someone holding a valid code learns this.
var ErrEnrollmentProject = errors.New("this enrollment code does not add hosts to the project you asked for; ask an administrator for a code made for that project")

// RedeemEnrollmentFor is RedeemEnrollment that, when project is not 0,
// first checks that the code adds hosts to that project. A redeemer can
// never choose or change the code's project: the administrator who made the
// code decides it.
func (s *Store) RedeemEnrollmentFor(ctx context.Context, code, hostname string, project int64) (*Enrollment, string, error) {
	return s.Redeem(ctx, Redemption{Code: code, Hostname: hostname, Project: project})
}

// Redemption is one request to exchange a code for a collector token.
type Redemption struct {
	Code, Hostname string
	// Project, when not 0, must be the code's project (RedeemEnrollmentFor).
	Project int64
	// RemoteAddr is the address the request came from, kept in the code's
	// usage list.
	RemoteAddr string
}

// Redeem is RedeemEnrollmentFor that also records the use (host, address,
// token) in the code's usage list, in the same transaction.
func (s *Store) Redeem(ctx context.Context, rd Redemption) (*Enrollment, string, error) {
	code, hostname, project := rd.Code, rd.Hostname, rd.Project
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
		if project != 0 && (e.ProjectID == nil || *e.ProjectID != project) {
			return ErrEnrollmentProject // rolls the use back
		}
		// At the limit the code is not used up: the host could not be
		// monitored, and the code works once the organisation has room.
		if err := s.workspaceAtLimit(ctx, tx, e.WorkspaceID); err != nil {
			return err
		}
		// Nor while the organisation is read-only.
		if err := readOnly(ctx, tx, e.WorkspaceID); err != nil {
			return err
		}
		token, prefix, err := auth.NewToken("stk")
		if err != nil {
			return err
		}
		name := fmt.Sprintf("agent on %s (enrollment %s)", hostname, e.Prefix)
		var tokenID int64
		if err := tx.QueryRow(ctx, `INSERT INTO api_tokens (name, prefix, token_hash, role, created_by, workspace_id, project_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
			name, prefix, auth.HashToken(token), auth.RoleCollector, e.CreatedBy, e.WorkspaceID, e.ProjectID).Scan(&tokenID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO enrollment_uses (workspace_id, enrollment_id, hostname, remote_addr, token_id) VALUES ($1,$2,$3,$4,$5)`,
			e.WorkspaceID, e.ID, hostname, rd.RemoteAddr, tokenID); err != nil {
			return err
		}
		secret = token
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return e, secret, nil
}
