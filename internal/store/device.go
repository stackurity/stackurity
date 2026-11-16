package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Signing in a command-line tool from the browser: the OAuth 2.0 Device
// Authorization Grant (RFC 8628; migration 0108, docs/device-login.md).
//
// The tool asks for a code (CreateDeviceAuthorization) and shows the person
// its user code; the person approves it in a signed-in browser
// (ApproveDeviceAuthorization), which makes an upload-only API token in their
// organisation; the tool polls (PollDeviceAuthorization) and gets the token's
// secret once. Every lookup is by the hash of a code, in system scope: the
// request has no organisation before someone approves it.

const (
	// DeviceCodeTTL is how long a code may wait for the person and for the
	// tool to collect its token.
	DeviceCodeTTL = 10 * time.Minute
	// DeviceInterval is how often the tool may poll at first; polling faster
	// answers slow_down and adds DeviceSlowDown (RFC 8628 section 3.5).
	DeviceInterval = 5 * time.Second
	DeviceSlowDown = 5 * time.Second
	// DeviceTokenTTL is how long a token made by device sign-in works.
	DeviceTokenTTL = 365 * 24 * time.Hour
)

// UserCodeAlphabet is what user codes are made of: twenty consonants, so no
// letters that look alike (no vowels, so no words, no 0/O or 1/I), as RFC 8628
// section 6.1 suggests. Eight of them (about 34 bits) are shown as XXXX-XXXX.
const UserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

const userCodeLen = 8

// Statuses of a device authorization.
const (
	DevicePending  = "pending"
	DeviceApproved = "approved"
	DeviceDenied   = "denied"
	DeviceIssued   = "issued"
)

// ErrDeviceInvalidGrant: the device code is unknown, belongs to another
// client, or its token was already collected (RFC 6749 invalid_grant).
var ErrDeviceInvalidGrant = errors.New("this device code is unknown, belongs to another client, or was already used; start signing in again")

// ErrDeviceNotPending: the code was already approved or denied, or it
// expired, so it cannot be decided.
var ErrDeviceNotPending = errors.New("this code was already used or has expired; start signing in again from your terminal")

// DeviceAuthorization is a sign-in request of a command-line tool.
type DeviceAuthorization struct {
	ID          int64     `json:"id"`
	ClientID    string    `json:"client_id"`
	HostLabel   string    `json:"host"`
	RequestIP   string    `json:"request_ip"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Status      string    `json:"status"`
	WorkspaceID *int64    `json:"workspace_id"`
	UserID      *int64    `json:"user_id"`
	ProjectID   *int64    `json:"project_id"`
	TokenID     *int64    `json:"token_id"`
	// Expired is true once ExpiresAt has passed (by the database's clock).
	Expired bool `json:"expired"`
}

const deviceCols = `id, client_id, host_label, request_ip, created_at, expires_at, status, workspace_id, user_id, project_id, token_id, expires_at <= now()`

// NormalizeUserCode turns what a person typed ("bcdf-ghjk", "BCDF GHJK")
// into the code's eight letters, or "" when it cannot be a code.
func NormalizeUserCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == '-' || r == ' ' || r == '\t':
			continue
		case strings.ContainsRune(UserCodeAlphabet, r):
			b.WriteRune(r)
		default:
			return ""
		}
	}
	if b.Len() != userCodeLen {
		return ""
	}
	return b.String()
}

// FormatUserCode shows a normalized code as XXXX-XXXX.
func FormatUserCode(code string) string {
	if len(code) != userCodeLen {
		return code
	}
	return code[:4] + "-" + code[4:]
}

func newUserCode() (string, error) {
	out := make([]byte, 0, userCodeLen)
	buf := make([]byte, 16)
	for len(out) < userCodeLen {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, c := range buf {
			// 240 is the largest multiple of 20 below 256: no bias.
			if c < 240 && len(out) < userCodeLen {
				out = append(out, UserCodeAlphabet[int(c)%len(UserCodeAlphabet)])
			}
		}
	}
	return string(out), nil
}

func userCodeHash(code string) []byte {
	h := sha256.Sum256([]byte("stackurity-device-user-code:" + code))
	return h[:]
}

// CreateDeviceAuthorization starts a sign-in for clientID (a known client),
// with the host label the tool sent and the address it came from. It returns
// the device code (the tool's secret, kept only as a hash) and the user code
// (eight letters, normalized). On the way it tidies up: tokens of approved
// requests whose tool never collected them are revoked once they expire, and
// requests that ended more than a day ago are deleted.
func (s *Store) CreateDeviceAuthorization(ctx context.Context, clientID, host, ip string) (deviceCode, userCode string, d *DeviceAuthorization, err error) {
	sys := tenant.System(ctx)
	if err := s.expireDeviceAuthorizations(sys); err != nil {
		return "", "", nil, err
	}
	for attempt := 0; attempt < 5; attempt++ {
		deviceCode, _, err = auth.NewToken("stkd")
		if err != nil {
			return "", "", nil, err
		}
		userCode, err = newUserCode()
		if err != nil {
			return "", "", nil, err
		}
		rows, err := s.Pool.Query(sys, `INSERT INTO device_authorizations (device_code_hash, user_code_hash, client_id, host_label, request_ip,
			expires_at, interval_seconds) VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6), $7) RETURNING `+deviceCols,
			auth.HashToken(deviceCode), userCodeHash(userCode), clientID, host, ip, DeviceCodeTTL.Seconds(), int(DeviceInterval/time.Second))
		if err != nil {
			return "", "", nil, err
		}
		d, err = pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[DeviceAuthorization])
		if isUniqueViolation(err) {
			continue // the same user code is still in use: draw another
		}
		if err != nil {
			return "", "", nil, err
		}
		return deviceCode, userCode, d, nil
	}
	return "", "", nil, fmt.Errorf("could not draw an unused user code")
}

// expireDeviceAuthorizations revokes the tokens of approved requests that
// expired before their tool collected them (nobody ever knew their secret)
// and deletes requests that ended more than a day ago.
func (s *Store) expireDeviceAuthorizations(sys context.Context) error {
	if _, err := s.Pool.Exec(sys, `UPDATE api_tokens SET revoked_at = now() WHERE revoked_at IS NULL AND id IN
		(SELECT token_id FROM device_authorizations WHERE status = 'approved' AND expires_at <= now() AND token_id IS NOT NULL)`); err != nil {
		return err
	}
	_, err := s.Pool.Exec(sys, `DELETE FROM device_authorizations WHERE expires_at < now() - interval '1 day'`)
	return err
}

// DeviceAuthorizationByUserCode finds a request by its user code
// (normalized), whatever its status; ErrNotFound when none has it.
func (s *Store) DeviceAuthorizationByUserCode(ctx context.Context, userCode string) (*DeviceAuthorization, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT `+deviceCols+` FROM device_authorizations WHERE user_code_hash = $1`, userCodeHash(userCode))
	if err != nil {
		return nil, err
	}
	d, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[DeviceAuthorization])
	return d, notFound(err)
}

// DeviceApproval is the person's answer: who approved, in which
// organisation, the project the token's new assets go to (nil: none), and
// the token's name.
type DeviceApproval struct {
	UserID      int64
	WorkspaceID int64
	ProjectID   *int64
	TokenName   string
}

// lockPendingDevice locks the request with userCode for a decision:
// ErrNotFound when no request has it, ErrDeviceNotPending when it was
// decided already or has expired.
func lockPendingDevice(ctx context.Context, tx pgx.Tx, userCode string) (*DeviceAuthorization, error) {
	rows, err := tx.Query(ctx, `SELECT `+deviceCols+` FROM device_authorizations WHERE user_code_hash = $1 FOR UPDATE`, userCodeHash(userCode))
	if err != nil {
		return nil, err
	}
	d, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[DeviceAuthorization])
	if err != nil {
		return nil, notFound(err)
	}
	if d.Status != DevicePending || d.Expired {
		return nil, ErrDeviceNotPending
	}
	return d, nil
}

// ApproveDeviceAuthorization approves a pending request: it makes the
// token now (so the organisation's plan limit on API tokens is checked here,
// where the person sees the answer, and the token is listed in Settings at
// once) with a secret nobody knows; PollDeviceAuthorization gives it a new
// secret when the tool collects it. The token belongs to the approver, has
// the collector role (it may only upload, and only while the approver may),
// and expires after DeviceTokenTTL.
func (s *Store) ApproveDeviceAuthorization(ctx context.Context, userCode string, a DeviceApproval) (*DeviceAuthorization, *Token, error) {
	sys := tenant.System(ctx)
	var d *DeviceAuthorization
	var tok *Token
	err := pgx.BeginFunc(sys, s.Pool, func(tx pgx.Tx) error {
		var err error
		if d, err = lockPendingDevice(sys, tx, userCode); err != nil {
			return err
		}
		if a.ProjectID != nil {
			var active bool
			if err := tx.QueryRow(sys, `SELECT EXISTS (SELECT 1 FROM projects WHERE id = $1 AND workspace_id = $2 AND archived_at IS NULL)`,
				*a.ProjectID, a.WorkspaceID).Scan(&active); err != nil {
				return err
			}
			if !active {
				return fmt.Errorf("no such project: %w", ErrInvalid)
			}
		}
		// A placeholder secret: never shown, never kept.
		placeholder, _, err := auth.NewToken("stk")
		if err != nil {
			return err
		}
		rows, err := tx.Query(sys, `INSERT INTO api_tokens (workspace_id, name, prefix, token_hash, user_id, role, created_by, expires_at, project_id)
			VALUES ($1, $2, 'stk_pending', $3, $4, $5, $4, now() + make_interval(secs => $6), $7) RETURNING `+tokenCols,
			a.WorkspaceID, a.TokenName, auth.HashToken(placeholder), a.UserID, auth.RoleCollector, DeviceTokenTTL.Seconds(), a.ProjectID)
		if err != nil {
			return err
		}
		if tok, err = pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Token]); err != nil {
			return err
		}
		rows, err = tx.Query(sys, `UPDATE device_authorizations SET status = 'approved', decided_at = now(), workspace_id = $2, user_id = $3,
			project_id = $4, token_id = $5 WHERE id = $1 RETURNING `+deviceCols, d.ID, a.WorkspaceID, a.UserID, a.ProjectID, tok.ID)
		if err != nil {
			return err
		}
		d, err = pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[DeviceAuthorization])
		return err
	})
	if isForeignKey(err) {
		return nil, nil, fmt.Errorf("the account or project is not part of this organisation: %w", ErrInvalid)
	}
	if err != nil {
		return nil, nil, err
	}
	return d, tok, nil
}

// DenyDeviceAuthorization records that the person refused a pending
// request; its tool is told access_denied.
func (s *Store) DenyDeviceAuthorization(ctx context.Context, userCode string, userID, workspaceID int64) (*DeviceAuthorization, error) {
	sys := tenant.System(ctx)
	var d *DeviceAuthorization
	err := pgx.BeginFunc(sys, s.Pool, func(tx pgx.Tx) error {
		var err error
		if d, err = lockPendingDevice(sys, tx, userCode); err != nil {
			return err
		}
		rows, err := tx.Query(sys, `UPDATE device_authorizations SET status = 'denied', decided_at = now(), workspace_id = $2, user_id = $3
			WHERE id = $1 RETURNING `+deviceCols, d.ID, workspaceID, userID)
		if err != nil {
			return err
		}
		d, err = pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[DeviceAuthorization])
		return err
	})
	if isForeignKey(err) {
		return nil, fmt.Errorf("the account is not part of this organisation: %w", ErrInvalid)
	}
	return d, err
}

// DevicePoll is the answer to a tool's poll.
type DevicePoll struct {
	// Outcome is DevicePending (authorization_pending), "slow_down",
	// DeviceDenied (access_denied), "expired" (expired_token) or
	// DeviceIssued (the token, once).
	Outcome string
	// Interval is the polling interval in seconds from now on.
	Interval      int
	Authorization *DeviceAuthorization
	Token         *Token
	Secret        string
}

// DevicePollSlowDown and DevicePollExpired are DevicePoll outcomes.
const (
	DevicePollSlowDown = "slow_down"
	DevicePollExpired  = "expired"
)

// PollDeviceAuthorization answers a tool polling with deviceCode. A poll
// sooner than the interval allows (with a second's grace) answers slow_down
// and lengthens the interval. Once the request is approved, the first poll
// gives the token a new secret and returns it: the request is then used up,
// and further polls get ErrDeviceInvalidGrant. An approved request that
// expires before then has its token revoked.
func (s *Store) PollDeviceAuthorization(ctx context.Context, deviceCode, clientID string) (*DevicePoll, error) {
	sys := tenant.System(ctx)
	var out *DevicePoll
	err := pgx.BeginFunc(sys, s.Pool, func(tx pgx.Tx) error {
		var d DeviceAuthorization
		var interval int
		var tooSoon bool
		err := tx.QueryRow(sys, `SELECT `+deviceCols+`, interval_seconds,
			last_polled_at IS NOT NULL AND last_polled_at > now() - make_interval(secs => interval_seconds - 1)
			FROM device_authorizations WHERE device_code_hash = $1 FOR UPDATE`, auth.HashToken(deviceCode)).Scan(
			&d.ID, &d.ClientID, &d.HostLabel, &d.RequestIP, &d.CreatedAt, &d.ExpiresAt, &d.Status, &d.WorkspaceID, &d.UserID,
			&d.ProjectID, &d.TokenID, &d.Expired, &interval, &tooSoon)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDeviceInvalidGrant
		}
		if err != nil {
			return err
		}
		if d.ClientID != clientID || d.Status == DeviceIssued {
			return ErrDeviceInvalidGrant
		}
		out = &DevicePoll{Authorization: &d, Interval: interval}
		if d.Expired {
			out.Outcome = DevicePollExpired
			if d.Status == DeviceApproved && d.TokenID != nil {
				_, err := tx.Exec(sys, `UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, *d.TokenID)
				return err
			}
			return nil
		}
		if tooSoon {
			out.Outcome = DevicePollSlowDown
			out.Interval = min(interval+int(DeviceSlowDown/time.Second), 60)
			_, err := tx.Exec(sys, `UPDATE device_authorizations SET last_polled_at = now(), interval_seconds = $2 WHERE id = $1`, d.ID, out.Interval)
			return err
		}
		if _, err := tx.Exec(sys, `UPDATE device_authorizations SET last_polled_at = now() WHERE id = $1`, d.ID); err != nil {
			return err
		}
		switch d.Status {
		case DevicePending:
			out.Outcome = DevicePending
			return nil
		case DeviceDenied:
			out.Outcome = DeviceDenied
			return nil
		}
		// Approved: the token gets its real secret now, and only the tool
		// sees it. A token revoked (or expired) since the approval is not
		// handed out.
		if d.TokenID == nil {
			out.Outcome = DeviceDenied
			return nil
		}
		secret, prefix, err := auth.NewToken("stk")
		if err != nil {
			return err
		}
		rows, err := tx.Query(sys, `UPDATE api_tokens SET token_hash = $2, prefix = $3 WHERE id = $1 AND revoked_at IS NULL
			AND (expires_at IS NULL OR expires_at > now()) RETURNING `+tokenCols, *d.TokenID, auth.HashToken(secret), prefix)
		if err != nil {
			return err
		}
		tok, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Token])
		if errors.Is(err, pgx.ErrNoRows) {
			out.Outcome = DeviceDenied
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(sys, `UPDATE device_authorizations SET status = 'issued', issued_at = now() WHERE id = $1`, d.ID); err != nil {
			return err
		}
		d.Status = DeviceIssued
		out.Outcome, out.Token, out.Secret = DeviceIssued, tok, secret
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
