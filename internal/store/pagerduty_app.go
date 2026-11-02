package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// "Connect PagerDuty" (internal/api/pagerduty_app.go). A connect has two
// steps that both happen within PagerDutyConnectTTL: the OAuth round trip
// (a single-use state) and choosing the service (a session handle given
// after the code exchange). Both are bound to the person who started it in
// the context's workspace; only their SHA-256 is stored. PagerDuty's access
// token is sealed while the person chooses and deleted with the row.

// PagerDutyConnectTTL is how long each step may take.
const PagerDutyConnectTTL = 10 * time.Minute

// ErrPagerDutyStateInvalid hides whether a state or session is unknown,
// used, expired, another person's or another organisation's.
var ErrPagerDutyStateInvalid = errors.New("this PagerDuty connection is not valid any more; start Connect PagerDuty again")

func pagerDutyVerifierName(stateHash []byte) string {
	return "pagerduty-connect-verifier:" + base64.RawURLEncoding.EncodeToString(stateHash[:8])
}

func pagerDutyTokenName(sessionHash []byte) string {
	return "pagerduty-connect-token:" + base64.RawURLEncoding.EncodeToString(sessionHash[:8])
}

func newHandle() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	h := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(h))
	return h, sum[:], nil
}

// PurgePagerDutyConnects deletes connects past their time, with any token
// they hold. Called on every new connect and hourly.
func (s *Store) PurgePagerDutyConnects(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM pagerduty_connects WHERE expires_at < now()`)
	return err
}

// CreatePagerDutyConnect starts a connect for a person of the context's
// workspace: it returns the state to send to PagerDuty, with the PKCE
// verifier sealed in the row.
func (s *Store) CreatePagerDutyConnect(ctx context.Context, box Sealer, userID int64, verifier, returnTo string) (string, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return "", errNoWorkspace
	}
	if err := s.PurgePagerDutyConnects(ctx); err != nil {
		return "", err
	}
	state, sum, err := newHandle()
	if err != nil {
		return "", err
	}
	sealed, err := box.Seal(ws, pagerDutyVerifierName(sum), verifier)
	if err != nil {
		return "", err
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO pagerduty_connects (state_hash, user_id, verifier, return_to, expires_at)
		VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))`, sum, userID, sealed, returnTo, PagerDutyConnectTTL.Seconds())
	return state, err
}

// ClaimPagerDutyState uses a state once: unexpired, started by the same
// person in the context's workspace (row-level security keeps other
// workspaces' rows out). It returns the PKCE verifier and where to send the
// person back.
func (s *Store) ClaimPagerDutyState(ctx context.Context, box Sealer, state string, userID int64) (verifier, returnTo string, err error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return "", "", errNoWorkspace
	}
	sum := sha256.Sum256([]byte(state))
	var sealed []byte
	err = s.Pool.QueryRow(ctx, `UPDATE pagerduty_connects SET used_at = now()
		WHERE state_hash = $1 AND user_id = $2 AND used_at IS NULL AND expires_at > now() RETURNING verifier, return_to`,
		sum[:], userID).Scan(&sealed, &returnTo)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrPagerDutyStateInvalid
	}
	if err != nil {
		return "", "", err
	}
	verifier, err = box.Open(ws, pagerDutyVerifierName(sum[:]), sealed)
	return verifier, returnTo, err
}

// StartPagerDutySession keeps the access token, sealed, for the person to
// choose a service, and returns the session handle for that step. The
// state must have been claimed by the same person.
func (s *Store) StartPagerDutySession(ctx context.Context, box Sealer, state string, userID int64, region, token string) (string, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return "", errNoWorkspace
	}
	session, sessionSum, err := newHandle()
	if err != nil {
		return "", err
	}
	sealed, err := box.Seal(ws, pagerDutyTokenName(sessionSum), token)
	if err != nil {
		return "", err
	}
	stateSum := sha256.Sum256([]byte(state))
	tag, err := s.Pool.Exec(ctx, `UPDATE pagerduty_connects SET session_hash = $3, region = $4, access_token = $5,
		expires_at = now() + make_interval(secs => $6)
		WHERE state_hash = $1 AND user_id = $2 AND used_at IS NOT NULL AND session_hash IS NULL`,
		stateSum[:], userID, sessionSum, region, sealed, PagerDutyConnectTTL.Seconds())
	if err == nil && tag.RowsAffected() == 0 {
		return "", ErrPagerDutyStateInvalid
	}
	return session, err
}

// DropPagerDutyState deletes a claimed state whose code exchange failed.
func (s *Store) DropPagerDutyState(ctx context.Context, state string, userID int64) error {
	sum := sha256.Sum256([]byte(state))
	_, err := s.Pool.Exec(ctx, `DELETE FROM pagerduty_connects WHERE state_hash = $1 AND user_id = $2`, sum[:], userID)
	return err
}

// PagerDutySession is a connect waiting for the person to choose.
type PagerDutySession struct {
	ID          int64
	Region      string
	AccessToken string
	ReturnTo    string
}

// PagerDutySession opens a session of the same person in the context's
// workspace.
func (s *Store) PagerDutySession(ctx context.Context, box Sealer, session string, userID int64) (*PagerDutySession, error) {
	return s.pagerDutySession(ctx, box, session, userID, `SELECT id, region, access_token, return_to FROM pagerduty_connects
		WHERE session_hash = $1 AND user_id = $2 AND expires_at > now() AND access_token IS NOT NULL`)
}

// TakePagerDutySession opens a session and deletes it, with its token, in
// one statement: the token leaves the database before it is used to add
// the integration, and of two concurrent finishes only one gets it.
func (s *Store) TakePagerDutySession(ctx context.Context, box Sealer, session string, userID int64) (*PagerDutySession, error) {
	return s.pagerDutySession(ctx, box, session, userID, `DELETE FROM pagerduty_connects
		WHERE session_hash = $1 AND user_id = $2 AND expires_at > now() AND access_token IS NOT NULL
		RETURNING id, region, access_token, return_to`)
}

func (s *Store) pagerDutySession(ctx context.Context, box Sealer, session string, userID int64, query string) (*PagerDutySession, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil, errNoWorkspace
	}
	sum := sha256.Sum256([]byte(session))
	var out PagerDutySession
	var sealed []byte
	err := s.Pool.QueryRow(ctx, query, sum[:], userID).Scan(&out.ID, &out.Region, &sealed, &out.ReturnTo)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPagerDutyStateInvalid
	}
	if err != nil {
		return nil, err
	}
	if out.AccessToken, err = box.Open(ws, pagerDutyTokenName(sum[:]), sealed); err != nil {
		return nil, err
	}
	return &out, nil
}

// EndPagerDutySession deletes a session and the token it holds (Cancel).
func (s *Store) EndPagerDutySession(ctx context.Context, session string, userID int64) error {
	sum := sha256.Sum256([]byte(session))
	_, err := s.Pool.Exec(ctx, `DELETE FROM pagerduty_connects WHERE session_hash = $1 AND user_id = $2`, sum[:], userID)
	return err
}

// PagerDutyAppChannel finds the context's workspace's app channel for a
// PagerDuty service, so connecting the same service again refreshes it.
func (s *Store) PagerDutyAppChannel(ctx context.Context, serviceID string) (*Channel, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+channelCols+` FROM channels WHERE kind = 'pagerduty' AND config->>'pagerduty_app' = 'true'
		AND config->>'pagerduty_service_id' = $1 ORDER BY id LIMIT 1`, serviceID)
	if err != nil {
		return nil, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Channel])
	return c, notFound(err)
}
