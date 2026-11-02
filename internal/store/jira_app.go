package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Connect Jira: Atlassian OAuth 2.0 (3LO) connections of an organisation;
// see internal/notify/jiraapp.go and internal/api/jira_app.go.

// JiraOAuthTTL is how long a Connect Jira may take.
const JiraOAuthTTL = 10 * time.Minute

// jiraRefreshMargin: an access token that expires sooner than this is
// refreshed before use.
const jiraRefreshMargin = 2 * time.Minute

// ErrJiraStateInvalid hides whether an OAuth state is unknown, used,
// expired, another person's or another organisation's.
var ErrJiraStateInvalid = errors.New("this Connect Jira link is not valid any more; start Connect Jira again")

// ErrJiraGrantRevoked is returned by a refresh function when Atlassian
// refused the refresh token for good (invalid_grant): it was revoked, it
// expired, or the person's password changed. The connection then needs
// reconnecting.
var ErrJiraGrantRevoked = errors.New("Atlassian refused the refresh token")

// JiraReconnectError: the connection cannot be used until an administrator
// connects Jira again.
type JiraReconnectError struct{ Reason string }

func (e *JiraReconnectError) Error() string {
	if e.Reason == "" {
		return "the Jira connection needs reconnecting"
	}
	return "the Jira connection needs reconnecting: " + e.Reason
}

// JiraSite is a Jira Cloud site a connection may reach (Atlassian's
// accessible-resources).
type JiraSite struct {
	ID   string `json:"id"` // the cloud id
	Name string `json:"name"`
	URL  string `json:"url"`
}

// JiraConnection is an Atlassian authorisation made from an organisation.
// It never holds the tokens.
type JiraConnection struct {
	ID           int64      `json:"id"`
	Sites        []JiraSite `json:"sites"`
	Scopes       string     `json:"scopes"`
	Status       string     `json:"status"` // active or reconnect_needed
	StatusReason string     `json:"status_reason"`
	ConnectedBy  *int64     `json:"connected_by"`
	ConnectedAt  time.Time  `json:"connected_at"`
	RefreshedAt  *time.Time `json:"refreshed_at"`
}

// Site returns the connection's site with that cloud id.
func (c *JiraConnection) Site(cloudID string) (JiraSite, bool) {
	for _, s := range c.Sites {
		if s.ID == cloudID {
			return s, true
		}
	}
	return JiraSite{}, false
}

// JiraTokens are what Atlassian's token endpoint returns.
type JiraTokens struct {
	Access    string
	Refresh   string // empty on a refresh that did not rotate it
	ExpiresAt time.Time
}

const (
	JiraStatusActive    = "active"
	JiraStatusReconnect = "reconnect_needed"
)

func jiraTokenName(id int64, which string) string {
	return "jira-oauth-" + which + ":" + strconv.FormatInt(id, 10)
}

// CreateJiraOAuthState starts Connect Jira for a person of the context's
// workspace, reconnecting connection (0: a new connection), and returns
// the state to send to Atlassian.
func (s *Store) CreateJiraOAuthState(ctx context.Context, userID int64, returnTo string, connection int64) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	state := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(state))
	if _, err := s.Pool.Exec(ctx, `DELETE FROM jira_oauth_states WHERE expires_at < now() - interval '1 day'`); err != nil {
		return "", err
	}
	var conn *int64
	if connection > 0 {
		conn = &connection
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO jira_oauth_states (state_hash, user_id, connection_id, return_to, expires_at)
		VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))`, sum[:], userID, conn, returnTo, JiraOAuthTTL.Seconds())
	return state, err
}

// ClaimJiraOAuthState uses a state once: it must be unexpired and started by
// the same person in the context's workspace (row-level security keeps
// other workspaces' states out). It returns where to send the person back
// and the connection being reconnected (0 for a new one).
func (s *Store) ClaimJiraOAuthState(ctx context.Context, state string, userID int64) (string, int64, error) {
	if state == "" || len(state) > 100 {
		return "", 0, ErrJiraStateInvalid
	}
	sum := sha256.Sum256([]byte(state))
	var returnTo string
	var conn *int64
	err := s.Pool.QueryRow(ctx, `UPDATE jira_oauth_states SET used_at = now()
		WHERE state_hash = $1 AND user_id = $2 AND used_at IS NULL AND expires_at > now() RETURNING return_to, connection_id`,
		sum[:], userID).Scan(&returnTo, &conn)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, ErrJiraStateInvalid
	}
	if err != nil {
		return "", 0, err
	}
	if conn == nil {
		return returnTo, 0, nil
	}
	return returnTo, *conn, nil
}

const jiraConnCols = `id, sites, scopes, status, status_reason, connected_by, connected_at, refreshed_at`

func scanJiraConnection(row pgx.Row) (*JiraConnection, error) {
	var c JiraConnection
	var sites []byte
	if err := row.Scan(&c.ID, &sites, &c.Scopes, &c.Status, &c.StatusReason, &c.ConnectedBy, &c.ConnectedAt, &c.RefreshedAt); err != nil {
		return nil, notFound(err)
	}
	if err := json.Unmarshal(sites, &c.Sites); err != nil {
		return nil, err
	}
	if c.Sites == nil {
		c.Sites = []JiraSite{}
	}
	return &c, nil
}

// JiraConnections lists the context's workspace's connections.
func (s *Store) JiraConnections(ctx context.Context) ([]JiraConnection, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+jiraConnCols+` FROM jira_connections ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []JiraConnection{}
	for rows.Next() {
		c, err := scanJiraConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// GetJiraConnection reads one connection of the context's workspace.
func (s *Store) GetJiraConnection(ctx context.Context, id int64) (*JiraConnection, error) {
	return scanJiraConnection(s.Pool.QueryRow(ctx, `SELECT `+jiraConnCols+` FROM jira_connections WHERE id = $1`, id))
}

// SaveJiraConnection records a new connection (id 0) or reconnects one:
// its sites, scopes and tokens are replaced and it is active again. The
// tokens are sealed with box, bound to the workspace and the connection.
func (s *Store) SaveJiraConnection(ctx context.Context, box Sealer, id int64, sites []JiraSite, scopes string, tok JiraTokens, by int64) (int64, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return 0, errNoWorkspace
	}
	if tok.Access == "" || tok.Refresh == "" {
		return 0, errors.New("jira connection without tokens")
	}
	rawSites, err := json.Marshal(sites)
	if err != nil {
		return 0, err
	}
	var who *int64
	if by > 0 {
		who = &by
	}
	err = pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if id == 0 {
			if err := tx.QueryRow(ctx, `INSERT INTO jira_connections (sites, scopes, connected_by) VALUES ($1, $2, $3) RETURNING id`,
				rawSites, scopes, who).Scan(&id); err != nil {
				return err
			}
		} else if err := tx.QueryRow(ctx, `SELECT id FROM jira_connections WHERE id = $1 FOR UPDATE`, id).Scan(&id); err != nil {
			return notFound(err)
		}
		access, err := box.Seal(ws, jiraTokenName(id, "access"), tok.Access)
		if err != nil {
			return err
		}
		refresh, err := box.Seal(ws, jiraTokenName(id, "refresh"), tok.Refresh)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE jira_connections SET sites = $2, scopes = $3, access_token = $4, refresh_token = $5, expires_at = $6,
			token_version = token_version + 1, status = 'active', status_reason = '', connected_by = $7, connected_at = now(), refreshed_at = NULL
			WHERE id = $1`, id, rawSites, scopes, access, refresh, tok.ExpiresAt, who)
		if err != nil {
			return err
		}
		// Reconnected: the channels' "needs reconnecting" no longer holds.
		_, err = tx.Exec(ctx, `UPDATE channels SET last_error = '' WHERE kind = 'jira' AND config->>'auth' = 'oauth'
			AND config->>'connection_id' = $1::text AND last_error LIKE 'the Jira connection needs reconnecting%'`, strconv.FormatInt(id, 10))
		return err
	})
	return id, err
}

// JiraRefresher trades a refresh token for new tokens at Atlassian. It
// returns an error wrapping ErrJiraGrantRevoked when Atlassian refused the
// refresh token for good.
type JiraRefresher func(ctx context.Context, refreshToken string) (JiraTokens, error)

// JiraAccessToken returns a usable access token of a connection of the
// context's workspace and its token_version, refreshing it first when it
// is about to expire. force asks for a new one because Jira refused the
// token of version seen; when another worker has refreshed since, its
// token is used instead of refreshing again.
//
// Atlassian rotates the refresh token on every use and disables the old
// one, so a refresh holds the connection's row lock from reading the
// refresh token until the new pair is stored in one update: a second
// worker waits, then finds the fresh token and does not refresh at all.
// When Atlassian refuses the refresh token, the connection is marked
// reconnect_needed, and so are the last errors of the channels using it,
// in the same transaction; the error is a *JiraReconnectError.
func (s *Store) JiraAccessToken(ctx context.Context, box Sealer, id int64, force bool, seen int64, refresh JiraRefresher) (string, int64, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return "", 0, errNoWorkspace
	}
	type row struct {
		access, refresh []byte
		expires         time.Time
		version         int64
		status, reason  string
	}
	usable := func(r row) bool {
		if len(r.access) == 0 || time.Until(r.expires) < jiraRefreshMargin {
			return false
		}
		return !force || r.version != seen
	}
	var r row
	err := s.Pool.QueryRow(ctx, `SELECT access_token, expires_at, token_version, status, status_reason FROM jira_connections WHERE id = $1`, id).
		Scan(&r.access, &r.expires, &r.version, &r.status, &r.reason)
	if err != nil {
		return "", 0, notFound(err)
	}
	if r.status != JiraStatusActive {
		return "", 0, &JiraReconnectError{Reason: r.reason}
	}
	if usable(r) {
		tok, err := box.Open(ws, jiraTokenName(id, "access"), r.access)
		return tok, r.version, err
	}
	var token string
	var reconnect *JiraReconnectError
	err = pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT access_token, refresh_token, expires_at, token_version, status, status_reason
			FROM jira_connections WHERE id = $1 FOR UPDATE`, id).Scan(&r.access, &r.refresh, &r.expires, &r.version, &r.status, &r.reason); err != nil {
			return notFound(err)
		}
		if r.status != JiraStatusActive {
			reconnect = &JiraReconnectError{Reason: r.reason}
			return nil
		}
		// Refreshed by another worker while this one waited for the lock.
		if usable(r) {
			var err error
			token, err = box.Open(ws, jiraTokenName(id, "access"), r.access)
			return err
		}
		old, err := box.Open(ws, jiraTokenName(id, "refresh"), r.refresh)
		if err != nil {
			return err
		}
		tok, err := refresh(ctx, old)
		if errors.Is(err, ErrJiraGrantRevoked) {
			reason := truncateText(err.Error()+". An administrator can reconnect Jira in Settings → Integrations.", 500)
			reconnect = &JiraReconnectError{Reason: reason}
			if _, err := tx.Exec(ctx, `UPDATE jira_connections SET status = 'reconnect_needed', status_reason = $2 WHERE id = $1`, id, reason); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE channels SET last_error = $2 WHERE kind = 'jira' AND config->>'auth' = 'oauth'
				AND config->>'connection_id' = $1::text`, strconv.FormatInt(id, 10), truncateText(reconnect.Error(), 1000))
			return err
		}
		if err != nil {
			return err // a network error or an outage: the old refresh token stays
		}
		if tok.Access == "" {
			return errors.New("Atlassian returned no access token")
		}
		access, err := box.Seal(ws, jiraTokenName(id, "access"), tok.Access)
		if err != nil {
			return err
		}
		newRefresh := r.refresh
		if tok.Refresh != "" {
			if newRefresh, err = box.Seal(ws, jiraTokenName(id, "refresh"), tok.Refresh); err != nil {
				return err
			}
		}
		if err := tx.QueryRow(ctx, `UPDATE jira_connections SET access_token = $2, refresh_token = $3, expires_at = $4,
			token_version = token_version + 1, refreshed_at = now() WHERE id = $1 RETURNING token_version`,
			id, access, newRefresh, tok.ExpiresAt).Scan(&r.version); err != nil {
			return err
		}
		token = tok.Access
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	if reconnect != nil {
		return "", 0, reconnect
	}
	return token, r.version, nil
}

// DeleteJiraConnection forgets a connection of the context's workspace:
// its tokens are deleted with it, and the Jira channels using it are
// switched off with note as their last error. It returns how many.
func (s *Store) DeleteJiraConnection(ctx context.Context, id int64, note string) (int, error) {
	var n int
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE channels SET enabled = false, last_error = $2 WHERE kind = 'jira' AND config->>'auth' = 'oauth'
			AND config->>'connection_id' = $1::text`, strconv.FormatInt(id, 10), truncateText(note, 1000))
		if err != nil {
			return err
		}
		n = int(tag.RowsAffected())
		tag, err = tx.Exec(ctx, `DELETE FROM jira_connections WHERE id = $1`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
	return n, err
}

// JiraConnectionChannels counts the Jira channels of the context's
// workspace that use a connection.
func (s *Store) JiraConnectionChannels(ctx context.Context, id int64) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM channels WHERE kind = 'jira' AND config->>'auth' = 'oauth'
		AND config->>'connection_id' = $1::text`, strconv.FormatInt(id, 10)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("jira connection channels: %w", err)
	}
	return n, nil
}
