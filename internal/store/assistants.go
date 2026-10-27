package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Connected AI assistants: the OAuth 2.1 authorization server behind the
// remote MCP endpoint (docs/ai-assistants.md). Clients are global; codes,
// connections (grants) and access tokens belong to one workspace. Codes and
// tokens are random, shown once and stored as SHA-256 only. Lookups by token
// span workspaces, so they run in system scope.

const (
	// OAuthCodeTTL is how long an authorization code can be exchanged.
	OAuthCodeTTL = 2 * time.Minute
	// OAuthAccessTTL is the life of an access token; clients refresh.
	OAuthAccessTTL = time.Hour
	// OAuthRefreshTTL is how long a connection keeps working unused: every
	// refresh starts it again.
	OAuthRefreshTTL = 30 * 24 * time.Hour
)

// ErrOAuthInvalidGrant is a code or refresh token that does not work
// (unknown, used, expired, revoked, or for another client). The token
// endpoint answers invalid_grant without saying which.
var ErrOAuthInvalidGrant = errors.New("the code or refresh token is invalid, expired or revoked")

type OAuthClient struct {
	ID           string   `json:"client_id"`
	Name         string   `json:"client_name"`
	ClientURI    string   `json:"client_uri"`
	RedirectURIs []string `json:"redirect_uris"`
	AuthMethod   string   `json:"token_endpoint_auth_method"`
	MetadataURL  bool     `json:"-"`
	SecretHash   []byte   `json:"-"`
	FetchedAt    *time.Time
}

const oauthClientCols = `id, name, client_uri, redirect_uris, auth_method, metadata_url, secret_hash, fetched_at`

// RegisterOAuthClient stores a client registered by dynamic client
// registration and returns its secret (empty for a public client). Clients
// that were never used are removed after 30 days, so anonymous registrations
// cannot pile up.
func (s *Store) RegisterOAuthClient(ctx context.Context, c OAuthClient) (*OAuthClient, string, error) {
	sys := tenant.System(ctx)
	id, _, err := auth.NewToken("stkc")
	if err != nil {
		return nil, "", err
	}
	c.ID = id[:5+26] // stkc_ and 130 random bits: an identifier, not a secret
	var secret string
	var hash []byte
	if c.AuthMethod != "none" {
		if secret, _, err = auth.NewToken("stks"); err != nil {
			return nil, "", err
		}
		hash = auth.HashToken(secret)
	}
	_, _ = s.Pool.Exec(sys, `DELETE FROM oauth_clients WHERE NOT metadata_url AND last_used_at IS NULL
		AND created_at < now() - interval '30 days' AND NOT EXISTS (SELECT 1 FROM oauth_grants g WHERE g.client_id = oauth_clients.id)`)
	_, err = s.Pool.Exec(sys, `INSERT INTO oauth_clients (id, name, client_uri, redirect_uris, auth_method, secret_hash)
		VALUES ($1, $2, $3, $4, $5, $6)`, c.ID, c.Name, c.ClientURI, c.RedirectURIs, c.AuthMethod, hash)
	if err != nil {
		return nil, "", err
	}
	c.SecretHash = hash
	return &c, secret, nil
}

// SaveMetadataClient stores (or refreshes) a client read from its client ID
// metadata document; the id is the document's HTTPS URL.
func (s *Store) SaveMetadataClient(ctx context.Context, c OAuthClient) error {
	_, err := s.Pool.Exec(tenant.System(ctx), `INSERT INTO oauth_clients (id, name, client_uri, redirect_uris, auth_method, metadata_url, fetched_at)
		VALUES ($1, $2, $3, $4, 'none', true, now())
		ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, client_uri = EXCLUDED.client_uri,
		redirect_uris = EXCLUDED.redirect_uris, fetched_at = now() WHERE oauth_clients.metadata_url`,
		c.ID, c.Name, c.ClientURI, c.RedirectURIs)
	return err
}

func (s *Store) GetOAuthClient(ctx context.Context, id string) (*OAuthClient, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT `+oauthClientCols+` FROM oauth_clients WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[OAuthClient])
	return c, notFound(err)
}

// OAuthCode is what the person allowed on the consent screen, waiting to be
// exchanged by the client.
type OAuthCode struct {
	ClientID      string
	UserID        int64
	ProjectID     *int64
	Role          auth.Role
	RedirectURI   string
	CodeChallenge string
	Resource      string
	ClientName    string
	RedirectHost  string
}

// CreateOAuthCode issues an authorization code in the caller's workspace.
func (s *Store) CreateOAuthCode(ctx context.Context, c OAuthCode) (string, error) {
	if _, ok := tenant.Workspace(ctx); !ok {
		return "", fmt.Errorf("an authorization code needs a workspace: %w", ErrInvalid)
	}
	code, _, err := auth.NewToken("stkx")
	if err != nil {
		return "", err
	}
	ctx = tenant.WithoutProject(ctx)
	_, _ = s.Pool.Exec(ctx, `DELETE FROM oauth_codes WHERE expires_at < now() - interval '1 day'`)
	_, err = s.Pool.Exec(ctx, `INSERT INTO oauth_codes (code_hash, client_id, user_id, project_id, role, redirect_uri, code_challenge, resource, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9))`,
		auth.HashToken(code), c.ClientID, c.UserID, c.ProjectID, c.Role, c.RedirectURI, c.CodeChallenge, c.Resource, OAuthCodeTTL.Seconds())
	if isForeignKey(err) {
		return "", fmt.Errorf("the project or client does not exist: %w", ErrInvalid)
	}
	return code, err
}

// OAuthTokens is the answer of the token endpoint.
type OAuthTokens struct {
	Access  string
	Refresh string
	Grant   *AssistantGrant
}

// RedeemOAuthCode exchanges a code for a new connection and its first
// tokens. check sees the stored code (client, redirect URI, PKCE challenge)
// and refuses with an error; the code is used up either way. A code used a
// second time revokes the connection made with it.
func (s *Store) RedeemOAuthCode(ctx context.Context, code string, check func(OAuthCode) error) (*OAuthTokens, error) {
	sys := tenant.System(ctx)
	var out *OAuthTokens
	var checkErr error
	err := pgx.BeginFunc(sys, s.Pool, func(tx pgx.Tx) error {
		var id, ws int64
		var c OAuthCode
		var used bool
		var expired bool
		var grantID *int64
		err := tx.QueryRow(sys, `SELECT oc.id, oc.workspace_id, oc.client_id, oc.user_id, oc.project_id, oc.role, oc.redirect_uri,
			oc.code_challenge, oc.resource, oc.used_at IS NOT NULL, oc.expires_at < now(), oc.grant_id, cl.name
			FROM oauth_codes oc JOIN oauth_clients cl ON cl.id = oc.client_id WHERE oc.code_hash = $1 FOR UPDATE OF oc`,
			auth.HashToken(code)).Scan(&id, &ws, &c.ClientID, &c.UserID, &c.ProjectID, &c.Role, &c.RedirectURI,
			&c.CodeChallenge, &c.Resource, &used, &expired, &grantID, &c.ClientName)
		if err != nil {
			return notFound(err)
		}
		if used {
			checkErr = ErrOAuthInvalidGrant // after the revocation below commits
			if grantID != nil {
				_, err := tx.Exec(sys, `UPDATE oauth_grants SET revoked_at = now(), revoked_reason = 'authorization code used twice',
					refresh_hash = NULL WHERE id = $1 AND revoked_at IS NULL`, *grantID)
				if err != nil {
					return err
				}
				if _, err := tx.Exec(sys, `DELETE FROM oauth_access_tokens WHERE grant_id = $1`, *grantID); err != nil {
					return err
				}
			}
			return nil
		}
		if _, err := tx.Exec(sys, `UPDATE oauth_codes SET used_at = now() WHERE id = $1`, id); err != nil {
			return err
		}
		if expired {
			return ErrOAuthInvalidGrant
		}
		if checkErr = check(c); checkErr != nil {
			return nil // keep the code used up
		}
		if ok, err := activeMember(sys, tx, ws, c.UserID); err != nil {
			return err
		} else if !ok {
			checkErr = ErrOAuthInvalidGrant
			return nil
		}
		var g AssistantGrant
		err = tx.QueryRow(sys, `INSERT INTO oauth_grants (workspace_id, client_id, user_id, project_id, role, client_name, redirect_host)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`, ws, c.ClientID, c.UserID, c.ProjectID, c.Role, c.ClientName,
			redirectHost(c.RedirectURI)).Scan(&g.ID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(sys, `UPDATE oauth_codes SET grant_id = $2 WHERE id = $1`, id, g.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(sys, `UPDATE oauth_clients SET last_used_at = now() WHERE id = $1`, c.ClientID); err != nil {
			return err
		}
		out, err = issueOAuthTokens(sys, tx, g.ID, ws, nil)
		if err != nil {
			return err
		}
		out.Grant, err = grantByID(sys, tx, g.ID)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return nil, ErrOAuthInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	if checkErr != nil {
		return nil, checkErr
	}
	return out, nil
}

// issueOAuthTokens makes a new access token and rotates the refresh token
// of grant id, keeping the one before as previous (a replay of it revokes
// the connection).
func issueOAuthTokens(ctx context.Context, tx pgx.Tx, grantID, ws int64, previous []byte) (*OAuthTokens, error) {
	access, _, err := auth.NewToken("stka")
	if err != nil {
		return nil, err
	}
	refresh, _, err := auth.NewToken("stkr")
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM oauth_access_tokens WHERE grant_id = $1 AND expires_at < now()`, grantID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO oauth_access_tokens (token_hash, workspace_id, grant_id, expires_at)
		VALUES ($1, $2, $3, now() + make_interval(secs => $4))`, auth.HashToken(access), ws, grantID, OAuthAccessTTL.Seconds()); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE oauth_grants SET refresh_hash = $2, previous_refresh_hash = $3,
		refresh_expires_at = now() + make_interval(secs => $4), last_used_at = now() WHERE id = $1`,
		grantID, auth.HashToken(refresh), previous, OAuthRefreshTTL.Seconds()); err != nil {
		return nil, err
	}
	return &OAuthTokens{Access: access, Refresh: refresh}, nil
}

// RefreshOAuthGrant rotates a connection's refresh token and issues a new
// access token. A refresh token that was already rotated away revokes the
// connection: either the client or someone who stole the token used it
// twice, and they cannot be told apart.
func (s *Store) RefreshOAuthGrant(ctx context.Context, refresh, clientID string) (*OAuthTokens, error) {
	sys := tenant.System(ctx)
	h := auth.HashToken(refresh)
	var out *OAuthTokens
	replayed := false
	err := pgx.BeginFunc(sys, s.Pool, func(tx pgx.Tx) error {
		var id, ws, userID int64
		var client string
		var live bool
		err := tx.QueryRow(sys, `SELECT id, workspace_id, user_id, client_id,
			revoked_at IS NULL AND refresh_expires_at > now() FROM oauth_grants WHERE refresh_hash = $1 FOR UPDATE`, h).
			Scan(&id, &ws, &userID, &client, &live)
		if errors.Is(err, pgx.ErrNoRows) {
			tag, err := tx.Exec(sys, `UPDATE oauth_grants SET revoked_at = now(), revoked_reason = 'refresh token used twice',
				refresh_hash = NULL WHERE previous_refresh_hash = $1 AND revoked_at IS NULL`, h)
			if err != nil {
				return err
			}
			if tag.RowsAffected() > 0 {
				replayed = true
				_, err = tx.Exec(sys, `DELETE FROM oauth_access_tokens t USING oauth_grants g
					WHERE g.id = t.grant_id AND g.previous_refresh_hash = $1`, h)
				return err
			}
			return ErrOAuthInvalidGrant
		}
		if err != nil {
			return err
		}
		if !live || client != clientID {
			return ErrOAuthInvalidGrant
		}
		if ok, err := activeMember(sys, tx, ws, userID); err != nil {
			return err
		} else if !ok {
			return ErrOAuthInvalidGrant
		}
		if out, err = issueOAuthTokens(sys, tx, id, ws, h); err != nil {
			return err
		}
		out.Grant, err = grantByID(sys, tx, id)
		return err
	})
	if err == nil && replayed {
		// Committed: the connection is revoked.
		return nil, ErrOAuthInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func activeMember(ctx context.Context, tx pgx.Tx, ws, userID int64) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM workspace_members m JOIN workspaces w ON w.id = m.workspace_id
		JOIN users u ON u.id = m.user_id WHERE m.workspace_id = $1 AND m.user_id = $2 AND w.disabled_at IS NULL AND NOT u.disabled)`,
		ws, userID).Scan(&ok)
	return ok, err
}

// RevokeOAuthToken implements token revocation (RFC 7009) for clientID: a
// refresh token ends its connection, an access token stops working. Unknown
// tokens, and tokens of other clients, are ignored. It returns the
// connection ended, if any.
func (s *Store) RevokeOAuthToken(ctx context.Context, token, clientID string) (*AssistantGrant, error) {
	sys := tenant.System(ctx)
	h := auth.HashToken(token)
	var id int64
	err := s.Pool.QueryRow(sys, `UPDATE oauth_grants SET revoked_at = now(), revoked_reason = 'revoked by the assistant', refresh_hash = NULL
		WHERE refresh_hash = $1 AND client_id = $2 AND revoked_at IS NULL RETURNING id`, h, clientID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		_, err = s.Pool.Exec(sys, `DELETE FROM oauth_access_tokens t USING oauth_grants g
			WHERE t.token_hash = $1 AND g.id = t.grant_id AND g.client_id = $2`, h, clientID)
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if _, err := s.Pool.Exec(sys, `DELETE FROM oauth_access_tokens WHERE grant_id = $1`, id); err != nil {
		return nil, err
	}
	return grantByID(sys, s.Pool, id)
}

// AssistantGrant is a connected assistant.
type AssistantGrant struct {
	ID            int64      `json:"id"`
	WorkspaceID   int64      `json:"workspace_id"`
	WorkspaceName string     `json:"workspace_name"`
	ClientID      string     `json:"client_id"`
	ClientName    string     `json:"client_name"`
	RedirectHost  string     `json:"redirect_host"`
	UserID        int64      `json:"user_id"`
	ProjectID     *int64     `json:"project_id"`
	ProjectName   string     `json:"project_name"`
	Role          auth.Role  `json:"role"`
	CreatedAt     time.Time  `json:"created_at"`
	LastUsedAt    *time.Time `json:"last_used_at"`
}

const assistantCols = `g.id, g.workspace_id, w.name, g.client_id, g.client_name, g.redirect_host, g.user_id, g.project_id,
	COALESCE((SELECT p.name FROM projects p WHERE p.id = g.project_id), ''), g.role, g.created_at, g.last_used_at`

func grantByID(ctx context.Context, db q, id int64) (*AssistantGrant, error) {
	rows, err := db.Query(ctx, `SELECT `+assistantCols+` FROM oauth_grants g JOIN workspaces w ON w.id = g.workspace_id WHERE g.id = $1`, id)
	if err != nil {
		return nil, err
	}
	g, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[AssistantGrant])
	return g, notFound(err)
}

// AssistantPrincipal resolves an access token to its connection and user.
// Like TokenPrincipal it runs in system scope and refuses a disabled user,
// a disabled workspace, or a user who has left it; the request is then
// capped at the lower of the connection's role and the user's own.
func (s *Store) AssistantPrincipal(ctx context.Context, secret string) (*AssistantGrant, *User, error) {
	sys := tenant.System(ctx)
	rows, err := s.Pool.Query(sys, `SELECT `+assistantCols+` FROM oauth_access_tokens t
		JOIN oauth_grants g ON g.id = t.grant_id JOIN workspaces w ON w.id = g.workspace_id
		WHERE t.token_hash = $1 AND t.expires_at > now() AND g.revoked_at IS NULL AND w.disabled_at IS NULL`, auth.HashToken(secret))
	if err != nil {
		return nil, nil, err
	}
	g, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[AssistantGrant])
	if err != nil {
		return nil, nil, notFound(err)
	}
	_, _ = s.Pool.Exec(sys, `UPDATE oauth_grants SET last_used_at = now() WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`, g.ID)
	u, err := s.GetUser(tenant.WithWorkspace(ctx, g.WorkspaceID), g.UserID)
	if errors.Is(err, ErrNotFound) || (err == nil && u.Disabled) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	access, err := s.UserAccess(ctx, g.WorkspaceID, u.ID)
	if err != nil {
		return nil, nil, err
	}
	if !access.Member || auth.Higher(access.OrgRole, access.ProjectRole) == "" {
		return nil, nil, ErrNotFound
	}
	return g, u, nil
}

// ListAssistantGrants lists userID's connected assistants in every
// workspace, newest first.
func (s *Store) ListAssistantGrants(ctx context.Context, userID int64) ([]AssistantGrant, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT `+assistantCols+` FROM oauth_grants g JOIN workspaces w ON w.id = g.workspace_id
		WHERE g.user_id = $1 AND g.revoked_at IS NULL AND (g.refresh_expires_at IS NULL OR g.refresh_expires_at > now())
		ORDER BY g.created_at DESC LIMIT 200`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[AssistantGrant])
}

// RevokeAssistantGrant disconnects one of userID's assistants: its refresh
// token and access tokens stop working at once.
func (s *Store) RevokeAssistantGrant(ctx context.Context, id, userID int64) (*AssistantGrant, error) {
	sys := tenant.System(ctx)
	var g *AssistantGrant
	err := pgx.BeginFunc(sys, s.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(sys, `UPDATE oauth_grants SET revoked_at = now(), revoked_reason = 'disconnected', refresh_hash = NULL
			WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, id, userID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, err := tx.Exec(sys, `DELETE FROM oauth_access_tokens WHERE grant_id = $1`, id); err != nil {
			return err
		}
		g, err = grantByID(sys, tx, id)
		return err
	})
	return g, err
}

// redirectHost is the host the codes of a connection went to, shown with
// the connection ("claude.ai", "localhost"); for an app's own scheme, the
// scheme.
func redirectHost(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	h := u.Hostname()
	if h == "" {
		h = u.Scheme + ":"
	}
	if len(h) > 300 {
		h = h[:300]
	}
	return h
}
