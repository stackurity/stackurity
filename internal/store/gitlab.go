package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Connect GitLab; see internal/gitlab and internal/api/gitlab.go. The only
// GitLab credential stored is a connection's own (a group access token, or
// a read-only OAuth credential), sealed. The admin's setup token is sealed
// here for at most 10 minutes, between the code exchange and the group
// being picked, and then revoked at GitLab.

// KindGitLab is the integration kind of a project of a connected GitLab
// group: one integration per project, made and changed only by Connect
// GitLab (never with POST /integrations).
const KindGitLab = "gitlab"

// GitLabStateTTL is how long an authorisation at GitLab, and then picking
// the group, may take.
const GitLabStateTTL = 10 * time.Minute

// ErrGitLabStateInvalid hides whether a state is unknown, used, expired,
// another person's or another organisation's.
var ErrGitLabStateInvalid = errors.New("this GitLab link is not valid any more; start Connect GitLab again")

// ErrGitLabGroupTaken: the group (or a group containing it, or one inside
// it) is already connected to another organisation. Which one is never
// said.
var ErrGitLabGroupTaken = errors.New("this GitLab group, or a group above or below it, is already connected to another Stackurity organisation; disconnect it there first")

// ErrGitLabCredentialRevoked: GitLab no longer accepts the connection's
// credential (revoked, expired, or its refresh token was used elsewhere).
var ErrGitLabCredentialRevoked = errors.New("GitLab no longer accepts this connection's credential")

// ErrGitLabNoCredential: the connection has no working credential.
var ErrGitLabNoCredential = errors.New("this GitLab connection has no working credential")

// GitLabState is a claimed authorisation.
type GitLabState struct {
	ID           int64
	Purpose      string
	ConnectionID *int64
	ReturnTo     string
}

func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CreateGitLabState starts an authorisation at GitLab for a person of the
// context's workspace and returns the state to send.
func (s *Store) CreateGitLabState(ctx context.Context, userID int64, purpose string, connectionID *int64, returnTo string) (string, error) {
	state, err := randomSecret()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(state))
	// Expired rows still holding a setup token are revoked and deleted by
	// TakeExpiredGitLabPicks; the rest are deleted here.
	if _, err := s.Pool.Exec(ctx, `DELETE FROM gitlab_oauth_states WHERE expires_at < now() - interval '1 day' AND user_token IS NULL`); err != nil {
		return "", err
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO gitlab_oauth_states (state_hash, user_id, purpose, connection_id, return_to, expires_at)
		VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))`, sum[:], userID, purpose, connectionID, returnTo, GitLabStateTTL.Seconds())
	return state, err
}

// ClaimGitLabState uses a state once: it must be unexpired and started by
// the same person in the context's workspace (row-level security keeps
// other workspaces' states out).
func (s *Store) ClaimGitLabState(ctx context.Context, state string, userID int64) (*GitLabState, error) {
	if state == "" || len(state) > 100 {
		return nil, ErrGitLabStateInvalid
	}
	sum := sha256.Sum256([]byte(state))
	var st GitLabState
	err := s.Pool.QueryRow(ctx, `UPDATE gitlab_oauth_states SET used_at = now()
		WHERE state_hash = $1 AND user_id = $2 AND used_at IS NULL AND expires_at > now()
		RETURNING id, purpose, connection_id, return_to`, sum[:], userID).Scan(&st.ID, &st.Purpose, &st.ConnectionID, &st.ReturnTo)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrGitLabStateInvalid
	}
	if err != nil {
		return nil, err
	}
	return &st, nil
}

func gitlabPickName(stateID int64) string { return "gitlab-setup:" + strconv.FormatInt(stateID, 10) }

// SetGitLabPick keeps the person's setup token, sealed, on their claimed
// state until they pick a group (GitLabStateTTL from now), and returns the
// single-use handle that picks it up.
func (s *Store) SetGitLabPick(ctx context.Context, box Sealer, stateID int64, userToken string) (string, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return "", errNoWorkspace
	}
	pick, err := randomSecret()
	if err != nil {
		return "", err
	}
	sealed, err := box.Seal(ws, gitlabPickName(stateID), userToken)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(pick))
	tag, err := s.Pool.Exec(ctx, `UPDATE gitlab_oauth_states SET pick_hash = $2, user_token = $3, expires_at = now() + make_interval(secs => $4)
		WHERE id = $1 AND purpose = 'setup' AND used_at IS NOT NULL AND user_token IS NULL`, stateID, sum[:], sealed, GitLabStateTTL.Seconds())
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrGitLabStateInvalid
	}
	return pick, err
}

// TakeGitLabPick returns the setup token a pick handle holds, once, to the
// person it belongs to, and deletes it.
func (s *Store) TakeGitLabPick(ctx context.Context, box Sealer, pick string, userID int64) (string, string, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return "", "", errNoWorkspace
	}
	if pick == "" || len(pick) > 100 {
		return "", "", ErrGitLabStateInvalid
	}
	sum := sha256.Sum256([]byte(pick))
	var id int64
	var sealed []byte
	var returnTo string
	err := s.Pool.QueryRow(ctx, `UPDATE gitlab_oauth_states n SET user_token = NULL, pick_hash = NULL
		FROM (SELECT id, user_token FROM gitlab_oauth_states WHERE pick_hash = $1 AND user_id = $2 AND user_token IS NOT NULL
			AND expires_at > now() FOR UPDATE) o
		WHERE n.id = o.id RETURNING n.id, o.user_token, n.return_to`, sum[:], userID).Scan(&id, &sealed, &returnTo)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrGitLabStateInvalid
	}
	if err != nil {
		return "", "", err
	}
	tok, err := box.Open(ws, gitlabPickName(id), sealed)
	return tok, returnTo, err
}

// TakeExpiredGitLabPicks removes the setup tokens of every organisation
// whose group was never picked, and returns them so they can be revoked at
// GitLab. System scope.
func (s *Store) TakeExpiredGitLabPicks(ctx context.Context, box Sealer) ([]string, error) {
	ctx = tenant.System(ctx)
	rows, err := s.Pool.Query(ctx, `DELETE FROM gitlab_oauth_states WHERE user_token IS NOT NULL AND expires_at <= now()
		RETURNING id, workspace_id, user_token`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, ws int64
		var sealed []byte
		if err := rows.Scan(&id, &ws, &sealed); err != nil {
			return nil, err
		}
		if tok, err := box.Open(ws, gitlabPickName(id), sealed); err == nil {
			out = append(out, tok)
		}
	}
	return out, rows.Err()
}

// GitLabConnection is a GitLab group connected to one organisation.
type GitLabConnection struct {
	ID                int64      `json:"id"`
	GroupID           int64      `json:"group_id"`
	GroupPath         string     `json:"group_path"`
	GroupName         string     `json:"group_name"`
	CredentialKind    string     `json:"credential_kind"`
	CredentialExpires *time.Time `json:"credential_expires"`
	Webhook           string     `json:"webhook"`
	Status            string     `json:"status"`
	Note              string     `json:"note"`
	ConnectedBy       *int64     `json:"connected_by"`
	ConnectedAt       time.Time  `json:"connected_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	LastSync          *time.Time `json:"last_sync"`
	// Projects scanned through it (not removed).
	Projects int64 `json:"projects"`
	// ProjectID is the Stackurity project its assets are added to (nil:
	// none, they stay in no project).
	ProjectID *int64 `json:"project_id"`
	// TokenID and HookID are GitLab's ids of what Stackurity created.
	TokenID *int64 `json:"-"`
	HookID  *int64 `json:"-"`
}

const glConnCols = `c.id, c.group_id, c.group_path, c.group_name, c.credential_kind, c.credential_expires, c.webhook, c.status, c.note,
	c.connected_by, c.connected_at, c.updated_at, c.last_sync,
	(SELECT count(*) FROM gitlab_projects p WHERE p.connection_id = c.id AND p.removed_at IS NULL), c.project_id, c.token_id, c.hook_id`

// BindGitLabGroup records a group as connected to the context's workspace;
// a group already connected here is returned as it is (connecting again
// renews its credential). A group connected to another organisation, or
// one above or below a group connected anywhere, is refused: a project is
// scanned for one organisation.
//
// project is the Stackurity project the group's assets are added to: nil
// keeps what a connection made before has (none for a new one), 0 is none.
// A project chosen when connecting again also files the assets already
// scanned that are in no project.
func (s *Store) BindGitLabGroup(ctx context.Context, groupID int64, path, name string, by int64, project *int64) (*GitLabConnection, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil, errNoWorkspace
	}
	var installer *int64
	if by > 0 {
		installer = &by
	}
	var id int64
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		// One bind at a time, so two overlapping groups cannot both pass the
		// check.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(726354140)`); err != nil {
			return err
		}
		// Connecting a group connected here again (its credential expired,
		// or to renew the group access token) carries on with the same
		// connection.
		err := tx.QueryRow(ctx, `UPDATE gitlab_connections SET group_path = $2, group_name = $3, updated_at = now() WHERE group_id = $1 RETURNING id`,
			groupID, clip(path, 255), clip(name, 255)).Scan(&id)
		if err == nil && project != nil {
			_, err = setGitLabProject(ctx, tx, id, *project)
		}
		if err == nil || !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var owner int64
		err = asSystem(ctx, tx, func() error {
			return tx.QueryRow(ctx, `SELECT workspace_id FROM gitlab_connections
				WHERE group_id = $1 OR lower(group_path) = lower($2)
					OR starts_with(lower($2), lower(group_path) || '/') OR starts_with(lower(group_path), lower($2) || '/')
				ORDER BY (workspace_id = $3) LIMIT 1`, groupID, path, ws).Scan(&owner)
		})
		switch {
		case err == nil && owner != ws:
			return ErrGitLabGroupTaken
		case err == nil:
			return fmt.Errorf("%w: this group, or a group above or below it, is already connected here", ErrConflict)
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		var pid *int64
		if project != nil && *project > 0 {
			pid = project
		}
		return tx.QueryRow(ctx, `INSERT INTO gitlab_connections (group_id, group_path, group_name, connected_by, project_id) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
			groupID, clip(path, 255), clip(name, 255), installer, pid).Scan(&id)
	})
	if isUniqueViolation(err) {
		return nil, ErrGitLabGroupTaken
	}
	if err != nil {
		return nil, err
	}
	return s.GetGitLabConnection(ctx, id)
}

// SetGitLabProject chooses the Stackurity project a connection's assets
// are added to (0: none). The assets its projects already have that are in
// no active project are added to it now; it returns how many. Assets
// already in a project stay where they are.
func (s *Store) SetGitLabProject(ctx context.Context, id, project int64) (int64, error) {
	var n int64
	err := pgx.BeginTxFunc(tenant.WithoutProject(ctx), s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var err error
		n, err = setGitLabProject(tenant.WithoutProject(ctx), tx, id, project)
		return notFound(err)
	})
	return n, err
}

func setGitLabProject(ctx context.Context, tx pgx.Tx, id, project int64) (int64, error) {
	var pid *int64
	if project > 0 {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM projects WHERE id = $1 AND archived_at IS NULL)`, project).Scan(&ok); err != nil {
			return 0, err
		}
		if !ok {
			return 0, fmt.Errorf("%w: no such project", ErrNotFound)
		}
		pid = &project
	}
	if err := tx.QueryRow(ctx, `UPDATE gitlab_connections SET project_id = $2, updated_at = now() WHERE id = $1 RETURNING id`, id, pid).Scan(&id); err != nil {
		return 0, err
	}
	if pid == nil {
		return 0, nil
	}
	tag, err := tx.Exec(ctx, `INSERT INTO project_assets (project_id, asset_id)
		SELECT DISTINCT $2::bigint, a.id FROM gitlab_projects gp
		JOIN integrations i ON i.id = gp.integration_id
		JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL
		WHERE gp.connection_id = $1
		  AND NOT EXISTS (SELECT 1 FROM project_assets pa JOIN projects p ON p.id = pa.project_id
		    WHERE pa.asset_id = a.id AND p.archived_at IS NULL)
		ON CONFLICT DO NOTHING`, id, *pid)
	return tag.RowsAffected(), err
}

// FileGitLabAsset adds the asset a Connect GitLab integration scanned to
// its connection's Stackurity project, if it has one. The runner calls it
// when the integration's asset is new to it (its first scan), so an asset
// someone took out of the project later is not put back.
func (s *Store) FileGitLabAsset(ctx context.Context, integrationID, assetID int64) error {
	_, err := s.Pool.Exec(tenant.WithoutProject(ctx), `INSERT INTO project_assets (project_id, asset_id)
		SELECT c.project_id, $2 FROM gitlab_projects gp
		JOIN gitlab_connections c ON c.id = gp.connection_id
		JOIN projects p ON p.id = c.project_id AND p.archived_at IS NULL
		WHERE gp.integration_id = $1
		ON CONFLICT DO NOTHING`, integrationID, assetID)
	return err
}

// GetGitLabConnection reads a connection of the context's workspace.
func (s *Store) GetGitLabConnection(ctx context.Context, id int64) (*GitLabConnection, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+glConnCols+` FROM gitlab_connections c WHERE c.id = $1`, id)
	if err != nil {
		return nil, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[GitLabConnection])
	return c, notFound(err)
}

// ListGitLabConnections lists the context's workspace's connections.
func (s *Store) ListGitLabConnections(ctx context.Context) ([]GitLabConnection, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+glConnCols+` FROM gitlab_connections c ORDER BY c.group_path, c.id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[GitLabConnection])
}

// ActiveGitLabConnections are the context's workspace's active connections
// not synced for at least age.
func (s *Store) ActiveGitLabConnections(ctx context.Context, age time.Duration) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id FROM gitlab_connections
		WHERE status = 'active' AND (last_sync IS NULL OR last_sync < now() - make_interval(secs => $1)) ORDER BY id`, age.Seconds())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// GitLabCredential is a connection's credential, in clear only in memory.
type GitLabCredential struct {
	// Token is the group access token, or the OAuth access token.
	Token string `json:"token"`
	// RefreshToken is the OAuth refresh token (oauth only).
	RefreshToken string `json:"refresh_token,omitempty"`
	// ExpiresAt is when Token expires.
	ExpiresAt time.Time `json:"expires_at"`
}

func gitlabCredName(groupID int64) string {
	return "gitlab-credential:" + strconv.FormatInt(groupID, 10)
}

func sealGitLabCred(box Sealer, ws, groupID int64, c GitLabCredential) ([]byte, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return box.Seal(ws, gitlabCredName(groupID), string(b))
}

func openGitLabCred(box Sealer, ws, groupID int64, sealed []byte) (*GitLabCredential, error) {
	s, err := box.Open(ws, gitlabCredName(groupID), sealed)
	if err != nil {
		return nil, err
	}
	var c GitLabCredential
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		return nil, errors.New("stored GitLab credential is corrupt")
	}
	return &c, nil
}

// SetGitLabCredential stores a connection's credential (kind group_token
// or oauth), sealed, and makes the connection active. expires is when the
// credential as a whole stops working (a group access token's expiry); nil
// for an OAuth credential, which is refreshed.
func (s *Store) SetGitLabCredential(ctx context.Context, box Sealer, id int64, kind string, c GitLabCredential, tokenID *int64, expires *time.Time) error {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return errNoWorkspace
	}
	if kind != "group_token" && kind != "oauth" {
		return fmt.Errorf("%w: credential kind %q", ErrInvalid, kind)
	}
	var group int64
	if err := s.Pool.QueryRow(ctx, `SELECT group_id FROM gitlab_connections WHERE id = $1`, id).Scan(&group); err != nil {
		return notFound(err)
	}
	sealed, err := sealGitLabCred(box, ws, group, c)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `UPDATE gitlab_connections SET credential_kind = $2, credential = $3, token_id = $4, credential_expires = $5,
		status = 'active', note = '', updated_at = now() WHERE id = $1`, id, kind, sealed, tokenID, expires)
	return err
}

// SetGitLabStatus records a connection's status (active, needs_credential
// or expired) with a note. Expired or needing a credential, its projects'
// integrations show the note.
func (s *Store) SetGitLabStatus(ctx context.Context, id int64, status, note string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE gitlab_connections SET status = $2, note = $3, updated_at = now() WHERE id = $1`, id, status, clip(note, 1000))
	return err
}

// SetGitLabWebhook records the group webhook Stackurity created (hookID
// and the SHA-256 of its secret), or why there is none (not_permitted,
// none).
func (s *Store) SetGitLabWebhook(ctx context.Context, id int64, status string, hookID *int64, secret string) error {
	var hash []byte
	if secret != "" {
		sum := sha256.Sum256([]byte(secret))
		hash = sum[:]
	}
	_, err := s.Pool.Exec(ctx, `UPDATE gitlab_connections SET webhook = $2, hook_id = $3, hook_secret_hash = $4, updated_at = now() WHERE id = $1`,
		id, status, hookID, hash)
	return err
}

// GitLabHookOwner checks a webhook delivery's X-Gitlab-Token against the
// connection's webhook secret, in constant time, and returns the workspace
// the connection belongs to. ErrNotFound for anything that does not match
// (no such connection, no webhook, wrong or missing token).
func (s *Store) GitLabHookOwner(ctx context.Context, id int64, token string) (int64, error) {
	var ws int64
	var hash []byte
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT workspace_id, hook_secret_hash FROM gitlab_connections WHERE id = $1`, id).Scan(&ws, &hash)
	sum := sha256.Sum256([]byte(token))
	if err != nil || len(hash) != sha256.Size {
		// Compare anyway, so a missing connection takes as long.
		hash = make([]byte, sha256.Size)
		subtle.ConstantTimeCompare(sum[:], hash)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return 0, err
		}
		return 0, ErrNotFound
	}
	if token == "" || subtle.ConstantTimeCompare(sum[:], hash) != 1 {
		return 0, ErrNotFound
	}
	return ws, nil
}

// GitLabSecrets is what cleanup needs: the connection's credential and
// what Stackurity created on GitLab.
type GitLabSecrets struct {
	GroupID    int64
	Kind       string
	Credential *GitLabCredential
	TokenID    *int64
	HookID     *int64
}

// GitLabConnectionSecrets opens a connection's credential (nil when it has
// none or it cannot be opened) for disconnecting.
func (s *Store) GitLabConnectionSecrets(ctx context.Context, box Sealer, id int64) (*GitLabSecrets, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil, errNoWorkspace
	}
	var out GitLabSecrets
	var sealed []byte
	if err := s.Pool.QueryRow(ctx, `SELECT group_id, credential_kind, credential, token_id, hook_id FROM gitlab_connections WHERE id = $1`, id).
		Scan(&out.GroupID, &out.Kind, &sealed, &out.TokenID, &out.HookID); err != nil {
		return nil, notFound(err)
	}
	if len(sealed) > 0 && box != nil {
		out.Credential, _ = openGitLabCred(box, ws, out.GroupID, sealed)
	}
	return &out, nil
}

// GitLabRefresher trades a refresh token for a new credential. It returns
// an error wrapping ErrGitLabCredentialRevoked when GitLab no longer
// accepts the refresh token.
type GitLabRefresher func(ctx context.Context, refreshToken string) (*GitLabCredential, error)

// refreshMargin: an OAuth access token closer than this to its expiry is
// refreshed before use (a clone may take minutes).
const refreshMargin = 15 * time.Minute

// GitLabAccessToken returns a working token for a connection of the
// context's workspace. A group access token is returned as stored. An
// OAuth access token near its expiry is refreshed first; the refresh runs
// with the connection's row locked, so concurrent callers wait and then use
// the new token, and GitLab's new refresh token is stored in the same
// transaction (GitLab revokes the old one when it is used: a second
// refresh with it would fail and lose the credential).
func (s *Store) GitLabAccessToken(ctx context.Context, box Sealer, id int64, refresh GitLabRefresher) (string, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return "", errNoWorkspace
	}
	if box == nil {
		return "", errors.New("Connect GitLab needs STACKURITY_SECRET_KEY to open the stored credential")
	}
	read := func(q interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	}, lock string) (string, *GitLabCredential, error) {
		var group int64
		var kind, status string
		var sealed []byte
		if err := q.QueryRow(ctx, `SELECT group_id, credential_kind, status, credential FROM gitlab_connections WHERE id = $1`+lock, id).
			Scan(&group, &kind, &status, &sealed); err != nil {
			return "", nil, notFound(err)
		}
		if status != "active" || kind == "none" || len(sealed) == 0 {
			return "", nil, ErrGitLabNoCredential
		}
		c, err := openGitLabCred(box, ws, group, sealed)
		return kind, c, err
	}
	kind, c, err := read(s.Pool, "")
	if err != nil {
		return "", err
	}
	if kind == "group_token" || time.Until(c.ExpiresAt) > refreshMargin {
		if kind == "group_token" && !c.ExpiresAt.IsZero() && time.Now().After(c.ExpiresAt) {
			return "", fmt.Errorf("%w: the group access token expired on %s", ErrGitLabCredentialRevoked, c.ExpiresAt.Format("2 January 2006"))
		}
		return c.Token, nil
	}
	var token string
	var revoked error
	err = pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		_, c, err := read(tx, " FOR UPDATE")
		if err != nil {
			return err
		}
		if time.Until(c.ExpiresAt) > refreshMargin {
			// Another caller refreshed it while this one waited.
			token = c.Token
			return nil
		}
		next, err := refresh(ctx, c.RefreshToken)
		if errors.Is(err, ErrGitLabCredentialRevoked) {
			revoked = err
			_, uerr := tx.Exec(ctx, `UPDATE gitlab_connections SET status = 'expired', note = $2, updated_at = now() WHERE id = $1`, id,
				"GitLab no longer accepts Stackurity's read-only authorisation (revoked on GitLab, or the person who gave it lost access). Connect GitLab again.")
			return uerr
		}
		if err != nil {
			return err
		}
		if next.RefreshToken == "" {
			next.RefreshToken = c.RefreshToken
		}
		var group int64
		if err := tx.QueryRow(ctx, `SELECT group_id FROM gitlab_connections WHERE id = $1`, id).Scan(&group); err != nil {
			return err
		}
		sealed, err := sealGitLabCred(box, ws, group, *next)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE gitlab_connections SET credential = $2, updated_at = now() WHERE id = $1`, id, sealed); err != nil {
			return err
		}
		token = next.Token
		return nil
	})
	if err != nil {
		return "", err
	}
	if revoked != nil {
		return "", revoked
	}
	return token, nil
}

// UpdateGitLabConnection refreshes the group's path and name and records a
// sync with note.
func (s *Store) UpdateGitLabConnection(ctx context.Context, id int64, path, name, note string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE gitlab_connections SET group_path = $2, group_name = $3, note = $4, last_sync = now(), updated_at = now()
		WHERE id = $1 AND status = 'active'`, id, clip(path, 255), clip(name, 255), clip(note, 1000))
	return err
}

// DisconnectGitLab removes a connection of the context's workspace: its
// credential and webhook secret are deleted with it, and its projects'
// integrations are switched off with note and kept, with their assets and
// history.
func (s *Store) DisconnectGitLab(ctx context.Context, id int64, note string) error {
	return pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE integrations i SET enabled = false, last_error = $2
			FROM gitlab_projects p WHERE p.connection_id = $1 AND p.integration_id = i.id AND i.enabled`, id, clip(note, 2000)); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM gitlab_connections WHERE id = $1`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err == nil {
			_, err = tx.Exec(ctx, `DELETE FROM gitlab_oauth_states WHERE connection_id = $1`, id)
		}
		return err
	})
}

// GitLabProject is what a sync knows of one project.
type GitLabProject struct {
	ID            int64
	Path          string
	DefaultBranch string
	// GitURL is the normalised git-url identity its asset has (the same as
	// a CI scan's or a Git integration's).
	GitURL string
	// Config is the new integration's config.
	Config json.RawMessage
}

// GitLabSyncResult says what a sync changed.
type GitLabSyncResult struct {
	// Scan are integrations to scan now: new projects, and ones back in
	// the group.
	Scan []int64
	// Removed are projects no longer in the group.
	Removed int
	// Waiting are new projects left out at the asset limit.
	Waiting int
	// Limit and Monitored describe the asset limit when Waiting > 0.
	Limit, Monitored int64
}

// SyncGitLabProjects makes the context's workspace's view of an active
// connection's projects match the group's: a gitlab integration for each
// new project (while the asset limit leaves room; a project whose asset
// already exists, from CI or a Git integration, needs none), a project back
// in the group is switched on again, and one no longer in it is removed
// from scope (its integration is switched off and its asset's issues
// resolve as removed). A project whose integration someone deleted stays
// left out.
//
// TODO: SyncGitHubRepositories (the GitHub App, PR #169) is the same
// algorithm over its own tables; unify once both are merged.
func (s *Store) SyncGitLabProjects(ctx context.Context, id int64, projects []GitLabProject, schedule time.Duration, note string) (*GitLabSyncResult, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil, errNoWorkspace
	}
	res := &GitLabSyncResult{}
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM gitlab_connections WHERE id = $1 FOR UPDATE`, id).Scan(&status); err != nil {
			return notFound(err)
		}
		if status != "active" {
			return nil
		}
		type known struct {
			id          int64
			integration *int64
			removed     bool
		}
		have := map[int64]known{}
		rows, err := tx.Query(ctx, `SELECT project_id, id, integration_id, removed_at IS NOT NULL FROM gitlab_projects WHERE connection_id = $1`, id)
		if err != nil {
			return err
		}
		for rows.Next() {
			var pid int64
			var k known
			if err := rows.Scan(&pid, &k.id, &k.integration, &k.removed); err != nil {
				rows.Close()
				return err
			}
			have[pid] = k
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		room := int64(-1)
		var limit *int64
		var monitored, pending int64
		err = asSystem(ctx, tx, func() error {
			var err error
			if limit, err = assetLimit(ctx, tx, ws); err != nil || limit == nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM assets WHERE `+monitoredWhere, ws).Scan(&monitored); err != nil {
				return err
			}
			// Integrations still waiting for their first scan take room too.
			return tx.QueryRow(ctx, `SELECT count(*) FROM integrations WHERE workspace_id = $1 AND kind = $2 AND enabled AND asset_id IS NULL`,
				ws, KindGitLab).Scan(&pending)
		})
		if err != nil {
			return err
		}
		if limit != nil {
			room = max(*limit-monitored-pending, 0)
			res.Limit, res.Monitored = *limit, monitored
		}
		inGroup := map[int64]bool{}
		for _, p := range projects {
			inGroup[p.ID] = true
			k, seen := have[p.ID]
			if seen && k.integration == nil && !k.removed {
				// Left out on purpose: its integration was deleted.
				if _, err := tx.Exec(ctx, `UPDATE gitlab_projects SET path_with_namespace = $2, default_branch = $3 WHERE id = $1`,
					k.id, p.Path, clip(p.DefaultBranch, 255)); err != nil {
					return err
				}
				continue
			}
			if seen && k.integration != nil {
				if _, err := tx.Exec(ctx, `UPDATE gitlab_projects SET path_with_namespace = $2, default_branch = $3, removed_at = NULL WHERE id = $1`,
					k.id, p.Path, clip(p.DefaultBranch, 255)); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `UPDATE integrations SET config = $2 WHERE id = $1`, *k.integration, p.Config); err != nil {
					return err
				}
				if k.removed {
					if _, err := tx.Exec(ctx, `UPDATE integrations SET enabled = true, last_error = '' WHERE id = $1`, *k.integration); err != nil {
						return err
					}
					res.Scan = append(res.Scan, *k.integration)
				}
				continue
			}
			if room == 0 {
				var exists bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM asset_identifiers ai JOIN assets a ON a.id = ai.asset_id
					WHERE ai.scheme = 'git-url' AND ai.value = $1 AND a.merged_into IS NULL)`, p.GitURL).Scan(&exists); err != nil {
					return err
				}
				if !exists {
					res.Waiting++
					continue
				}
			}
			// The project's integration from an earlier connection
			// (disconnected and connected again) carries on, with its asset
			// and history.
			var inID int64
			err := tx.QueryRow(ctx, `UPDATE integrations i SET enabled = true, last_error = '', config = $3
				WHERE i.id = (SELECT id FROM integrations WHERE kind = $1 AND config->>'project_id' = $2
					AND NOT EXISTS (SELECT 1 FROM gitlab_projects gp WHERE gp.integration_id = integrations.id)
					ORDER BY id LIMIT 1)
				RETURNING i.id`, KindGitLab, strconv.FormatInt(p.ID, 10), p.Config).Scan(&inID)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			name := p.Path
			for i := 2; inID == 0; i++ {
				err := tx.QueryRow(ctx, `INSERT INTO integrations (kind, name, config, secret_ref, schedule) VALUES ($1, $2, $3, '', $4)
					ON CONFLICT (workspace_id, kind, name) DO NOTHING RETURNING id`, KindGitLab, name, p.Config, schedule).Scan(&inID)
				if err == nil {
					break
				}
				if !errors.Is(err, pgx.ErrNoRows) || i > 20 {
					return err
				}
				name = fmt.Sprintf("%s (%d)", p.Path, i)
			}
			if seen {
				if _, err := tx.Exec(ctx, `UPDATE gitlab_projects SET path_with_namespace = $2, default_branch = $3, integration_id = $4, removed_at = NULL
					WHERE id = $1`, k.id, p.Path, clip(p.DefaultBranch, 255), inID); err != nil {
					return err
				}
			} else if _, err := tx.Exec(ctx, `INSERT INTO gitlab_projects (connection_id, project_id, path_with_namespace, default_branch, integration_id)
				VALUES ($1, $2, $3, $4, $5)`, id, p.ID, p.Path, clip(p.DefaultBranch, 255), inID); err != nil {
				return err
			}
			if room > 0 {
				room--
			}
			res.Scan = append(res.Scan, inID)
		}
		var gone []int64
		for pid, k := range have {
			if !inGroup[pid] && !k.removed {
				gone = append(gone, pid)
			}
		}
		n, err := removeGitLabProjects(ctx, tx, id, gone, note)
		res.Removed = n
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// removeGitLabProjects marks projects removed: their integrations are
// switched off with note, and each asset the integration reports resolves
// as removed. The asset, its integration and their history stay.
func removeGitLabProjects(ctx context.Context, tx pgx.Tx, connID int64, projectIDs []int64, note string) (int, error) {
	if len(projectIDs) == 0 {
		return 0, nil
	}
	rows, err := tx.Query(ctx, `UPDATE gitlab_projects SET removed_at = now()
		WHERE connection_id = $1 AND project_id = ANY($2) AND removed_at IS NULL
		RETURNING integration_id, path_with_namespace`, connID, projectIDs)
	if err != nil {
		return 0, err
	}
	type gone struct {
		integration *int64
		path        string
	}
	var list []gone
	for rows.Next() {
		var g gone
		if err := rows.Scan(&g.integration, &g.path); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, g := range list {
		if g.integration == nil {
			continue
		}
		var asset *int64
		if err := tx.QueryRow(ctx, `UPDATE integrations SET enabled = false, last_error = $2 WHERE id = $1 RETURNING asset_id`,
			*g.integration, clip(note, 2000)).Scan(&asset); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return 0, err
		}
		if asset == nil {
			continue
		}
		if err := resolveIntegrationRepoRemoved(ctx, tx, *asset, *g.integration, "gitlab:"+g.path,
			"no longer in the connected GitLab group: the project was deleted, moved out of the group or Stackurity lost access to it"); err != nil {
			return 0, err
		}
	}
	return len(list), nil
}

// resolveIntegrationRepoRemoved gives a repository asset reported by
// integration a complete, empty collection (its issues resolve as removed
// on the next evaluation), a coverage note saying why, and collection
// status "removed". An asset whose latest report came from elsewhere (a CI
// scan) is left alone: that source still speaks for it.
//
// TODO: resolveRepoRemoved (the GitHub App, PR #169) is this with a fixed
// reason; unify once both are merged.
func resolveIntegrationRepoRemoved(ctx context.Context, tx pgx.Tx, assetID, integrationID int64, scope, reason string) error {
	var reporter *int64
	if err := tx.QueryRow(ctx, `SELECT report_integration_id FROM assets WHERE id = $1 AND merged_into IS NULL FOR UPDATE`, assetID).Scan(&reporter); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	if reporter == nil || *reporter != integrationID {
		return nil
	}
	const collector = "lockfile-scanner" // lockfile.CollectorID, the scan that reported it
	var coll int64
	if err := tx.QueryRow(ctx, `INSERT INTO collections
		(asset_id, collector_id, collector_version, method, observed_at, complete, observation_count, proves_absence)
		VALUES ($1, $2, '', 'repository', now(), true, 0, true) RETURNING id`, assetID, collector).Scan(&coll); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE inventory SET removed_at = now() WHERE asset_id = $1 AND removed_at IS NULL`, assetID); err != nil {
		return err
	}
	scope = clip(scope, 500)
	if _, err := tx.Exec(ctx, `INSERT INTO coverage (asset_id, collector_id, scope, status, reason, tool_version, last_attempt)
		VALUES ($1, $2, $3, 'skipped', $4, '', now())
		ON CONFLICT (asset_id, collector_id, scope) DO UPDATE SET status = EXCLUDED.status, reason = EXCLUDED.reason,
		  last_attempt = EXCLUDED.last_attempt`, assetID, collector, scope, reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO coverage_history (collection_id, scope, status, reason) VALUES ($1, $2, 'skipped', $3)`,
		coll, scope, reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE assets SET collection_status = $2 WHERE id = $1`, assetID, AssetRemoved); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO jobs (kind, payload, dedupe_key, run_at)
		VALUES ('evaluate', jsonb_build_object('asset_id', $1::bigint), 'evaluate:asset:' || $1::bigint, now() + interval '5 seconds')
		ON CONFLICT (COALESCE(workspace_id, 0), dedupe_key) WHERE dedupe_key IS NOT NULL AND done_at IS NULL AND failed_at IS NULL
		DO UPDATE SET requeue = true WHERE jobs.locked_at IS NOT NULL`, assetID)
	return err
}

// GitLabProjectRef is a project of a connection with the connection's
// state.
type GitLabProjectRef struct {
	ConnectionID       int64
	ProjectID          int64
	Path               string
	DefaultBranch      string
	IntegrationID      *int64
	IntegrationEnabled bool
	Removed            bool
	ConnectionStatus   string
	GroupPath          string
}

const glProjCols = `p.connection_id, p.project_id, p.path_with_namespace, p.default_branch, p.integration_id, COALESCE(i.enabled, false),
	p.removed_at IS NOT NULL, c.status, c.group_path`

// GitLabProjectForIntegration finds the project an integration of the
// context's workspace scans. Row-level security keeps it to that
// workspace.
func (s *Store) GitLabProjectForIntegration(ctx context.Context, integrationID int64) (*GitLabProjectRef, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+glProjCols+` FROM gitlab_projects p
		JOIN gitlab_connections c ON c.id = p.connection_id
		LEFT JOIN integrations i ON i.id = p.integration_id
		WHERE p.integration_id = $1`, integrationID)
	if err != nil {
		return nil, err
	}
	r, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[GitLabProjectRef])
	return r, notFound(err)
}

// GitLabProjectByID finds a project of a connection of the context's
// workspace.
func (s *Store) GitLabProjectByID(ctx context.Context, connID, projectID int64) (*GitLabProjectRef, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+glProjCols+` FROM gitlab_projects p
		JOIN gitlab_connections c ON c.id = p.connection_id
		LEFT JOIN integrations i ON i.id = p.integration_id
		WHERE p.connection_id = $1 AND p.project_id = $2`, connID, projectID)
	if err != nil {
		return nil, err
	}
	r, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[GitLabProjectRef])
	return r, notFound(err)
}

// GitLabDeliveryFresh records a webhook delivery and reports whether it is
// new: a redelivery (the same X-Gitlab-Event-UUID) or the same body sent
// again is not.
func (s *Store) GitLabDeliveryFresh(ctx context.Context, delivery string, bodyHash []byte, event string) (bool, error) {
	ctx = tenant.System(ctx)
	if _, err := s.Pool.Exec(ctx, `DELETE FROM gitlab_deliveries WHERE received_at < now() - interval '30 days'`); err != nil {
		return false, err
	}
	tag, err := s.Pool.Exec(ctx, `INSERT INTO gitlab_deliveries (delivery_id, body_hash, event) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		clip(delivery, 100), bodyHash, clip(strings.TrimSpace(event), 60))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ForgetGitLabDelivery drops a delivery that could not be handled, so
// GitLab's retry is.
func (s *Store) ForgetGitLabDelivery(ctx context.Context, delivery string) error {
	_, err := s.Pool.Exec(tenant.System(ctx), `DELETE FROM gitlab_deliveries WHERE delivery_id = $1`, delivery)
	return err
}

// QueueIntegrationRun queues an integration's run within delay: sooner
// than an already-queued run, and once more after one that is running now
// (a push that arrives during a scan may not be in its clone).
//
// TODO: ScanSoon (the GitHub App, PR #169) is the same; keep one once both
// are merged.
func (s *Store) QueueIntegrationRun(ctx context.Context, integrationID int64, delay time.Duration) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO jobs (kind, payload, dedupe_key, run_at)
		VALUES ('integration.run', jsonb_build_object('integration_id', $1::bigint), 'integration:' || $1::bigint, now() + make_interval(secs => $2))
		ON CONFLICT (COALESCE(workspace_id, 0), dedupe_key) WHERE dedupe_key IS NOT NULL AND done_at IS NULL AND failed_at IS NULL
		DO UPDATE SET run_at = LEAST(jobs.run_at, EXCLUDED.run_at), requeue = jobs.requeue OR jobs.locked_at IS NOT NULL`,
		integrationID, delay.Seconds())
	return err
}
