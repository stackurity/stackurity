package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Acting from Slack (interactive buttons on Slack channels set up with a
// Slack app's signing secret). See internal/api/slack.go.

// SlackLinkTTL is how long a link to confirm a Slack account works.
const SlackLinkTTL = 15 * time.Minute

// slackSeenWindow is how long a request signature is remembered; requests
// older than 5 minutes are refused before this table is read.
const slackSeenWindow = 10 * time.Minute

// ErrSlackLinkInvalid hides whether a link token is unknown, used, expired
// or from another workspace.
var ErrSlackLinkInvalid = errors.New("this link is not valid any more; click the button in Slack again for a new one")

// ErrSlackAlreadyLinked: the Slack account is linked to another Stackurity
// account of this workspace, which has to remove the link first.
var ErrSlackAlreadyLinked = errors.New("this Slack account is already linked to another Stackurity account here; that account has to unlink it first")

// SlackChannel is a channel found by id outside any workspace scope, for
// the public interactivity endpoint: the request names it, and its signing
// secret must then verify the request.
type SlackChannel struct {
	Channel
	WorkspaceID int64
}

// SlackChannelByID finds an enabled Slack channel of an enabled workspace,
// in any workspace.
func (s *Store) SlackChannelByID(ctx context.Context, id int64) (*SlackChannel, error) {
	var c SlackChannel
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT c.id, c.kind, c.name, c.config, c.secret_ref, c.enabled, c.created_at,
		c.last_ok_at, c.last_error, c.workspace_id
		FROM channels c JOIN workspaces w ON w.id = c.workspace_id AND w.disabled_at IS NULL
		WHERE c.id = $1 AND c.kind = 'slack' AND c.enabled`, id).Scan(&c.ID, &c.Kind, &c.Name, &c.Config, &c.SecretRef, &c.Enabled,
		&c.CreatedAt, &c.LastOKAt, &c.LastError, &c.WorkspaceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &c, err
}

// SlackRequestFresh records a request signature (its SHA-256) in the
// workspace of ctx and reports whether it was new: false means a replay.
// Signatures older than the window are removed first.
func (s *Store) SlackRequestFresh(ctx context.Context, signatureHash []byte) (bool, error) {
	if _, err := s.Pool.Exec(ctx, `DELETE FROM slack_seen_requests WHERE workspace_id = stackurity_ws() AND seen_at < now() - make_interval(secs => $1)`,
		slackSeenWindow.Seconds()); err != nil {
		return false, err
	}
	tag, err := s.Pool.Exec(ctx, `INSERT INTO slack_seen_requests (signature_hash) VALUES ($1) ON CONFLICT DO NOTHING`, signatureHash)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// SlackLink is a Slack user linked to a Stackurity user of the workspace.
type SlackLink struct {
	ID            int64      `json:"id"`
	TeamID        string     `json:"team_id"`
	TeamName      string     `json:"team_name"`
	SlackUserID   string     `json:"slack_user_id"`
	SlackUserName string     `json:"slack_user_name"`
	UserID        int64      `json:"user_id"`
	CreatedAt     time.Time  `json:"created_at"`
	LastUsedAt    *time.Time `json:"last_used_at"`
}

const slackLinkCols = `id, team_id, team_name, slack_user_id, slack_user_name, user_id, created_at, last_used_at`

// SlackLinkFor returns the link of a Slack user, or ErrNotFound.
func (s *Store) SlackLinkFor(ctx context.Context, teamID, slackUserID string) (*SlackLink, error) {
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `SELECT `+slackLinkCols+` FROM slack_links WHERE team_id = $1 AND slack_user_id = $2`,
		teamID, slackUserID)
	if err != nil {
		return nil, err
	}
	l, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[SlackLink])
	return l, notFound(err)
}

// TouchSlackLink records that a link was used.
func (s *Store) TouchSlackLink(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(tenant.WithoutProject(ctx), `UPDATE slack_links SET last_used_at = now() WHERE id = $1`, id)
	return err
}

// ListSlackLinks returns the Slack accounts linked to a user.
func (s *Store) ListSlackLinks(ctx context.Context, userID int64) ([]SlackLink, error) {
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `SELECT `+slackLinkCols+` FROM slack_links WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[SlackLink])
}

// DeleteSlackLink removes one of a user's links; another user's link is not
// found.
func (s *Store) DeleteSlackLink(ctx context.Context, id, userID int64) (*SlackLink, error) {
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `DELETE FROM slack_links WHERE id = $1 AND user_id = $2 RETURNING `+slackLinkCols, id, userID)
	if err != nil {
		return nil, err
	}
	l, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[SlackLink])
	return l, notFound(err)
}

// SlackLinkRequest is a pending link to confirm a Slack account.
type SlackLinkRequest struct {
	TeamID        string    `json:"team_id"`
	TeamName      string    `json:"team_name"`
	SlackUserID   string    `json:"slack_user_id"`
	SlackUserName string    `json:"slack_user_name"`
	ExpiresAt     time.Time `json:"expires_at"`
	// LinkedToYou: this Slack account is already linked to the caller.
	LinkedToYou bool `json:"linked_to_you"`
	// LinkedToOther: it is linked to another account (which is not named).
	LinkedToOther bool `json:"linked_to_other"`
	id            int64
}

// CreateSlackLinkRequest stores a one-time link for a Slack user who is not
// linked yet, in the workspace of ctx, and returns its token (shown once,
// in Slack). Earlier unused links for the same Slack user stop working.
func (s *Store) CreateSlackLinkRequest(ctx context.Context, channelID int64, teamID, teamName, slackUserID, slackUserName string) (string, time.Time, error) {
	secret, _, err := auth.NewToken("slk")
	if err != nil {
		return "", time.Time{}, err
	}
	ctx = tenant.WithoutProject(ctx)
	var channel *int64
	if channelID > 0 {
		channel = &channelID
	}
	var expires time.Time
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM slack_link_requests WHERE expires_at < now() - interval '1 day'
			OR (team_id = $1 AND slack_user_id = $2 AND used_at IS NULL)`, teamID, slackUserID); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO slack_link_requests (channel_id, team_id, team_name, slack_user_id, slack_user_name, token_hash, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7)) RETURNING expires_at`,
			channel, teamID, clip(teamName, 200), slackUserID, clip(slackUserName, 200), auth.HashToken(secret), SlackLinkTTL.Seconds()).Scan(&expires)
	})
	return secret, expires, err
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}

func slackRequestByToken(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, token string, lock bool) (*SlackLinkRequest, error) {
	if !strings.HasPrefix(token, "slk_") || len(token) > 200 {
		return nil, ErrSlackLinkInvalid
	}
	sql := `SELECT id, team_id, team_name, slack_user_id, slack_user_name, expires_at FROM slack_link_requests
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()`
	if lock {
		sql += ` FOR UPDATE`
	}
	var r SlackLinkRequest
	err := q.QueryRow(ctx, sql, auth.HashToken(token)).Scan(&r.id, &r.TeamID, &r.TeamName, &r.SlackUserID, &r.SlackUserName, &r.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSlackLinkInvalid
	}
	return &r, err
}

// PreviewSlackLink describes a usable link token of the workspace of ctx
// for userID. A token of another workspace is invalid.
func (s *Store) PreviewSlackLink(ctx context.Context, token string, userID int64) (*SlackLinkRequest, error) {
	ctx = tenant.WithoutProject(ctx)
	r, err := slackRequestByToken(ctx, s.Pool, token, false)
	if err != nil {
		return nil, err
	}
	// In system scope, so that a member with project access only learns
	// that the Slack account is taken (never by whom).
	var owner *int64
	err = s.Pool.QueryRow(tenant.System(ctx), `SELECT user_id FROM slack_links WHERE workspace_id = $1 AND team_id = $2 AND slack_user_id = $3`,
		mustWorkspace(ctx), r.TeamID, r.SlackUserID).Scan(&owner)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if owner != nil {
		r.LinkedToYou, r.LinkedToOther = *owner == userID, *owner != userID
	}
	return r, nil
}

func mustWorkspace(ctx context.Context) int64 {
	ws, _ := tenant.Workspace(ctx)
	return ws
}

// ConfirmSlackLink uses up a link token of the workspace of ctx and links
// its Slack account to userID. It is idempotent for a Slack account
// already linked to userID, and refuses one linked to someone else.
func (s *Store) ConfirmSlackLink(ctx context.Context, token string, userID int64) (*SlackLink, error) {
	if userID <= 0 {
		return nil, ErrSlackLinkInvalid
	}
	ctx = tenant.WithoutProject(ctx)
	// Who holds the Slack account now is read in system scope (a member
	// with project access only sees their own links); the unique key
	// settles a race with another confirmation.
	pre, err := s.PreviewSlackLink(ctx, token, userID)
	if err != nil {
		return nil, err
	}
	if pre.LinkedToOther {
		return nil, ErrSlackAlreadyLinked
	}
	var link *SlackLink
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		r, err := slackRequestByToken(ctx, tx, token, true)
		if err != nil {
			return err
		}
		if r.TeamID != pre.TeamID || r.SlackUserID != pre.SlackUserID {
			return ErrSlackLinkInvalid
		}
		if !pre.LinkedToYou {
			rows, err := tx.Query(ctx, `INSERT INTO slack_links (team_id, team_name, slack_user_id, slack_user_name, user_id)
				VALUES ($1, $2, $3, $4, $5) RETURNING `+slackLinkCols, r.TeamID, r.TeamName, r.SlackUserID, r.SlackUserName, userID)
			if err != nil {
				return err
			}
			if link, err = pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[SlackLink]); err != nil {
				if isUniqueViolation(err) {
					return ErrSlackAlreadyLinked
				}
				if isForeignKey(err) {
					return fmt.Errorf("you are not a member of this organisation: %w", ErrInvalid)
				}
				return err
			}
		} else {
			rows, err := tx.Query(ctx, `UPDATE slack_links SET team_name = $3, slack_user_name = $4
				WHERE team_id = $1 AND slack_user_id = $2 RETURNING `+slackLinkCols, r.TeamID, r.SlackUserID, r.TeamName, r.SlackUserName)
			if err != nil {
				return err
			}
			if link, err = pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[SlackLink]); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE slack_link_requests SET used_at = now(), used_by = $2 WHERE id = $1`, r.id, userID)
		return err
	})
	return link, err
}
