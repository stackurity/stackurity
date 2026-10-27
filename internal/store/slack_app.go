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

// The Stackurity Slack app ("Add to Slack"); see internal/api/slack_app.go.

// SlackOAuthTTL is how long an "Add to Slack" may take.
const SlackOAuthTTL = 10 * time.Minute

// ErrSlackStateInvalid hides whether an OAuth state is unknown, used,
// expired, another person's or another organisation's.
var ErrSlackStateInvalid = errors.New("this Slack link is not valid any more; start Add to Slack again")

// CreateSlackOAuthState starts an install for a person of the context's
// workspace and returns the state to send to Slack.
func (s *Store) CreateSlackOAuthState(ctx context.Context, userID int64, returnTo string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	state := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(state))
	if _, err := s.Pool.Exec(ctx, `DELETE FROM slack_oauth_states WHERE expires_at < now() - interval '1 day'`); err != nil {
		return "", err
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO slack_oauth_states (state_hash, user_id, return_to, expires_at)
		VALUES ($1, $2, $3, now() + make_interval(secs => $4))`, sum[:], userID, returnTo, SlackOAuthTTL.Seconds())
	return state, err
}

// ClaimSlackOAuthState uses a state once: it must be unexpired and started
// by the same person in the context's workspace (row-level security keeps
// other workspaces' states out). It returns where to send the person back.
func (s *Store) ClaimSlackOAuthState(ctx context.Context, state string, userID int64) (string, error) {
	sum := sha256.Sum256([]byte(state))
	var returnTo string
	err := s.Pool.QueryRow(ctx, `UPDATE slack_oauth_states SET used_at = now()
		WHERE state_hash = $1 AND user_id = $2 AND used_at IS NULL AND expires_at > now() RETURNING return_to`, sum[:], userID).Scan(&returnTo)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrSlackStateInvalid
	}
	return returnTo, err
}

// SlackInstallation is the app installed in a Slack workspace from an
// organisation.
type SlackInstallation struct {
	TeamID    string
	TeamName  string
	AppID     string
	BotUserID string
	Scopes    string
	BotToken  string // in clear only in memory; stored sealed
}

func slackTokenName(team string) string { return "slack-app-bot:" + team }

// SaveSlackInstallation records (or refreshes) the install in the context's
// workspace, the bot token sealed with box.
func (s *Store) SaveSlackInstallation(ctx context.Context, box Sealer, in SlackInstallation, by int64) error {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return errNoWorkspace
	}
	var sealed []byte
	if in.BotToken != "" {
		var err error
		if sealed, err = box.Seal(ws, slackTokenName(in.TeamID), in.BotToken); err != nil {
			return err
		}
	}
	var installer *int64
	if by > 0 {
		installer = &by
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO slack_installations (team_id, team_name, app_id, bot_user_id, scopes, bot_token, installed_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (workspace_id, team_id) DO UPDATE SET team_name = EXCLUDED.team_name, app_id = EXCLUDED.app_id,
			bot_user_id = EXCLUDED.bot_user_id, scopes = EXCLUDED.scopes, bot_token = COALESCE(EXCLUDED.bot_token, slack_installations.bot_token),
			installed_by = EXCLUDED.installed_by, installed_at = now()`,
		in.TeamID, in.TeamName, in.AppID, in.BotUserID, in.Scopes, sealed, installer)
	return err
}

// SlackBotToken opens the bot token of the context's workspace's install
// in team; "" when there is none.
func (s *Store) SlackBotToken(ctx context.Context, box Sealer, team string) (string, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return "", errNoWorkspace
	}
	var sealed []byte
	err := s.Pool.QueryRow(ctx, `SELECT bot_token FROM slack_installations WHERE team_id = $1`, team).Scan(&sealed)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && len(sealed) == 0 {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return box.Open(ws, slackTokenName(team), sealed)
}

// ForgetSlackChannel is called after an app channel of the context's
// workspace was deleted: it deletes the channel's webhook secret and, when
// no other app channel of that Slack workspace remains here, the install.
// last is true when no organisation has the app installed in that Slack
// workspace any more, so the app can be removed from it.
func (s *Store) ForgetSlackChannel(ctx context.Context, team, secretName string) (last bool, err error) {
	err = pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if secretName != "" {
			if _, err := tx.Exec(ctx, `DELETE FROM workspace_secrets WHERE name = $1`, secretName); err != nil {
				return err
			}
		}
		// Other app channels still connected (an uninstall from Slack
		// leaves them disabled, without their webhook).
		var others int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM channels c WHERE c.kind = 'slack' AND c.config->>'slack_app' = 'true' AND c.config->>'team_id' = $1
			AND EXISTS (SELECT 1 FROM workspace_secrets s WHERE 'secret:' || s.name = c.secret_ref)`,
			team).Scan(&others); err != nil {
			return err
		}
		if others > 0 {
			return nil
		}
		tag, err := tx.Exec(ctx, `DELETE FROM slack_installations WHERE team_id = $1`, team)
		last = err == nil && tag.RowsAffected() > 0
		return err
	})
	if err != nil || !last {
		return false, err
	}
	// The connection above is scoped to the workspace; other
	// organisations' installs are read in system scope.
	var elsewhere bool
	if err := s.Pool.QueryRow(tenant.System(ctx), `SELECT EXISTS (SELECT 1 FROM slack_installations WHERE team_id = $1)`, team).Scan(&elsewhere); err != nil {
		return false, err
	}
	return !elsewhere, nil
}

// SlackAppRemoved handles the app being removed from a Slack workspace
// (app_uninstalled, or its tokens revoked), in every organisation: their
// app channels for that team are disabled with a note, their webhook
// secrets and the installs deleted. It returns how many channels were
// disabled.
func (s *Store) SlackAppRemoved(ctx context.Context, team, note string) (int, error) {
	ctx = tenant.System(ctx)
	var n int
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE channels SET enabled = false, last_error = $2
			WHERE kind = 'slack' AND config->>'slack_app' = 'true' AND config->>'team_id' = $1
			RETURNING workspace_id, secret_ref`, team, note)
		if err != nil {
			return err
		}
		type ref struct {
			ws   int64
			name string
		}
		var refs []ref
		for rows.Next() {
			var r ref
			var secretRef string
			if err := rows.Scan(&r.ws, &secretRef); err != nil {
				rows.Close()
				return err
			}
			if len(secretRef) > len("secret:") {
				r.name = secretRef[len("secret:"):]
			}
			refs = append(refs, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		n = len(refs)
		for _, r := range refs {
			if _, err := tx.Exec(ctx, `DELETE FROM workspace_secrets WHERE workspace_id = $1 AND name = $2`, r.ws, r.name); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `DELETE FROM slack_installations WHERE team_id = $1`, team)
		return err
	})
	return n, err
}
