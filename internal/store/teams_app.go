package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// The Stackurity Teams app ("Add to Teams"); see internal/api/teams_app.go.

// TeamsCodeTTL is how long an Add to Teams code can be used.
const TeamsCodeTTL = 15 * time.Minute

// ErrTeamsCodeInvalid hides whether a code is unknown, used or expired.
var ErrTeamsCodeInvalid = errors.New("this code is not valid any more")

// teamsCodeAlphabet has no 0/O, 1/I/L: codes are read and typed by people.
const teamsCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// TeamsCodeLength is the number of characters of a code (shown as two
// groups of five): 31^10, about 2^49.5.
const TeamsCodeLength = 10

// NormalizeTeamsCode upper-cases a typed code and drops spaces and
// dashes; "" when what is left cannot be a code.
func NormalizeTeamsCode(s string) string {
	var b strings.Builder
	for _, c := range strings.ToUpper(s) {
		switch {
		case c == '-' || c == ' ':
		case strings.ContainsRune(teamsCodeAlphabet, c):
			b.WriteRune(c)
		default:
			return ""
		}
	}
	if b.Len() != TeamsCodeLength {
		return ""
	}
	return b.String()
}

func teamsCodeHash(code string) []byte {
	sum := sha256.Sum256([]byte("teams-install:" + code))
	return sum[:]
}

// TeamsInstallCode is a code made for Add to Teams.
type TeamsInstallCode struct {
	ID        int64     `json:"id"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CreateTeamsInstallCode makes a code for a person of the context's
// workspace. Their earlier unused codes stop working. project (nil: the
// organisation) owns the channel the code connects.
func (s *Store) CreateTeamsInstallCode(ctx context.Context, userID int64, project *int64) (*TeamsInstallCode, error) {
	b := make([]byte, TeamsCodeLength)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	// Rejection sampling keeps every character equally likely.
	var code strings.Builder
	for code.Len() < TeamsCodeLength {
		for _, x := range b {
			if int(x) < 256-256%len(teamsCodeAlphabet) && code.Len() < TeamsCodeLength {
				code.WriteByte(teamsCodeAlphabet[int(x)%len(teamsCodeAlphabet)])
			}
		}
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
	}
	out := &TeamsInstallCode{Code: code.String()}
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM teams_install_codes WHERE expires_at < now() - interval '1 day'
			OR (user_id = $1 AND used_at IS NULL)`, userID); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO teams_install_codes (code_hash, user_id, expires_at, owner_project_id)
			VALUES ($1, $2, now() + make_interval(secs => $3), $4) RETURNING id, expires_at`,
			teamsCodeHash(out.Code), userID, TeamsCodeTTL.Seconds(), project).Scan(&out.ID, &out.ExpiresAt)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TeamsInstallClaim is a code used in Teams: whose it was.
type TeamsInstallClaim struct {
	ID        int64
	Workspace int64
	UserID    int64
	// ProjectID: the project the code was made for (nil: the organisation).
	ProjectID *int64
}

// ClaimTeamsInstallCode uses a code once, from Teams (system scope: the
// code is all that names the organisation). tenantID is the Microsoft 365
// tenant it was typed in.
func (s *Store) ClaimTeamsInstallCode(ctx context.Context, code, tenantID string) (*TeamsInstallClaim, error) {
	code = NormalizeTeamsCode(code)
	if code == "" {
		return nil, ErrTeamsCodeInvalid
	}
	var c TeamsInstallClaim
	err := s.Pool.QueryRow(tenant.System(ctx), `UPDATE teams_install_codes SET used_at = now(), tenant_id = $2
		WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now() RETURNING id, workspace_id, user_id, owner_project_id`,
		teamsCodeHash(code), truncateText(tenantID, 64)).Scan(&c.ID, &c.Workspace, &c.UserID, &c.ProjectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTeamsCodeInvalid
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// TeamsInstallBound records the channel a code connected (context: the
// code's workspace).
func (s *Store) TeamsInstallBound(ctx context.Context, codeID, channelID int64) error {
	_, err := s.Pool.Exec(ctx, `UPDATE teams_install_codes SET channel_id = $2 WHERE id = $1`, codeID, channelID)
	return err
}

// TeamsInstallStatus is what became of a code: pending (not used yet),
// expired, connected (with the channel) or failed (used, but no channel).
type TeamsInstallStatus struct {
	Status    string    `json:"status"`
	ChannelID *int64    `json:"channel_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GetTeamsInstallStatus reads a code of the person in the context's
// workspace.
func (s *Store) GetTeamsInstallStatus(ctx context.Context, id, userID int64) (*TeamsInstallStatus, error) {
	var out TeamsInstallStatus
	var used *time.Time
	var expired bool
	err := s.Pool.QueryRow(ctx, `SELECT used_at, channel_id, expires_at, expires_at <= now() FROM teams_install_codes WHERE id = $1 AND user_id = $2`,
		id, userID).Scan(&used, &out.ChannelID, &out.ExpiresAt, &expired)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	switch {
	case out.ChannelID != nil:
		out.Status = "connected"
	case used != nil:
		out.Status = "failed"
	case expired:
		out.Status = "expired"
	default:
		out.Status = "pending"
	}
	return &out, nil
}

// TeamsAppChannel finds the context's workspace's app channel for a Teams
// channel, so adding it again refreshes it instead of making a second one.
func (s *Store) TeamsAppChannel(ctx context.Context, tenantID, channelID string) (*Channel, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+channelCols+` FROM channels WHERE kind = 'teams' AND config->>'teams_app' = 'true'
		AND config->>'tenant_id' = $1 AND config->>'teams_channel_id' = $2 ORDER BY id LIMIT 1`, tenantID, channelID)
	if err != nil {
		return nil, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Channel])
	return c, notFound(err)
}

// TeamsAppRemoved handles the app being removed from a team (or the team
// or one channel deleted), in every organisation: their app channels for
// that tenant and team (and channel, when given) are switched off with
// note. It returns how many were.
func (s *Store) TeamsAppRemoved(ctx context.Context, tenantID, teamID, channelID, note string) (int, error) {
	if tenantID == "" || teamID == "" {
		return 0, nil
	}
	tag, err := s.Pool.Exec(tenant.System(ctx), `UPDATE channels SET enabled = false, last_error = $4
		WHERE kind = 'teams' AND config->>'teams_app' = 'true' AND config->>'tenant_id' = $1 AND config->>'teams_team_id' = $2
		AND ($3 = '' OR config->>'teams_channel_id' = $3)`, tenantID, teamID, channelID, note)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// TeamsAppServiceURL keeps the Bot Connector address of a team's app
// channels current in every organisation (Teams may move a team to
// another; the address comes from a verified activity and is checked by
// the caller).
func (s *Store) TeamsAppServiceURL(ctx context.Context, tenantID, teamID, serviceURL string) error {
	if tenantID == "" || teamID == "" || serviceURL == "" {
		return nil
	}
	_, err := s.Pool.Exec(tenant.System(ctx), `UPDATE channels SET config = jsonb_set(config, '{service_url}', to_jsonb($3::text))
		WHERE kind = 'teams' AND config->>'teams_app' = 'true' AND config->>'tenant_id' = $1 AND config->>'teams_team_id' = $2
		AND config->>'service_url' IS DISTINCT FROM $3`, tenantID, teamID, serviceURL)
	return err
}

// DisconnectChannel switches a channel off with a note saying why.
func (s *Store) DisconnectChannel(ctx context.Context, id int64, note string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE channels SET enabled = false, last_error = $2 WHERE id = $1`, id, truncateText(note, 1000))
	return err
}
