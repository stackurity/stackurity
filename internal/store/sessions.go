package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
)

// Your account → Active sessions: a person's own browser sessions, and
// signing them out. Sessions are an account table without row-level security
// (they are looked up before the workspace is known), so every query here
// names the user itself, and a session is named by its public_id: the token
// hash never leaves the store. API tokens are not sessions.

// SessionClient is the browser a session is signed in from: its User-Agent
// and client address, as the API saw them at sign-in.
type SessionClient struct {
	UserAgent string
	IP        string
}

type sessionClientKey struct{}

// WithSessionClient records the request's browser on ctx, so that any
// session started while handling it (CreateSessionWith, from every sign-in
// path) stores it.
func WithSessionClient(ctx context.Context, c SessionClient) context.Context {
	return context.WithValue(ctx, sessionClientKey{}, c)
}

// maxUserAgent is the most of a User-Agent that is kept.
const maxUserAgent = 512

func sessionClientOf(ctx context.Context) SessionClient {
	c, _ := ctx.Value(sessionClientKey{}).(SessionClient)
	// Printable characters only, and not too much of them: the header is
	// whatever the client sent.
	ua := strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, c.UserAgent)
	if len(ua) > maxUserAgent {
		ua = strings.ToValidUTF8(ua[:maxUserAgent], "")
	}
	c.UserAgent = strings.TrimSpace(ua)
	if len(c.IP) > 64 {
		c.IP = ""
	}
	return c
}

// ActiveSession is one of a person's browser sessions, as Your account
// shows it.
type ActiveSession struct {
	// ID names the session in the API; it is not its token and signs
	// nothing in.
	ID string `json:"id"`
	// Current: the session the request was made with.
	Current bool `json:"current"`
	// LoginMethod: how it was signed in (password, passkey, invite, signup,
	// social, sso; "" for a session from an older release).
	LoginMethod string `json:"login_method"`
	// MFAMethod: the second factor checked ("" for none).
	MFAMethod string `json:"mfa_method"`
	// UserAgent and IP: the browser and the client address at sign-in (""
	// for a session from before they were recorded).
	UserAgent string `json:"user_agent"`
	IP        string `json:"ip"`
	// Organisation: for a session pinned by an organisation's single
	// sign-on, that organisation (it works there only).
	Organisation string    `json:"organisation,omitempty"`
	SignedInAt   time.Time `json:"signed_in_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// sessionScope is which of a person's sessions a request may see: all of
// them, or for a session pinned by an organisation's single sign-on only
// those pinned to the same organisation. An organisation's identity provider
// vouches for that organisation only, so a session it started neither sees
// where the person signs in for their other organisations nor signs those
// sessions out.
const sessionScope = `s.user_id = $1 AND ($2::bigint = 0 OR s.sso_workspace_id = $2)`

// ListSessions returns userID's browser sessions that still work, newest
// sign-in first. current is the request's own session secret (marked
// Current); pinned is the workspace that session is pinned to (0: none),
// which limits the list to sessions pinned there.
func (s *Store) ListSessions(ctx context.Context, userID int64, current string, pinned int64) ([]ActiveSession, error) {
	rows, err := s.Pool.Query(ctx, `SELECT s.public_id::text, s.token_hash = $3,
		COALESCE(s.login_method, CASE WHEN s.password_login THEN 'password' WHEN s.sso_workspace_id IS NOT NULL THEN 'sso' ELSE '' END),
		COALESCE(s.mfa_method, CASE WHEN s.mfa_at IS NOT NULL THEN 'totp' ELSE '' END),
		COALESCE(s.user_agent, ''), COALESCE(s.ip, ''), COALESCE(w.name, ''), COALESCE(s.signed_in_at, s.created_at), s.last_seen_at, s.expires_at
		FROM sessions s LEFT JOIN workspaces w ON w.id = s.sso_workspace_id
		WHERE `+sessionScope+` AND s.expires_at > now() AND NOT ($4 > 0 AND s.last_seen_at < now() - make_interval(secs => $4))
		ORDER BY COALESCE(s.signed_in_at, s.created_at) DESC, s.public_id`, userID, pinned, auth.HashToken(current), s.SessionIdle.Seconds())
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ActiveSession])
	if out == nil {
		out = []ActiveSession{}
	}
	return out, err
}

var sessionIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ErrSessionEnded: the session a new ID was asked for (SessionOpts.Replaces)
// has ended, for instance signed out from Your account while the request
// was in flight. It is ErrNotFound to callers that only check that.
var ErrSessionEnded = fmt.Errorf("the session has ended: %w", ErrNotFound)

// ErrCurrentSession is a request to sign out, by its ID, the session the
// request was made with (POST /auth/logout does that).
var ErrCurrentSession = errors.New("this is the session you are using")

// EndedSession is a session signed out from Your account, for the activity
// log.
type EndedSession struct {
	ID          string
	LoginMethod string
	// Workspace is where it was working (0: none).
	Workspace int64
}

// RevokeSession signs out userID's session id at once: the row is deleted,
// and every request checks the session in the database. Another person's
// session, one outside pinned (ListSessions), an unknown ID and an ended
// session are all ErrNotFound; the request's own session (current) is
// ErrCurrentSession.
func (s *Store) RevokeSession(ctx context.Context, userID int64, id, current string, pinned int64) (*EndedSession, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	if !sessionIDPattern.MatchString(id) {
		return nil, ErrNotFound
	}
	var e EndedSession
	var ws *int64
	var isCurrent bool
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT s.public_id::text, s.token_hash = $4, COALESCE(s.login_method, ''), s.workspace_id
			FROM sessions s WHERE `+sessionScope+` AND s.public_id = $3::uuid FOR UPDATE`,
			userID, pinned, id, auth.HashToken(current)).Scan(&e.ID, &isCurrent, &e.LoginMethod, &ws)
		if err != nil {
			return notFound(err)
		}
		if isCurrent {
			return ErrCurrentSession
		}
		_, err = tx.Exec(ctx, `DELETE FROM sessions WHERE public_id = $1::uuid AND user_id = $2`, id, userID)
		return err
	})
	if err != nil {
		return nil, err
	}
	if ws != nil {
		e.Workspace = *ws
	}
	return &e, nil
}

// RevokeOtherSessions signs out every session of userID except current (the
// request's own), limited to those pinned to pinned when that is not 0
// (ListSessions). It returns how many ended.
func (s *Store) RevokeOtherSessions(ctx context.Context, userID int64, current string, pinned int64) (int64, error) {
	if current == "" {
		// Without a session to keep this would end all of them.
		return 0, ErrInvalid
	}
	tag, err := s.Pool.Exec(ctx, `DELETE FROM sessions s WHERE `+sessionScope+` AND s.token_hash <> $3`, userID, pinned, auth.HashToken(current))
	return tag.RowsAffected(), err
}
