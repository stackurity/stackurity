package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Ask Stackurity feedback (migration ask_feedback): explicit ratings and
// forms from people, implicit signals the server notices, and the
// operator's review of both. Organisations never list feedback: only the
// installation's operators read it, in system scope.

// Feedback retention: snapshots go after AskFeedbackSnapshotRetention, rows
// after AskFeedbackRetention (PurgeAskFeedback, hourly).
const (
	AskFeedbackSnapshotRetention = 90 * 24 * time.Hour
	AskFeedbackRetention         = 365 * 24 * time.Hour
)

// Feedback categories a person picks ("What was wrong").
var AskFeedbackCategories = []string{"wrong", "misunderstood", "incomplete", "slow", "wrong_data", "formatting", "other"}

// Implicit signal categories.
const (
	AskSignalRephrased = "rephrased"  // the same question asked again within two turns
	AskSignalNotFound  = "not_found"  // the answer says it could not understand or find something, or a refusal
	AskSignalToolError = "tool_error" // a tool the model called failed
	AskSignalStopped   = "stopped"    // the person pressed Stop before the answer ended
	AskSignalAbandoned = "abandoned"  // see DetectAskAbandoned
)

// AskFeedbackStatuses are the review states.
var AskFeedbackStatuses = []string{"new", "triaged", "fixed", "wontfix"}

// AskFeedback is one feedback row as the operator's review sees it.
type AskFeedback struct {
	ID              int64           `json:"id"`
	WorkspaceID     int64           `json:"workspace_id"`
	UserID          *int64          `json:"user_id"`
	ConversationID  *int64          `json:"conversation_id"`
	MessageID       *int64          `json:"message_id"`
	Kind            string          `json:"kind"`
	Rating          *string         `json:"rating"`
	Category        string          `json:"category"`
	Scope           string          `json:"scope"`
	Text            string          `json:"text"`
	Consent         bool            `json:"consent"`
	Snapshot        json.RawMessage `json:"snapshot,omitempty"`
	PromptVersion   string          `json:"prompt_version"`
	Model           string          `json:"model"`
	UsageCallID     *int64          `json:"usage_call_id"`
	PagePath        string          `json:"page_path"`
	Viewport        string          `json:"viewport"`
	Status          string          `json:"status"`
	ResolutionNotes string          `json:"resolution_notes"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// AskSnapshotMessage is one message kept in a feedback snapshot: its
// visible text only.
type AskSnapshotMessage struct {
	Seq  int    `json:"seq"`
	Role string `json:"role"`
	Text string `json:"text"`
}

// AskFeedbackInput is explicit feedback from the person who asked.
// Snapshot is already cleaned by the caller; it is kept only with Consent.
type AskFeedbackInput struct {
	UserID         int64
	ConversationID int64
	// Seq is the answer's sequence number (0: the whole conversation, or
	// the bot's look and controls).
	Seq           int
	Rating        string // up, down or ""
	Category      string
	Scope         string // answer, chat or ui
	Text          string
	Consent       bool
	Snapshot      []AskSnapshotMessage
	PromptVersion string
	Model         string
	UsageCallID   *int64
	PagePath      string
	Viewport      string
}

func validIn(v string, set []string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

// Validate reports an input the table would refuse.
func (in *AskFeedbackInput) Validate() error {
	switch in.Rating {
	case "", "up", "down":
	default:
		return fmt.Errorf("rating %q: %w", in.Rating, ErrInvalid)
	}
	if in.Category != "" && !validIn(in.Category, AskFeedbackCategories) {
		return fmt.Errorf("category %q: %w", in.Category, ErrInvalid)
	}
	if in.Scope == "" {
		in.Scope = "answer"
	}
	if !validIn(in.Scope, []string{"answer", "chat", "ui"}) {
		return fmt.Errorf("scope %q: %w", in.Scope, ErrInvalid)
	}
	if in.Scope == "answer" && in.Seq < 1 {
		return fmt.Errorf("feedback on an answer names it: %w", ErrInvalid)
	}
	if in.Rating == "" && in.Category == "" && strings.TrimSpace(in.Text) == "" {
		return fmt.Errorf("say what was wrong, or rate the answer: %w", ErrInvalid)
	}
	if len([]rune(in.Text)) > 2000 {
		return fmt.Errorf("text over 2000 characters: %w", ErrInvalid)
	}
	if len(in.PagePath) > 300 || len(in.Viewport) > 20 {
		return fmt.Errorf("page or viewport too long: %w", ErrInvalid)
	}
	return nil
}

const askFeedbackCols = `id, workspace_id, user_id, conversation_id, message_id, kind, rating, category, scope, text, consent, snapshot,
	prompt_version, model, usage_call_id, page_path, viewport, status, resolution_notes, created_at, updated_at`

func scanAskFeedback(row pgx.Row) (*AskFeedback, error) {
	var f AskFeedback
	var snap []byte
	err := row.Scan(&f.ID, &f.WorkspaceID, &f.UserID, &f.ConversationID, &f.MessageID, &f.Kind, &f.Rating, &f.Category, &f.Scope, &f.Text,
		&f.Consent, &snap, &f.PromptVersion, &f.Model, &f.UsageCallID, &f.PagePath, &f.Viewport, &f.Status, &f.ResolutionNotes,
		&f.CreatedAt, &f.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if len(snap) > 0 {
		f.Snapshot = snap
	}
	return &f, err
}

// AddAskFeedback records explicit feedback on user's own conversation in
// the workspace in ctx; another person's conversation is ErrNotFound, and
// so is an answer (Seq) that is not one of its assistant messages.
func (s *Store) AddAskFeedback(ctx context.Context, in AskFeedbackInput) (*AskFeedback, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	if _, err := s.AskConversation(ctx, in.UserID, in.ConversationID); err != nil {
		return nil, err
	}
	ws, err := askWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	var msgID *int64
	if in.Seq > 0 {
		// The answer's own model and prompt version, and the model call
		// that produced it (the latest answer call of the conversation up to
		// the answer's time; the call log has no message id).
		var id int64
		var model, pv string
		var call *int64
		err := s.Pool.QueryRow(ctx, `SELECT m.id, m.model, m.prompt_version,
			(SELECT a.id FROM ask_api_calls a WHERE a.conversation_id = m.conversation_id AND a.kind = 'answer'
				AND a.created_at <= m.created_at + interval '5 seconds' ORDER BY a.id DESC LIMIT 1)
			FROM ask_messages m WHERE m.conversation_id = $1 AND m.seq = $2 AND m.role = 'assistant'`,
			in.ConversationID, in.Seq).Scan(&id, &model, &pv, &call)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		msgID = &id
		if in.Model == "" {
			in.Model = model
		}
		if in.PromptVersion == "" {
			in.PromptVersion = pv
		}
		if in.UsageCallID == nil {
			in.UsageCallID = call
		}
	}
	var snap any
	if in.Consent && len(in.Snapshot) > 0 {
		b, err := json.Marshal(in.Snapshot)
		if err != nil {
			return nil, err
		}
		snap = b
	}
	var rating any
	if in.Rating != "" {
		rating = in.Rating
	}
	return scanAskFeedback(s.Pool.QueryRow(ctx, `INSERT INTO ask_feedback (workspace_id, user_id, conversation_id, message_id, kind, rating,
		category, scope, text, consent, snapshot, prompt_version, model, usage_call_id, page_path, viewport)
		VALUES ($1, $2, $3, $4, 'explicit', $5, $6, $7, $8, $9, $10, left($11, 40), left($12, 100), $13, $14, $15)
		RETURNING `+askFeedbackCols, ws, in.UserID, in.ConversationID, msgID, rating, in.Category, in.Scope, strings.TrimSpace(in.Text),
		in.Consent, snap, in.PromptVersion, in.Model, in.UsageCallID, in.PagePath, in.Viewport))
}

// AskSignal is an implicit signal: metadata only.
type AskSignal struct {
	UserID         int64
	ConversationID int64
	// Seq is the message it is about (0: the conversation).
	Seq           int
	Category      string
	PromptVersion string
	Model         string
}

// AddAskSignal records an implicit signal in the workspace in ctx, once per
// conversation, message and category. It returns whether a row was added.
func (s *Store) AddAskSignal(ctx context.Context, sig AskSignal) (bool, error) {
	if !validIn(sig.Category, []string{AskSignalRephrased, AskSignalNotFound, AskSignalToolError, AskSignalStopped, AskSignalAbandoned}) {
		return false, fmt.Errorf("signal %q: %w", sig.Category, ErrInvalid)
	}
	ws, err := askWorkspace(ctx)
	if err != nil {
		return false, err
	}
	var msgID *int64
	if sig.Seq > 0 {
		var id int64
		err := s.Pool.QueryRow(ctx, `SELECT id FROM ask_messages WHERE conversation_id = $1 AND seq = $2`, sig.ConversationID, sig.Seq).Scan(&id)
		if err == nil {
			msgID = &id
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return false, err
		}
	}
	tag, err := s.Pool.Exec(ctx, `INSERT INTO ask_feedback (workspace_id, user_id, conversation_id, message_id, kind, category, scope, prompt_version, model)
		SELECT $1, $2, c.id, $4, 'implicit', $5, CASE WHEN $4::bigint IS NULL THEN 'chat' ELSE 'answer' END, left($6, 40), left($7, 100)
		FROM ask_conversations c WHERE c.id = $3 AND c.user_id = $2
		ON CONFLICT (conversation_id, COALESCE(message_id, 0), category) WHERE kind = 'implicit' DO NOTHING`,
		ws, sig.UserID, sig.ConversationID, msgID, sig.Category, sig.PromptVersion, sig.Model)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// AskFeedbackFilter selects feedback for review. Before pages backwards by
// id (newest first).
type AskFeedbackFilter struct {
	Status        string
	Kind          string
	Rating        string
	Category      string
	WorkspaceID   int64
	Since         *time.Time
	PromptVersion string
	Before        int64
	Limit         int
}

// ListAskFeedback returns feedback across every organisation, newest
// first, for the installation's operators (system scope).
func (s *Store) ListAskFeedback(ctx context.Context, f AskFeedbackFilter) ([]AskFeedback, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	q := `SELECT ` + askFeedbackCols + ` FROM ask_feedback WHERE true`
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		q += fmt.Sprintf(" AND "+cond, len(args))
	}
	if f.Status != "" {
		add("status = $%d", f.Status)
	}
	if f.Kind != "" {
		add("kind = $%d", f.Kind)
	}
	if f.Rating != "" {
		add("rating = $%d", f.Rating)
	}
	if f.Category != "" {
		add("category = $%d", f.Category)
	}
	if f.WorkspaceID > 0 {
		add("workspace_id = $%d", f.WorkspaceID)
	}
	if f.Since != nil {
		add("created_at >= $%d", *f.Since)
	}
	if f.PromptVersion != "" {
		add("prompt_version = $%d", f.PromptVersion)
	}
	if f.Before > 0 {
		add("id < $%d", f.Before)
	}
	args = append(args, f.Limit)
	q += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(args))
	rows, err := s.Pool.Query(tenant.System(ctx), q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AskFeedback{}
	for rows.Next() {
		fb, err := scanAskFeedback(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *fb)
	}
	return out, rows.Err()
}

// GetAskFeedback returns one feedback row (system scope).
func (s *Store) GetAskFeedback(ctx context.Context, id int64) (*AskFeedback, error) {
	return scanAskFeedback(s.Pool.QueryRow(tenant.System(ctx), `SELECT `+askFeedbackCols+` FROM ask_feedback WHERE id = $1`, id))
}

// ReviewAskFeedback sets a row's status and resolution notes (nil: keep).
func (s *Store) ReviewAskFeedback(ctx context.Context, id int64, status, notes *string) (*AskFeedback, error) {
	if status != nil && !validIn(*status, AskFeedbackStatuses) {
		return nil, fmt.Errorf("status %q: %w", *status, ErrInvalid)
	}
	if notes != nil && len([]rune(*notes)) > 4000 {
		return nil, fmt.Errorf("notes over 4000 characters: %w", ErrInvalid)
	}
	return scanAskFeedback(s.Pool.QueryRow(tenant.System(ctx), `UPDATE ask_feedback SET status = COALESCE($2, status),
		resolution_notes = COALESCE($3, resolution_notes), updated_at = now() WHERE id = $1 RETURNING `+askFeedbackCols, id, status, notes))
}

// PurgeAskFeedback removes snapshots older than AskFeedbackSnapshotRetention
// and rows older than AskFeedbackRetention, in every organisation.
func (s *Store) PurgeAskFeedback(ctx context.Context) (snapshots, rows int64, err error) {
	ctx = tenant.System(ctx)
	tag, err := s.Pool.Exec(ctx, `UPDATE ask_feedback SET snapshot = NULL WHERE snapshot IS NOT NULL
		AND created_at < now() - make_interval(secs => $1)`, AskFeedbackSnapshotRetention.Seconds())
	if err != nil {
		return 0, 0, err
	}
	snapshots = tag.RowsAffected()
	tag, err = s.Pool.Exec(ctx, `DELETE FROM ask_feedback WHERE created_at < now() - make_interval(secs => $1)`, AskFeedbackRetention.Seconds())
	if err != nil {
		return snapshots, 0, err
	}
	return snapshots, tag.RowsAffected(), nil
}

// AbandonedAfter is how long a conversation must be quiet after a failed
// answer to count as abandoned; AbandonedWindow bounds how far back the
// hourly check looks, so each conversation is judged once.
const (
	AbandonedAfter  = 30 * time.Minute
	AbandonedWindow = 6 * time.Hour
)

// DetectAskAbandoned records an "abandoned" signal for conversations whose
// last answer failed and that nobody came back to: the last message is the
// person's question with no answer after it (the answer was stopped or
// ended in an error), or an answer that was a refusal, was cut short
// (max_tokens), stopped between tool calls (tool_use), or has a "stopped"
// or "not_found" signal; and the
// conversation has been quiet for AbandonedAfter (but not longer than
// AbandonedWindow). It runs in system scope and returns the rows added.
func (s *Store) DetectAskAbandoned(ctx context.Context) (int64, error) {
	tag, err := s.Pool.Exec(tenant.System(ctx), `INSERT INTO ask_feedback (workspace_id, user_id, conversation_id, message_id, kind, category, scope, model)
		SELECT c.workspace_id, c.user_id, c.id, m.id, 'implicit', 'abandoned', 'chat', m.model
		FROM ask_conversations c
		JOIN LATERAL (SELECT id, role, stop_reason, visible_text, model FROM ask_messages
			WHERE conversation_id = c.id AND (role = 'assistant' OR visible_text <> '') ORDER BY seq DESC LIMIT 1) m ON true
		WHERE c.updated_at < now() - make_interval(secs => $1) AND c.updated_at >= now() - make_interval(secs => $2)
		AND (
			m.role = 'user'
			OR m.stop_reason IN ('refusal', 'max_tokens', 'tool_use')
			OR EXISTS (SELECT 1 FROM ask_feedback f WHERE f.conversation_id = c.id AND f.message_id = m.id
				AND f.kind = 'implicit' AND f.category IN ('stopped', 'not_found'))
		)
		ON CONFLICT (conversation_id, COALESCE(message_id, 0), category) WHERE kind = 'implicit' DO NOTHING`,
		AbandonedAfter.Seconds(), AbandonedWindow.Seconds())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// --- review tokens

// AskFeedbackReviewTokenKind is the prefix of a feedback review token's
// secret.
const AskFeedbackReviewTokenKind = "stkfr"

// AskFeedbackReviewToken is a read-only token for reviewing feedback.
type AskFeedbackReviewToken struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedBy  *int64     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

const askReviewTokenCols = `id, name, prefix, created_by, created_at, expires_at, last_used_at, revoked_at`

func scanAskReviewToken(row pgx.Row) (*AskFeedbackReviewToken, error) {
	var t AskFeedbackReviewToken
	err := row.Scan(&t.ID, &t.Name, &t.Prefix, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &t, err
}

// CreateAskFeedbackReviewToken makes a review token and returns its secret,
// shown once. ttl 0: no expiry.
func (s *Store) CreateAskFeedbackReviewToken(ctx context.Context, name string, createdBy int64, ttl time.Duration) (*AskFeedbackReviewToken, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return nil, "", fmt.Errorf("name: %w", ErrInvalid)
	}
	secret, prefix, err := auth.NewToken(AskFeedbackReviewTokenKind)
	if err != nil {
		return nil, "", err
	}
	var exp *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		exp = &t
	}
	t, err := scanAskReviewToken(s.Pool.QueryRow(tenant.System(ctx), `INSERT INTO ask_feedback_review_tokens (name, prefix, token_hash, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5) RETURNING `+askReviewTokenCols, name, prefix, auth.HashToken(secret), createdBy, exp))
	if err != nil {
		return nil, "", err
	}
	return t, secret, nil
}

// ListAskFeedbackReviewTokens returns every review token, newest first.
func (s *Store) ListAskFeedbackReviewTokens(ctx context.Context) ([]AskFeedbackReviewToken, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT `+askReviewTokenCols+` FROM ask_feedback_review_tokens ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AskFeedbackReviewToken{}
	for rows.Next() {
		t, err := scanAskReviewToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// RevokeAskFeedbackReviewToken revokes token id.
func (s *Store) RevokeAskFeedbackReviewToken(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(tenant.System(ctx), `UPDATE ask_feedback_review_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// AskFeedbackReviewPrincipal returns the live review token with secret, and
// notes its use; ErrNotFound for an unknown, revoked or expired one.
func (s *Store) AskFeedbackReviewPrincipal(ctx context.Context, secret string) (*AskFeedbackReviewToken, error) {
	return scanAskReviewToken(s.Pool.QueryRow(tenant.System(ctx), `UPDATE ask_feedback_review_tokens SET last_used_at = now()
		WHERE token_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
		RETURNING `+askReviewTokenCols, auth.HashToken(secret)))
}
