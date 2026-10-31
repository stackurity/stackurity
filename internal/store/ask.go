package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Ask Stackurity, the in-app assistant (internal/ask), stores its
// conversations, its monthly usage and the spend held for model calls in
// flight here (migration 0067).
//
// Conversations are private to the person who asked. Every query that
// returns a conversation or its messages takes the person's user id and
// matches it: there is no query that returns another person's messages, so
// an organisation admin can delete conversations (DeleteAllAskConversations)
// but never read them.

// AskRetention is how long a conversation is kept after it was created.
const AskRetention = 30 * 24 * time.Hour

// askHoldTTL is how long a spend hold counts when its call never settles it.
const askHoldTTL = 10 * time.Minute

// AskSettings are the organisation's switch, limits and model.
type AskSettings struct {
	Enabled bool `json:"enabled"`
	// QuestionLimit is questions per QuestionPeriod: nil no limit, 0 not
	// included.
	QuestionLimit *int64 `json:"question_limit"`
	// QuestionPeriod is "month" (a calendar month, UTC) or "total" (an
	// allowance that never renews, for a trial).
	QuestionPeriod string `json:"question_period"`
	// SpendCapMicros is model spend a month, in millionths of a US dollar
	// (nil: no cap).
	SpendCapMicros *int64 `json:"spend_cap_micros"`
	// Model is the model for this organisation ("": the server's default).
	Model string `json:"model"`
}

// AskLimits are what an edition or an instance admin sets for an
// organisation: everything in AskSettings but the admin's switch.
type AskLimits struct {
	QuestionLimit  *int64
	QuestionPeriod string // month (the default) or total
	SpendCapMicros *int64
	Model          string
}

// AskSettings returns the settings of the workspace in ctx.
func (s *Store) AskSettings(ctx context.Context) (AskSettings, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return AskSettings{}, ErrNotFound
	}
	var a AskSettings
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT ask_enabled, ask_question_limit, ask_question_period, ask_spend_cap_micros, ask_model FROM workspaces WHERE id = $1`, ws).
		Scan(&a.Enabled, &a.QuestionLimit, &a.QuestionPeriod, &a.SpendCapMicros, &a.Model)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

// SetAskEnabled turns the assistant on or off for the workspace in ctx.
func (s *Store) SetAskEnabled(ctx context.Context, enabled bool) error {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return ErrNotFound
	}
	tag, err := s.Pool.Exec(tenant.System(ctx), `UPDATE workspaces SET ask_enabled = $2 WHERE id = $1`, ws, enabled)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetAskLimits sets workspace ws's limits and model.
func (s *Store) SetAskLimits(ctx context.Context, ws int64, l AskLimits) error {
	if l.QuestionLimit != nil && (*l.QuestionLimit < 0 || *l.QuestionLimit > 1_000_000_000) {
		return fmt.Errorf("question limit must be between 0 and 1000000000: %w", ErrInvalid)
	}
	if l.SpendCapMicros != nil && *l.SpendCapMicros < 0 {
		return fmt.Errorf("spend cap must not be negative: %w", ErrInvalid)
	}
	if !validAskModel(l.Model) {
		return fmt.Errorf("model %q is not a model id: %w", l.Model, ErrInvalid)
	}
	switch l.QuestionPeriod {
	case "":
		l.QuestionPeriod = "month"
	case "month", "total":
	default:
		return fmt.Errorf("question period %q: %w", l.QuestionPeriod, ErrInvalid)
	}
	tag, err := s.Pool.Exec(tenant.System(ctx), `UPDATE workspaces SET ask_question_limit = $2, ask_question_period = $3, ask_spend_cap_micros = $4, ask_model = $5 WHERE id = $1`,
		ws, l.QuestionLimit, l.QuestionPeriod, l.SpendCapMicros, l.Model)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func validAskModel(m string) bool {
	if len(m) > 100 {
		return false
	}
	for _, c := range m {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == ':' || c == '@' || c == '/' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

// --- conversations

// AskConversation is one conversation (without its messages).
type AskConversation struct {
	ID            int64     `json:"id"`
	UserID        int64     `json:"-"`
	ProjectID     *int64    `json:"project_id"`
	Model         string    `json:"model"`
	Title         string    `json:"title"`
	ContextTokens int64     `json:"context_tokens"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	// ExpiresAt is when housekeeping deletes it.
	ExpiresAt time.Time `json:"expires_at"`
}

// AskMessage is one message of a conversation.
type AskMessage struct {
	Seq  int    `json:"seq"`
	Role string `json:"role"` // user or assistant
	// Content is the message as sent to or received from the model.
	Content     json.RawMessage `json:"-"`
	VisibleText string          `json:"text"`
	Page        json.RawMessage `json:"page,omitempty"`
	Model       string          `json:"-"`
	StopReason  string          `json:"stop_reason,omitempty"`
	Usage       AskTokens       `json:"-"`
	CostMicros  int64           `json:"-"`
	RequestID   string          `json:"-"`
	CreatedAt   time.Time       `json:"created_at"`
}

// AskTokens are the tokens one model call used.
type AskTokens struct {
	Input      int64 `json:"input"`
	CacheWrite int64 `json:"cache_write"`
	CacheRead  int64 `json:"cache_read"`
	Output     int64 `json:"output"`
}

const askConversationCols = `id, user_id, project_id, model, title, context_tokens, created_at, updated_at`

func scanAskConversation(row pgx.Row) (*AskConversation, error) {
	var c AskConversation
	err := row.Scan(&c.ID, &c.UserID, &c.ProjectID, &c.Model, &c.Title, &c.ContextTokens, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	c.ExpiresAt = c.CreatedAt.Add(AskRetention)
	return &c, err
}

func askWorkspace(ctx context.Context) (int64, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return 0, ErrNotFound
	}
	return ws, nil
}

// CreateAskConversation starts a conversation of user's in the workspace in
// ctx. projectID is the project chosen in the switcher (nil: none).
func (s *Store) CreateAskConversation(ctx context.Context, userID int64, projectID *int64, model, title string) (*AskConversation, error) {
	ws, err := askWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	if model == "" || !validAskModel(model) {
		return nil, fmt.Errorf("model %q: %w", model, ErrInvalid)
	}
	return scanAskConversation(s.Pool.QueryRow(ctx, `INSERT INTO ask_conversations (workspace_id, user_id, project_id, model, title)
		VALUES ($1, $2, $3, $4, left($5, 200)) RETURNING `+askConversationCols, ws, userID, projectID, model, title))
}

// AskConversation returns user's conversation id; another person's is
// ErrNotFound.
func (s *Store) AskConversation(ctx context.Context, userID, id int64) (*AskConversation, error) {
	return scanAskConversation(s.Pool.QueryRow(ctx, `SELECT `+askConversationCols+` FROM ask_conversations WHERE id = $1 AND user_id = $2`, id, userID))
}

// ListAskConversations lists user's conversations, the latest first.
func (s *Store) ListAskConversations(ctx context.Context, userID int64, limit int) ([]AskConversation, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+askConversationCols+` FROM ask_conversations WHERE user_id = $1 ORDER BY updated_at DESC, id DESC LIMIT $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AskConversation{}
	for rows.Next() {
		c, err := scanAskConversation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// AskMessages returns the messages of user's conversation id, in order.
// Another person's conversation is ErrNotFound.
func (s *Store) AskMessages(ctx context.Context, userID, id int64) ([]AskMessage, error) {
	if _, err := s.AskConversation(ctx, userID, id); err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT m.seq, m.role, m.content, m.visible_text, m.page, m.model, m.stop_reason,
		m.input_tokens, m.cache_write_tokens, m.cache_read_tokens, m.output_tokens, m.cost_micros, m.request_id, m.created_at
		FROM ask_messages m JOIN ask_conversations c ON c.id = m.conversation_id
		WHERE m.conversation_id = $1 AND c.user_id = $2 ORDER BY m.seq`, id, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AskMessage{}
	for rows.Next() {
		var m AskMessage
		var page []byte
		if err := rows.Scan(&m.Seq, &m.Role, &m.Content, &m.VisibleText, &page, &m.Model, &m.StopReason,
			&m.Usage.Input, &m.Usage.CacheWrite, &m.Usage.CacheRead, &m.Usage.Output, &m.CostMicros, &m.RequestID, &m.CreatedAt); err != nil {
			return nil, err
		}
		if len(page) > 0 {
			m.Page = page
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AppendAskMessage adds m at the end of user's conversation id and returns
// its sequence number. Messages are never changed afterwards: the model
// gets the conversation back exactly as it was. contextTokens, when
// positive, records the prompt size of the call that produced m.
func (s *Store) AppendAskMessage(ctx context.Context, userID, id int64, m AskMessage, contextTokens int64) (int, error) {
	if m.Role != "user" && m.Role != "assistant" {
		return 0, fmt.Errorf("role %q: %w", m.Role, ErrInvalid)
	}
	if !json.Valid(m.Content) {
		return 0, fmt.Errorf("content is not JSON: %w", ErrInvalid)
	}
	var seq int
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var ws int64
		err := tx.QueryRow(ctx, `UPDATE ask_conversations SET updated_at = now(),
			context_tokens = CASE WHEN $3 > 0 THEN $3 ELSE context_tokens END
			WHERE id = $1 AND user_id = $2 RETURNING workspace_id`, id, userID, contextTokens).Scan(&ws)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var page any
		if len(m.Page) > 0 {
			page = m.Page
		}
		return tx.QueryRow(ctx, `INSERT INTO ask_messages (conversation_id, workspace_id, seq, role, content, visible_text, page, model, stop_reason,
			input_tokens, cache_write_tokens, cache_read_tokens, output_tokens, cost_micros, request_id)
			VALUES ($1, $2, (SELECT COALESCE(max(seq), 0) + 1 FROM ask_messages WHERE conversation_id = $1), $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, left($14, 200))
			RETURNING seq`, id, ws, m.Role, m.Content, m.VisibleText, page, m.Model, m.StopReason,
			m.Usage.Input, m.Usage.CacheWrite, m.Usage.CacheRead, m.Usage.Output, m.CostMicros, m.RequestID).Scan(&seq)
	})
	return seq, err
}

// DeleteAskConversation deletes user's conversation id with its messages.
func (s *Store) DeleteAskConversation(ctx context.Context, userID, id int64) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM ask_conversations WHERE id = $1 AND user_id = $2`, id, userID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// DeleteAskConversations deletes all of user's conversations in the
// workspace in ctx and says how many there were.
func (s *Store) DeleteAskConversations(ctx context.Context, userID int64) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM ask_conversations WHERE user_id = $1`, userID)
	return tag.RowsAffected(), err
}

// DeleteAllAskConversations deletes every conversation in the workspace in
// ctx, whoever had it (an organisation admin's choice), and says how many
// there were. Nothing about them is returned.
func (s *Store) DeleteAllAskConversations(ctx context.Context) (int64, error) {
	ws, err := askWorkspace(ctx)
	if err != nil {
		return 0, err
	}
	tag, err := s.Pool.Exec(ctx, `DELETE FROM ask_conversations WHERE workspace_id = $1`, ws)
	return tag.RowsAffected(), err
}

// PurgeAsk deletes conversations older than AskRetention, spend holds no
// call settled, and usage rows older than two years, in every workspace
// (system scope). It returns the conversations deleted.
func (s *Store) PurgeAsk(ctx context.Context) (int64, error) {
	ctx = tenant.System(ctx)
	tag, err := s.Pool.Exec(ctx, `DELETE FROM ask_conversations WHERE created_at < now() - make_interval(secs => $1)`, AskRetention.Seconds())
	if err != nil {
		return 0, err
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM ask_holds WHERE created_at < now() - make_interval(secs => $1)`, askHoldTTL.Seconds()); err != nil {
		return 0, err
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM ask_usage WHERE month < date_trunc('month', now() AT TIME ZONE 'UTC')::date - interval '24 months'`); err != nil {
		return 0, err
	}
	if _, err := s.Pool.Exec(ctx, `DELETE FROM ask_global_alerts WHERE month < date_trunc('month', now() AT TIME ZONE 'UTC')::date - interval '24 months'`); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// --- notice

// AcceptAskNotice records that user accepted notice version in the
// workspace in ctx.
func (s *Store) AcceptAskNotice(ctx context.Context, userID int64, version string) error {
	ws, err := askWorkspace(ctx)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO ask_notice_acceptances (workspace_id, user_id, version) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, ws, userID, version)
	return err
}

// AskNoticeAccepted reports whether user accepted notice version in the
// workspace in ctx.
func (s *Store) AskNoticeAccepted(ctx context.Context, userID int64, version string) (bool, error) {
	var ok bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ask_notice_acceptances WHERE user_id = $1 AND version = $2)`, userID, version).Scan(&ok)
	return ok, err
}

// --- usage, quota and spend

// AskUsage is an organisation's use in one month.
type AskUsage struct {
	Month      time.Time `json:"month"`
	Questions  int64     `json:"questions"`
	CostMicros int64     `json:"cost_micros"`
}

const askMonth = `date_trunc('month', now() AT TIME ZONE 'UTC')::date`

// AskUsageNow returns the workspace in ctx's use this month.
func (s *Store) AskUsageNow(ctx context.Context) (AskUsage, error) {
	ws, err := askWorkspace(ctx)
	if err != nil {
		return AskUsage{}, err
	}
	var u AskUsage
	err = s.Pool.QueryRow(tenant.System(ctx), `SELECT `+askMonth+`, COALESCE(sum(questions), 0), COALESCE(sum(cost_micros), 0)
		FROM ask_usage WHERE workspace_id = $1 AND month = `+askMonth, ws).Scan(&u.Month, &u.Questions, &u.CostMicros)
	return u, err
}

// AskGlobalSpend returns the spend of every organisation this month.
func (s *Store) AskGlobalSpend(ctx context.Context) (int64, error) {
	var n int64
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT COALESCE(sum(cost_micros), 0) FROM ask_usage WHERE month = `+askMonth).Scan(&n)
	return n, err
}

// ErrAskQuota is the monthly question limit reached.
var ErrAskQuota = errors.New("monthly question limit reached")

// AskQuestion is a question counted: the questions asked in its period,
// it included, and the month (UTC) it was counted in, which a refund
// takes it back from.
type AskQuestion struct {
	Used  int64
	Month time.Time
}

// askLockKey is a transaction-scoped advisory lock key for name and a
// workspace: a 64-bit hash of both, so no workspace id is truncated.
const askLockKey = `hashtextextended($1 || ':' || $2::bigint::text, 0)`

// CountAskQuestion counts a question against the workspace in ctx's
// question limit (nil: none) for period ("month" or "total"), or returns
// ErrAskQuota with nothing counted. Counts of one workspace are taken one
// at a time (a transaction-scoped advisory lock).
func (s *Store) CountAskQuestion(ctx context.Context, limit *int64, period string) (AskQuestion, error) {
	var q AskQuestion
	ws, err := askWorkspace(ctx)
	if err != nil {
		return q, err
	}
	if limit != nil && *limit <= 0 {
		return q, ErrAskQuota
	}
	if period != "total" {
		period = "month"
	}
	sys := tenant.System(ctx)
	err = pgx.BeginTxFunc(sys, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(sys, `SELECT pg_advisory_xact_lock(`+askLockKey+`)`, "stackurity-ask-questions", ws); err != nil {
			return err
		}
		var used int64
		count := `SELECT COALESCE(sum(questions), 0) FROM ask_usage WHERE workspace_id = $1 AND month = ` + askMonth
		if period == "total" {
			count = `SELECT COALESCE(sum(questions), 0) FROM ask_usage WHERE workspace_id = $1`
		}
		if err := tx.QueryRow(sys, count, ws).Scan(&used); err != nil {
			return err
		}
		if limit != nil && used >= *limit {
			return ErrAskQuota
		}
		if err := tx.QueryRow(sys, `INSERT INTO ask_usage AS u (workspace_id, month, questions) VALUES ($1, `+askMonth+`, 1)
			ON CONFLICT (workspace_id, month) DO UPDATE SET questions = u.questions + 1 RETURNING month`, ws).Scan(&q.Month); err != nil {
			return err
		}
		q.Used = used + 1
		return nil
	})
	if err != nil {
		return AskQuestion{}, err
	}
	return q, nil
}

// RefundAskQuestion takes back question q, which used nothing (the model
// was never reached), from the month it was counted in, even when a new
// month has begun since.
func (s *Store) RefundAskQuestion(ctx context.Context, q AskQuestion) error {
	ws, err := askWorkspace(ctx)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(tenant.System(ctx), `UPDATE ask_usage SET questions = questions - 1 WHERE workspace_id = $1 AND month = $2 AND questions > 0`,
		ws, q.Month)
	return err
}

// AskSpendCapError says which cap a model call would pass.
type AskSpendCapError struct {
	// Scope is "workspace" (the organisation's cap) or "global" (the
	// installation's).
	Scope string
	Cap   int64
	Spent int64
}

func (e *AskSpendCapError) Error() string {
	return fmt.Sprintf("the %s monthly spend cap for the assistant is reached", e.Scope)
}

// ErrAskSpendCap matches an *AskSpendCapError with errors.Is.
var ErrAskSpendCap = errors.New("assistant spend cap reached")

func (e *AskSpendCapError) Is(target error) bool { return target == ErrAskSpendCap }

// AskHold is spend held for one model call.
type AskHold struct {
	ID         int64
	Workspace  int64
	Micros     int64
	workspaceC *int64
	globalC    *int64
}

// HoldAskSpend holds micros for a model call of the workspace in ctx, or
// returns an *AskSpendCapError when spend this month plus every hold in
// flight plus this one would pass the organisation's cap (wsCap) or the
// installation's (globalCap); nil caps are no cap. Holds are taken one at
// a time across the installation (a transaction-scoped advisory lock), so
// calls made at once never pass a cap together. SettleAskSpend ends the
// hold.
func (s *Store) HoldAskSpend(ctx context.Context, micros int64, wsCap, globalCap *int64) (*AskHold, error) {
	ws, err := askWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	if micros < 0 {
		return nil, fmt.Errorf("hold must not be negative: %w", ErrInvalid)
	}
	sys := tenant.System(ctx)
	h := &AskHold{Workspace: ws, Micros: micros, workspaceC: wsCap, globalC: globalCap}
	err = pgx.BeginTxFunc(sys, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(sys, `SELECT pg_advisory_xact_lock(hashtextextended('stackurity-ask-spend', 0))`); err != nil {
			return err
		}
		var wsSpent, wsHeld, allSpent, allHeld int64
		if err := tx.QueryRow(sys, `SELECT
			COALESCE((SELECT cost_micros FROM ask_usage WHERE workspace_id = $1 AND month = `+askMonth+`), 0),
			COALESCE((SELECT sum(micros) FROM ask_holds WHERE workspace_id = $1 AND created_at > now() - make_interval(secs => $2)), 0),
			COALESCE((SELECT sum(cost_micros) FROM ask_usage WHERE month = `+askMonth+`), 0),
			COALESCE((SELECT sum(micros) FROM ask_holds WHERE created_at > now() - make_interval(secs => $2)), 0)`,
			ws, askHoldTTL.Seconds()).Scan(&wsSpent, &wsHeld, &allSpent, &allHeld); err != nil {
			return err
		}
		if wsCap != nil && wsSpent+wsHeld+micros > *wsCap {
			return &AskSpendCapError{Scope: "workspace", Cap: *wsCap, Spent: wsSpent}
		}
		if globalCap != nil && allSpent+allHeld+micros > *globalCap {
			return &AskSpendCapError{Scope: "global", Cap: *globalCap, Spent: allSpent}
		}
		return tx.QueryRow(sys, `INSERT INTO ask_holds (workspace_id, micros) VALUES ($1, $2) RETURNING id`, ws, micros).Scan(&h.ID)
	})
	if err != nil {
		return nil, err
	}
	return h, nil
}

// AskSpendLevel is spend after a call settled, against the caps the hold
// was taken under (nil: no cap).
type AskSpendLevel struct {
	WorkspaceSpent int64
	WorkspaceCap   *int64
	GlobalSpent    int64
	GlobalCap      *int64
}

// SettleAskSpend ends hold h and adds the call's actual cost to its
// workspace's spend this month. It returns the spend after it, for alerts.
func (s *Store) SettleAskSpend(ctx context.Context, h *AskHold, actual int64) (AskSpendLevel, error) {
	lvl := AskSpendLevel{WorkspaceCap: h.workspaceC, GlobalCap: h.globalC}
	if actual < 0 {
		actual = 0
	}
	sys := tenant.System(ctx)
	err := pgx.BeginTxFunc(sys, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(sys, `DELETE FROM ask_holds WHERE id = $1`, h.ID); err != nil {
			return err
		}
		if err := tx.QueryRow(sys, `INSERT INTO ask_usage AS u (workspace_id, month, cost_micros) VALUES ($1, `+askMonth+`, $2)
			ON CONFLICT (workspace_id, month) DO UPDATE SET cost_micros = u.cost_micros + $2 RETURNING cost_micros`, h.Workspace, actual).Scan(&lvl.WorkspaceSpent); err != nil {
			return err
		}
		return tx.QueryRow(sys, `SELECT COALESCE(sum(cost_micros), 0) FROM ask_usage WHERE month = `+askMonth).Scan(&lvl.GlobalSpent)
	})
	return lvl, err
}

// MarkAskAlert records that the alert for level (80 or 100 per cent) of a
// cap was sent this month and reports whether this is the first time:
// scope "workspace" for the workspace in ctx, "global" for the
// installation.
func (s *Store) MarkAskAlert(ctx context.Context, scope string, level int) (bool, error) {
	if level != 80 && level != 100 {
		return false, fmt.Errorf("alert level %d: %w", level, ErrInvalid)
	}
	sys := tenant.System(ctx)
	switch scope {
	case "global":
		tag, err := s.Pool.Exec(sys, `INSERT INTO ask_global_alerts (month, level) VALUES (`+askMonth+`, $1) ON CONFLICT DO NOTHING`, level)
		return tag.RowsAffected() == 1, err
	case "workspace":
		ws, err := askWorkspace(ctx)
		if err != nil {
			return false, err
		}
		col := "alerted_80"
		if level == 100 {
			col = "alerted_100"
		}
		tag, err := s.Pool.Exec(sys, `INSERT INTO ask_usage AS u (workspace_id, month, `+col+`) VALUES ($1, `+askMonth+`, now())
			ON CONFLICT (workspace_id, month) DO UPDATE SET `+col+` = now() WHERE u.`+col+` IS NULL`, ws)
		return tag.RowsAffected() == 1, err
	}
	return false, fmt.Errorf("alert scope %q: %w", scope, ErrInvalid)
}
