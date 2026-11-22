package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Ask Stackurity keeps one row per model call (ask_api_calls, migration
// 0088): tokens, cost, latency, tools and how the call ended. Never the
// question, the answer, tool results or a summary. Rows are kept
// AskCallRetention, then folded into daily totals (ask_api_calls_daily),
// kept AskCallDailyRetention.

// AskCallRetention is how long a detailed call row is kept.
const AskCallRetention = 90 * 24 * time.Hour

// AskCallDailyRetention is how long the daily totals are kept.
const AskCallDailyRetention = 2 * 365 * 24 * time.Hour

// AskAPICall is one model call, metadata only.
type AskAPICall struct {
	ID               int64    `json:"id"`
	WorkspaceID      int64    `json:"workspace_id"`
	UserID           *int64   `json:"user_id"`
	ConversationID   *int64   `json:"conversation_id"`
	Kind             string   `json:"kind"` // answer, summary or triage
	Model            string   `json:"model"`
	PromptVersion    string   `json:"prompt_version"`
	InputTokens      int64    `json:"input_tokens"`
	OutputTokens     int64    `json:"output_tokens"`
	CacheReadTokens  int64    `json:"cache_read_tokens"`
	CacheWriteTokens int64    `json:"cache_write_tokens"`
	CostMicros       int64    `json:"cost_micros"`
	LatencyMS        int64    `json:"latency_ms"`
	ToolCalls        int      `json:"tool_calls"`
	ToolNames        []string `json:"tool_names"`
	HistoryTurnsSent int      `json:"history_turns_sent"`
	SummaryUsed      bool     `json:"summary_used"`
	StopReason       string   `json:"stop_reason"`
	ErrorCode        string   `json:"error_code"`
	RequestID        string   `json:"request_id"`
	// StepUpReason is why this answer was moved to a stronger model
	// ("": it was not; internal/ask/tier.go), and SteppedFrom the model
	// it moved from.
	StepUpReason string `json:"step_up_reason"`
	SteppedFrom  string `json:"stepped_from"`
	// IncompleteReason says why an answer call ended without a full
	// answer ("": it did not; one of AskIncompleteReasons), and
	// RefusalCategory is the provider's category for a refusal.
	IncompleteReason string    `json:"incomplete_reason"`
	RefusalCategory  string    `json:"refusal_category"`
	CreatedAt        time.Time `json:"created_at"`
}

// Why an answer was refused or left incomplete (ask_api_calls.incomplete_reason).
const (
	AskIncompleteRefusal      = "refusal"       // the model declined (stop reason refusal)
	AskIncompleteCannotAnswer = "cannot_answer" // the answer says it could not find or answer something
	AskIncompleteToolError    = "tool_error"    // a lookup failed and the answer was given without it
	AskIncompleteMaxTokens    = "max_tokens"    // the answer was cut short
	AskIncompleteToolBudget   = "tool_budget"   // the question used up its lookups
	AskIncompleteTooLong      = "too_long"      // the conversation outgrew its budget
)

// AskIncompleteReasons are the values incomplete_reason may take, besides "".
var AskIncompleteReasons = []string{AskIncompleteRefusal, AskIncompleteCannotAnswer, AskIncompleteToolError,
	AskIncompleteMaxTokens, AskIncompleteToolBudget, AskIncompleteTooLong}

func validIncomplete(reason string) bool {
	return reason == "" || validIn(reason, AskIncompleteReasons)
}

// RecordAskAPICall stores c in the workspace in ctx and returns its id.
func (s *Store) RecordAskAPICall(ctx context.Context, c AskAPICall) (int64, error) {
	ws, err := askWorkspace(ctx)
	if err != nil {
		return 0, err
	}
	if c.Kind != "answer" && c.Kind != "summary" && c.Kind != "triage" {
		return 0, fmt.Errorf("kind %q: %w", c.Kind, ErrInvalid)
	}
	if len(c.ToolNames) > 64 {
		c.ToolNames = c.ToolNames[:64]
	}
	if c.ToolNames == nil {
		c.ToolNames = []string{}
	}
	if !validIncomplete(c.IncompleteReason) {
		return 0, fmt.Errorf("incomplete reason %q: %w", c.IncompleteReason, ErrInvalid)
	}
	var id int64
	err = s.Pool.QueryRow(ctx, `INSERT INTO ask_api_calls (workspace_id, user_id, conversation_id, kind, model, prompt_version,
		input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, cost_micros, latency_ms, tool_calls, tool_names,
		history_turns_sent, summary_used, stop_reason, error_code, request_id, step_up_reason, stepped_from, incomplete_reason, refusal_category)
		VALUES ($1, $2, $3, $4, left($5, 100), left($6, 40), $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, left($17, 40), left($18, 40), left($19, 200),
		left($20, 40), left($21, 100), $22, left($23, 40))
		RETURNING id`,
		ws, c.UserID, c.ConversationID, c.Kind, c.Model, c.PromptVersion,
		max(c.InputTokens, 0), max(c.OutputTokens, 0), max(c.CacheReadTokens, 0), max(c.CacheWriteTokens, 0), max(c.CostMicros, 0),
		min(max(c.LatencyMS, 0), 1<<31-1), max(c.ToolCalls, 0), c.ToolNames, max(c.HistoryTurnsSent, 0), c.SummaryUsed,
		c.StopReason, c.ErrorCode, c.RequestID, c.StepUpReason, c.SteppedFrom, c.IncompleteReason, c.RefusalCategory).Scan(&id)
	return id, err
}

// SetAskAPICallIncomplete records, on the call id already stored, that its
// answer was left incomplete: the question used up its lookups, or the
// conversation its budget, which is known only after the call. It never
// clears a reason.
func (s *Store) SetAskAPICallIncomplete(ctx context.Context, id int64, reason string) error {
	if reason == "" || !validIncomplete(reason) {
		return fmt.Errorf("incomplete reason %q: %w", reason, ErrInvalid)
	}
	_, err := s.Pool.Exec(ctx, `UPDATE ask_api_calls SET incomplete_reason = $2 WHERE id = $1`, id, reason)
	return err
}

// AskCallFilter narrows ListAskAPICalls.
type AskCallFilter struct {
	Since, Until time.Time // zero: no bound
	Limit        int       // default 1000, at most 10000
	BeforeID     int64     // page: rows with a smaller id
}

const askCallCols = `id, workspace_id, user_id, conversation_id, kind, model, prompt_version, input_tokens, output_tokens,
	cache_read_tokens, cache_write_tokens, cost_micros, latency_ms, tool_calls, tool_names, history_turns_sent, summary_used,
	stop_reason, error_code, request_id, step_up_reason, stepped_from, incomplete_reason, refusal_category, created_at`

// ListAskAPICalls lists call rows, newest first: the workspace in ctx's,
// or every workspace's when ctx is in system scope.
func (s *Store) ListAskAPICalls(ctx context.Context, f AskCallFilter) ([]AskAPICall, error) {
	if f.Limit <= 0 {
		f.Limit = 1000
	}
	f.Limit = min(f.Limit, 10000)
	var since, until, before any
	if !f.Since.IsZero() {
		since = f.Since
	}
	if !f.Until.IsZero() {
		until = f.Until
	}
	if f.BeforeID > 0 {
		before = f.BeforeID
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+askCallCols+` FROM ask_api_calls
		WHERE ($1::timestamptz IS NULL OR created_at >= $1) AND ($2::timestamptz IS NULL OR created_at < $2)
		AND ($3::bigint IS NULL OR id < $3)
		ORDER BY id DESC LIMIT $4`, since, until, before, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AskAPICall{}
	for rows.Next() {
		var c AskAPICall
		if err := rows.Scan(&c.ID, &c.WorkspaceID, &c.UserID, &c.ConversationID, &c.Kind, &c.Model, &c.PromptVersion,
			&c.InputTokens, &c.OutputTokens, &c.CacheReadTokens, &c.CacheWriteTokens, &c.CostMicros, &c.LatencyMS,
			&c.ToolCalls, &c.ToolNames, &c.HistoryTurnsSent, &c.SummaryUsed, &c.StopReason, &c.ErrorCode, &c.RequestID, &c.StepUpReason, &c.SteppedFrom,
			&c.IncompleteReason, &c.RefusalCategory, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AskConversationTotals returns how many questions user's conversation id
// has had and what its model calls cost (answers and summaries), for the
// "this chat is getting long" prompt.
func (s *Store) AskConversationTotals(ctx context.Context, userID, id int64) (questions int, costMicros int64, err error) {
	err = s.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM ask_messages m WHERE m.conversation_id = c.id AND m.role = 'user' AND m.visible_text <> ''),
		(SELECT COALESCE(sum(a.cost_micros), 0) FROM ask_api_calls a WHERE a.conversation_id = c.id)
		FROM ask_conversations c WHERE c.id = $1 AND c.user_id = $2`, id, userID).Scan(&questions, &costMicros)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, ErrNotFound
	}
	return questions, costMicros, err
}

// SetAskSummary records that user's conversation id is summarised up to
// message seq through. The summary only moves forward.
func (s *Store) SetAskSummary(ctx context.Context, userID, id int64, summary string, through int) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE ask_conversations SET summary = left($3, 16000), summary_through = $4
		WHERE id = $1 AND user_id = $2 AND summary_through <= $4`, id, userID, summary, through)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// RollUpAskAPICalls folds call rows into daily totals and deletes what is
// past its retention, in every workspace: daily totals are (re)computed
// for each complete day (UTC) that still has detailed rows since the last
// day already rolled up, detailed rows older than AskCallRetention go
// (their days are rolled up first), and daily rows older than
// AskCallDailyRetention go. It is idempotent: housekeeping runs it.
func (s *Store) RollUpAskAPICalls(ctx context.Context, now time.Time) (deleted, deletedDaily int64, err error) {
	sys := tenant.System(ctx)
	today := now.UTC().Truncate(24 * time.Hour)
	cutoff := now.Add(-AskCallRetention)
	const agg = `SELECT workspace_id, (created_at AT TIME ZONE 'UTC')::date AS day, model, kind,
		count(*), count(*) FILTER (WHERE error_code <> ''), sum(input_tokens), sum(output_tokens), sum(cache_read_tokens),
		sum(cache_write_tokens), sum(cost_micros), sum(latency_ms), sum(tool_calls), count(*) FILTER (WHERE summary_used),
		count(*) FILTER (WHERE step_up_reason <> ''), count(*) FILTER (WHERE incomplete_reason = 'refusal'),
		count(*) FILTER (WHERE incomplete_reason <> '')
		FROM ask_api_calls WHERE %s GROUP BY 1, 2, 3, 4`
	err = pgx.BeginTxFunc(sys, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		// Serialise with another replica's run.
		if _, err := tx.Exec(sys, `SELECT pg_advisory_xact_lock(hashtextextended('ask_api_calls_rollup', 0))`); err != nil {
			return err
		}
		// Complete days not rolled up yet (or still changing): replace.
		if _, err := tx.Exec(sys, `INSERT INTO ask_api_calls_daily (workspace_id, day, model, kind, calls, errors, input_tokens,
			output_tokens, cache_read_tokens, cache_write_tokens, cost_micros, latency_ms, tool_calls, summaries_used, step_ups,
			refusals, incomplete) `+
			fmt.Sprintf(agg, `created_at < $1 AND created_at >= COALESCE((SELECT max(day) FROM ask_api_calls_daily) - 1, '-infinity'::date)`)+`
			ON CONFLICT (workspace_id, day, model, kind) DO UPDATE SET calls = EXCLUDED.calls, errors = EXCLUDED.errors,
			input_tokens = EXCLUDED.input_tokens, output_tokens = EXCLUDED.output_tokens, cache_read_tokens = EXCLUDED.cache_read_tokens,
			cache_write_tokens = EXCLUDED.cache_write_tokens, cost_micros = EXCLUDED.cost_micros, latency_ms = EXCLUDED.latency_ms,
			tool_calls = EXCLUDED.tool_calls, summaries_used = EXCLUDED.summaries_used, step_ups = EXCLUDED.step_ups,
			refusals = EXCLUDED.refusals, incomplete = EXCLUDED.incomplete`, today); err != nil {
			return err
		}
		// Days about to lose their detailed rows that were never rolled up
		// (the job did not run for a long time): keep what is there.
		if _, err := tx.Exec(sys, `INSERT INTO ask_api_calls_daily (workspace_id, day, model, kind, calls, errors, input_tokens,
			output_tokens, cache_read_tokens, cache_write_tokens, cost_micros, latency_ms, tool_calls, summaries_used, step_ups,
			refusals, incomplete) `+
			fmt.Sprintf(agg, `created_at < $1`)+` ON CONFLICT DO NOTHING`, cutoff); err != nil {
			return err
		}
		tag, err := tx.Exec(sys, `DELETE FROM ask_api_calls WHERE created_at < $1`, cutoff)
		if err != nil {
			return err
		}
		deleted = tag.RowsAffected()
		tag, err = tx.Exec(sys, `DELETE FROM ask_api_calls_daily WHERE day < ($1::timestamptz AT TIME ZONE 'UTC')::date`, now.Add(-AskCallDailyRetention))
		if err != nil {
			return err
		}
		deletedDaily = tag.RowsAffected()
		return nil
	})
	return deleted, deletedDaily, err
}

// SetAskConversationModel moves user's conversation id to model, for the
// rest of the conversation (a step up to a stronger model, ask/tier.go).
// pending: the step up happened between questions (a thumbs-down, a
// stopped answer), so reason and from are kept for the next answer's call
// record; otherwise any pending step up is cleared.
func (s *Store) SetAskConversationModel(ctx context.Context, userID, id int64, model, reason, from string, pending bool) error {
	if !pending {
		reason, from = "", ""
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE ask_conversations SET model = left($3, 100), pending_step_up = left($4, 40),
		pending_stepped_from = left($5, 100) WHERE id = $1 AND user_id = $2`, id, userID, model, reason, from)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ClearAskPendingStepUp forgets a pending step up once a call carried it.
func (s *Store) ClearAskPendingStepUp(ctx context.Context, userID, id int64) error {
	_, err := s.Pool.Exec(ctx, `UPDATE ask_conversations SET pending_step_up = '', pending_stepped_from = '' WHERE id = $1 AND user_id = $2`, id, userID)
	return err
}

// DropAskMessagesAfter deletes user's conversation id's messages after seq:
// an answer that is about to be tried again with a stronger model.
func (s *Store) DropAskMessagesAfter(ctx context.Context, userID, id int64, seq int) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM ask_messages m USING ask_conversations c
		WHERE m.conversation_id = c.id AND c.id = $1 AND c.user_id = $2 AND m.seq > $3`, id, userID, seq)
	return err
}

// AskIncompleteDay is one day's (UTC) answer calls of one model, with how
// many were refused and how many left incomplete (refusals included).
type AskIncompleteDay struct {
	Day         string `json:"day"`
	Model       string `json:"model"`
	AnswerCalls int64  `json:"answer_calls"`
	Refusals    int64  `json:"refusals"`
	Incomplete  int64  `json:"incomplete"`
}

// AskIncompleteSummary counts refused and incomplete answers since a day.
// Days is read from the detailed rows while they are kept and from the
// daily totals after; ByReason and ByRefusalCategory from the detailed
// rows only (the last AskCallRetention), from DetailSince on.
type AskIncompleteSummary struct {
	Days              []AskIncompleteDay `json:"days"`
	AnswerCalls       int64              `json:"answer_calls"`
	Refusals          int64              `json:"refusals"`
	Incomplete        int64              `json:"incomplete"`
	ByReason          map[string]int64   `json:"by_reason"`
	ByRefusalCategory map[string]int64   `json:"by_refusal_category"`
	DetailSince       string             `json:"detail_since,omitempty"`
}

// AskIncompleteCounts summarises refused and incomplete answers from since
// on: the workspace in ctx's, or, in system scope, every workspace's (or
// workspaceID's, when it is set). Counts only, never text.
func (s *Store) AskIncompleteCounts(ctx context.Context, since time.Time, workspaceID int64) (*AskIncompleteSummary, error) {
	var ws any
	if workspaceID > 0 {
		ws = workspaceID
	}
	day := since.UTC().Truncate(24 * time.Hour)
	out := &AskIncompleteSummary{Days: []AskIncompleteDay{}, ByReason: map[string]int64{}, ByRefusalCategory: map[string]int64{}}
	rows, err := s.Pool.Query(ctx, `WITH d AS (
			SELECT (created_at AT TIME ZONE 'UTC')::date AS day, model, count(*) AS calls,
				count(*) FILTER (WHERE incomplete_reason = 'refusal') AS refusals, count(*) FILTER (WHERE incomplete_reason <> '') AS incomplete
			FROM ask_api_calls WHERE kind = 'answer' AND created_at >= $1 AND ($2::bigint IS NULL OR workspace_id = $2)
			GROUP BY 1, 2)
		SELECT day::text, model, sum(calls)::bigint, sum(refusals)::bigint, sum(incomplete)::bigint FROM (
			SELECT day, model, calls, refusals, incomplete FROM d
			UNION ALL
			SELECT day, model, calls, refusals, incomplete FROM ask_api_calls_daily
			WHERE kind = 'answer' AND day >= ($1::timestamptz AT TIME ZONE 'UTC')::date AND ($2::bigint IS NULL OR workspace_id = $2)
				AND day < COALESCE((SELECT (min(created_at) AT TIME ZONE 'UTC')::date FROM ask_api_calls), 'infinity'::date)
		) x GROUP BY 1, 2 ORDER BY 1 DESC, 2`, day, ws)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d AskIncompleteDay
		if err := rows.Scan(&d.Day, &d.Model, &d.AnswerCalls, &d.Refusals, &d.Incomplete); err != nil {
			rows.Close()
			return nil, err
		}
		out.Days = append(out.Days, d)
		out.AnswerCalls += d.AnswerCalls
		out.Refusals += d.Refusals
		out.Incomplete += d.Incomplete
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = s.Pool.Query(ctx, `SELECT incomplete_reason, refusal_category, count(*) FROM ask_api_calls
		WHERE kind = 'answer' AND incomplete_reason <> '' AND created_at >= $1 AND ($2::bigint IS NULL OR workspace_id = $2)
		GROUP BY 1, 2`, day, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var reason, category string
		var n int64
		if err := rows.Scan(&reason, &category, &n); err != nil {
			return nil, err
		}
		out.ByReason[reason] += n
		if reason == AskIncompleteRefusal {
			if category == "" {
				category = "unspecified"
			}
			out.ByRefusalCategory[category] += n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var first *time.Time
	if err := s.Pool.QueryRow(ctx, `SELECT min(created_at) FROM ask_api_calls WHERE created_at >= $1 AND ($2::bigint IS NULL OR workspace_id = $2)`,
		day, ws).Scan(&first); err != nil {
		return nil, err
	}
	if first != nil {
		out.DetailSince = first.UTC().Format("2006-01-02")
	}
	return out, nil
}
