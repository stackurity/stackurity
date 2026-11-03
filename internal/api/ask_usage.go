package api

import (
	"context"
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// GET /ask/usage/calls (organisation admins): this organisation's Ask
// Stackurity model calls, newest first, metadata only (never questions or
// answers). ?since, ?until (RFC 3339), ?limit (1000; at most 10000),
// ?before_id (paging), ?format=csv.
func (s *Server) askUsageCalls(w http.ResponseWriter, r *http.Request) {
	s.writeAskCalls(w, r, r.Context(), "ask-calls.csv")
}

// GET /admin/ask/calls (instance admins): every organisation's calls on
// this server, as /ask/usage/calls.
func (s *Server) adminAskCalls(w http.ResponseWriter, r *http.Request) {
	s.writeAskCalls(w, r, tenant.System(r.Context()), "ask-calls-all.csv")
}

func (s *Server) writeAskCalls(w http.ResponseWriter, r *http.Request, ctx context.Context, file string) {
	q := r.URL.Query()
	var f store.AskCallFilter
	for name, dst := range map[string]*time.Time{"since": &f.Since, "until": &f.Until} {
		if v := q.Get(name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				s.fail(w, r, badRequest(name+" must be an RFC 3339 time"))
				return
			}
			*dst = t
		}
	}
	for name, dst := range map[string]*int64{"before_id": &f.BeforeID} {
		if v := q.Get(name); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n <= 0 {
				s.fail(w, r, badRequest(name+" must be a positive number"))
				return
			}
			*dst = n
		}
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 10000 {
			s.fail(w, r, badRequest("limit must be between 1 and 10000"))
			return
		}
		f.Limit = n
	}
	calls, err := s.Store.ListAskAPICalls(ctx, f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	switch q.Get("format") {
	case "", "json":
		writeJSON(w, 200, map[string]any{"items": calls})
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+file+`"`)
		w.Header().Set("Cache-Control", "no-store")
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "created_at", "workspace_id", "user_id", "conversation_id", "kind", "model", "prompt_version",
			"input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens", "cost_micros", "latency_ms",
			"tool_calls", "tool_names", "history_turns_sent", "summary_used", "stop_reason", "error_code", "request_id", "step_up_reason", "stepped_from"})
		opt := func(p *int64) string {
			if p == nil {
				return ""
			}
			return strconv.FormatInt(*p, 10)
		}
		i := strconv.FormatInt
		for _, c := range calls {
			_ = cw.Write([]string{i(c.ID, 10), c.CreatedAt.UTC().Format(time.RFC3339), i(c.WorkspaceID, 10), opt(c.UserID), opt(c.ConversationID),
				c.Kind, csvSafe(c.Model), csvSafe(c.PromptVersion), i(c.InputTokens, 10), i(c.OutputTokens, 10), i(c.CacheReadTokens, 10),
				i(c.CacheWriteTokens, 10), i(c.CostMicros, 10), i(c.LatencyMS, 10), strconv.Itoa(c.ToolCalls),
				csvSafe(strings.Join(c.ToolNames, " ")), strconv.Itoa(c.HistoryTurnsSent), strconv.FormatBool(c.SummaryUsed),
				csvSafe(c.StopReason), csvSafe(c.ErrorCode), csvSafe(c.RequestID), csvSafe(c.StepUpReason), csvSafe(c.SteppedFrom)})
		}
		cw.Flush()
	default:
		s.fail(w, r, badRequest("format must be json or csv"))
	}
}

// csvSafe keeps a spreadsheet from reading a value as a formula.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}
