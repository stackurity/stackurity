package ask

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/stackurity/stackurity/internal/mcp"
	"github.com/stackurity/stackurity/internal/store"
)

// Model makes one model call; *Client is the real one.
type Model interface {
	Stream(ctx context.Context, call Call, on func(StreamEvent)) (*Result, error)
	Fallbacks() bool
}

// Engine answers questions.
type Engine struct {
	Model  Model
	Store  *store.Store
	Prices Prices
	Config Config
	Log    *slog.Logger
	// Alert is told when spend first reaches 80 or 100 per cent of a cap
	// this month: scope "workspace" (ctx is the workspace's) or "global".
	Alert func(ctx context.Context, scope string, level int, spent, cap int64)
	// Now is the clock (tests).
	Now func() time.Time
}

// Question is one question of a person, with everything the API checked.
type Question struct {
	Conversation *store.AskConversation
	UserID       int64
	Text         string
	Page         *PageRef
	// Project names the project the person chose ("" : none).
	Project string
	// Model is the organisation's model; Limits its caps.
	Model          string
	SpendCapMicros *int64
	// API runs the tools as the person.
	API mcp.API
}

// Event is what the engine reports while it answers.
type Event struct {
	Kind string `json:"-"` // text, reset, tool
	Text string `json:"text,omitempty"`
	// Tool describes a tool that runs, for the person ("Reading finding 12").
	Tool string `json:"tool,omitempty"`
}

// Outcome is how a question ended.
type Outcome struct {
	// Text is the answer as stored.
	Text string
	// StopReason: end_turn, refusal, max_tokens, rounds (the tool budget
	// was used up), too_long (the conversation is too long).
	StopReason string
	CostMicros int64
	Usage      []ModelUsage
	// ToolErrors counts tools that ran and failed (not those skipped for
	// the budget or a stop), for the implicit feedback signal.
	ToolErrors int
	// LongChat: the conversation has had many questions or cost a lot;
	// the panel suggests a new chat.
	LongChat bool
}

// ErrTooLong is a conversation that grew too long to continue.
var ErrTooLong = errors.New("this conversation is too long; start a new one")

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

// userMessage builds a user message as JSON.
func userMessage(blocks ...map[string]any) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"role": "user", "content": blocks})
	return b
}

func textBlock(s string) map[string]any { return map[string]any{"type": "text", "text": s} }

// Ask answers q. ctx is the person's request (its workspace scope); emit
// is called for each piece of the answer. The question is already counted
// against the quota. The conversation is stored as it goes, so an
// interrupted question leaves a conversation the next one can continue.
func (e *Engine) Ask(ctx context.Context, q Question, emit func(Event)) (Outcome, error) {
	var out Outcome
	c := q.Conversation
	if c.ContextTokens > MaxContextTokens {
		return out, ErrTooLong
	}
	history, err := e.Store.AskMessages(ctx, q.UserID, c.ID)
	if err != nil {
		return out, err
	}
	// The history budget (history.go): a summary of the earlier turns
	// once the history is too long, and the recent turns as they are.
	plan := planHistory(c, history)
	summary := c.Summary
	if len(plan.Summarise) > 0 {
		emit(Event{Kind: "tool", Tool: "Summarising the earlier conversation"})
		s, err := e.summarise(ctx, q, plan)
		switch {
		case err == nil:
			summary = s
		case errors.Is(err, store.ErrAskSpendCap) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
			return out, err
		default:
			// Not fatal: this question sends its whole history instead,
			// and the next one tries the summary again.
			e.log().Warn("assistant: summarising a conversation failed; sending its history", "err", err)
			plan = historyPlan{Tail: append(plan.Summarise, plan.Tail...)}
		}
	}
	spec := callSpec{kind: "answer", model: c.Model, maxTokens: DefaultMaxTokens, historyTurns: len(exchanges(plan.Tail)), summaryUsed: summary != ""}
	if len(plan.Tail) == 0 {
		spec.historyTurns = 0
	}
	msgs := historyMessages(summary, plan.Tail)
	var page json.RawMessage
	if q.Page != nil {
		page, _ = json.Marshal(q.Page)
	}
	um := userMessage(textBlock(contextBlock(e.now(), q.Page, q.Project)), textBlock(q.Text))
	if _, err := e.Store.AppendAskMessage(ctx, q.UserID, c.ID, store.AskMessage{Role: "user", Content: um, VisibleText: q.Text, Page: page}, 0); err != nil {
		return out, err
	}
	msgs = append(msgs, um)

	for round := 1; ; round++ {
		res, cost, err := e.call(ctx, q, spec, msgs, emit)
		if err != nil {
			// A call that ended early is still paid for: the caller
			// must not treat the question as never reaching the model.
			out.CostMicros += cost
			if res != nil {
				out.Usage = append(out.Usage, res.Usage...)
			}
			return out, err
		}
		out.CostMicros += cost
		out.Usage = append(out.Usage, res.Usage...)
		var prompt int64
		for _, u := range res.Usage {
			prompt = max(prompt, u.PromptTokens())
		}
		am := store.AskMessage{Role: "assistant", Content: res.Message, VisibleText: res.Text, Model: res.ServedBy, StopReason: res.StopReason,
			CostMicros: cost, RequestID: res.RequestID, PromptVersion: PromptVersion}
		for _, u := range res.Usage {
			am.Usage.Input += u.Input
			am.Usage.CacheWrite += u.CacheWrite
			am.Usage.CacheRead += u.CacheRead
			am.Usage.Output += u.Output
		}
		// Stored with a context that outlives a cancelled request: a model
		// call that was paid for is always recorded.
		sctx := context.WithoutCancel(ctx)
		if _, err := e.Store.AppendAskMessage(sctx, q.UserID, c.ID, am, prompt); err != nil {
			return out, err
		}
		msgs = append(msgs, res.Message)
		if res.Text != "" {
			out.Text = res.Text
		}
		if res.StopReason != "tool_use" || len(res.ToolUses) == 0 {
			out.StopReason = res.StopReason
			if res.StopReason == "refusal" {
				out.Text = ""
			}
			e.markLongChat(sctx, q, &out)
			return out, nil
		}
		last := round >= MaxRounds || prompt > MaxContextTokens
		results, failed := e.runTools(ctx, q.API, res.ToolUses, last, emit)
		out.ToolErrors += failed
		tm := userMessage(results...)
		if _, err := e.Store.AppendAskMessage(sctx, q.UserID, c.ID, store.AskMessage{Role: "user", Content: tm}, 0); err != nil {
			return out, err
		}
		msgs = append(msgs, tm)
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if last {
			out.StopReason = "rounds"
			if prompt > MaxContextTokens {
				out.StopReason = "too_long"
			}
			e.markLongChat(sctx, q, &out)
			return out, nil
		}
	}
}

// markLongChat sets out.LongChat when the conversation has had many
// questions or cost a lot: the panel then suggests a new chat.
func (e *Engine) markLongChat(ctx context.Context, q Question, out *Outcome) {
	n, cost, err := e.Store.AskConversationTotals(ctx, q.UserID, q.Conversation.ID)
	if err != nil {
		e.log().Warn("assistant: conversation totals", "err", err)
		return
	}
	out.LongChat = e.Config.longChat(n, cost)
}

// callSpec is one model call's kind and shape.
type callSpec struct {
	kind      string // answer or summary
	model     string
	maxTokens int
	// system and noTools: the summary call's own prompt, without tools.
	system  string
	noTools bool
	// historyTurns and summaryUsed describe the history sent, for the
	// call record.
	historyTurns int
	summaryUsed  bool
}

// call holds spend for one model call, makes it, settles the hold and
// records the call (ask_api_calls and one log line, metadata only).
func (e *Engine) call(ctx context.Context, q Question, spec callSpec, msgs []json.RawMessage, emit func(Event)) (*Result, int64, error) {
	var size int
	for _, m := range msgs {
		size += len(m)
	}
	// About three bytes a token, plus the tools and system prompt.
	prompt := int64(size/3 + 6000)
	fallbacks := e.Model.Fallbacks() && spec.kind == "answer"
	holdMicros := e.Prices.HoldFor(spec.model, prompt, int64(spec.maxTokens), fallbacks)
	hold, err := e.Store.HoldAskSpend(ctx, holdMicros, q.SpendCapMicros, e.Config.GlobalCapMicros)
	if err != nil {
		return nil, 0, err
	}
	started := e.now()
	res, err := e.Model.Stream(ctx, Call{Model: spec.model, Effort: e.Config.Effort, MaxTokens: spec.maxTokens, Messages: msgs,
		System: spec.system, NoTools: spec.noTools, NoFallbacks: !fallbacks}, func(ev StreamEvent) {
		switch {
		case ev.Reset:
			emit(Event{Kind: "reset"})
		case ev.Text != "":
			emit(Event{Kind: "text", Text: ev.Text})
		}
	})
	sctx := context.WithoutCancel(ctx)
	var cost int64
	switch {
	case err != nil && res == nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)):
		// Stopped before the provider's first event: the request may
		// already have been sent and billed, and nothing says how much,
		// so the hold is the charge.
		cost = holdMicros
	case res != nil:
		for _, u := range res.Usage {
			cost += e.Prices.Cost(u)
			if _, known := e.Prices.Of(u.Model); !known {
				e.log().Warn("assistant: no price for this model; spend counted at the highest price", "model", u.Model)
			}
		}
	}
	lvl, serr := e.Store.SettleAskSpend(sctx, hold, cost)
	if serr != nil {
		e.log().Error("assistant: recording spend", "err", serr)
	} else {
		e.alerts(sctx, lvl)
	}
	e.recordCall(sctx, q, spec, res, cost, e.now().Sub(started), err)
	if err != nil {
		return res, cost, err
	}
	return res, cost, nil
}

// recordCall stores one call's metadata (never text) and logs it on one
// line. It is written with the request, not buffered: a failure to record
// is logged and does not fail the question.
func (e *Engine) recordCall(ctx context.Context, q Question, spec callSpec, res *Result, cost int64, latency time.Duration, callErr error) {
	uid, cid := q.UserID, q.Conversation.ID
	c := store.AskAPICall{UserID: &uid, ConversationID: &cid, Kind: spec.kind, Model: spec.model, PromptVersion: PromptVersion,
		CostMicros: cost, LatencyMS: latency.Milliseconds(), HistoryTurnsSent: spec.historyTurns, SummaryUsed: spec.summaryUsed,
		ErrorCode: errorCode(callErr)}
	if res != nil {
		if res.ServedBy != "" {
			c.Model = res.ServedBy
		}
		c.StopReason, c.RequestID = res.StopReason, res.RequestID
		if res.Partial {
			c.StopReason = "partial"
		}
		for _, u := range res.Usage {
			c.InputTokens += u.Input
			c.OutputTokens += u.Output
			c.CacheReadTokens += u.CacheRead
			c.CacheWriteTokens += u.CacheWrite
		}
		for _, t := range res.ToolUses {
			c.ToolNames = append(c.ToolNames, t.Name)
		}
		c.ToolCalls = len(res.ToolUses)
	}
	if _, err := e.Store.RecordAskAPICall(ctx, c); err != nil {
		e.log().Error("assistant: recording a model call", "err", err)
	}
	e.log().Info("ask call", "kind", c.Kind, "model", c.Model, "prompt_version", c.PromptVersion, "conversation", cid,
		"input_tokens", c.InputTokens, "output_tokens", c.OutputTokens, "cache_read_tokens", c.CacheReadTokens,
		"cache_write_tokens", c.CacheWriteTokens, "cost_micros", c.CostMicros, "latency_ms", c.LatencyMS,
		"tool_calls", c.ToolCalls, "tools", strings.Join(c.ToolNames, ","), "history_turns", c.HistoryTurnsSent,
		"summary_used", c.SummaryUsed, "stop_reason", c.StopReason, "error", c.ErrorCode)
}

// errorCode names how a call failed ("" when it did not).
func errorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, ErrUnavailable):
		return "unavailable"
	case errors.Is(err, ErrRejected):
		return "rejected"
	}
	return "error"
}

// alerts tells Alert about a cap reached for the first time this month.
func (e *Engine) alerts(ctx context.Context, lvl store.AskSpendLevel) {
	if e.Alert == nil {
		return
	}
	check := func(scope string, spent int64, cap *int64) {
		if cap == nil || *cap <= 0 {
			return
		}
		for _, level := range []int{100, 80} {
			if spent*100 < *cap*int64(level) {
				continue
			}
			first, err := e.Store.MarkAskAlert(ctx, scope, level)
			if err != nil {
				e.log().Error("assistant: recording a spend alert", "err", err)
				return
			}
			if first {
				e.Alert(ctx, scope, level, spent, *cap)
			}
			return
		}
	}
	check("workspace", lvl.WorkspaceSpent, lvl.WorkspaceCap)
	check("global", lvl.GlobalSpent, lvl.GlobalCap)
}

// maxParallelTools runs at most this many tools of one call at once.
const maxParallelTools = 4

// MaxToolsPerRound is the most tools one model call may run; the rest get
// a "not run" result, so text planted in a tool's output cannot make one
// call fan out into dozens of large reads (and their cost next round).
const MaxToolsPerRound = 8

// runTools runs the tools the model asked for, as the person, and returns
// their results in order, all for one user message. last: the question's
// budget is used up, so each result says so instead of running.
func (e *Engine) runTools(ctx context.Context, api mcp.API, uses []ToolUse, last bool, emit func(Event)) ([]map[string]any, int) {
	out := make([]map[string]any, len(uses))
	ran := make([]bool, len(uses))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxParallelTools)
	for i, u := range uses {
		if last || ctx.Err() != nil || i >= MaxToolsPerRound {
			msg := "Not run: this question's tool budget is used up. Answer from what you have, and say what is missing."
			switch {
			case ctx.Err() != nil:
				msg = "Not run: the person stopped the question."
			case !last:
				msg = fmt.Sprintf("Not run: at most %d tools run at a time. Ask for this one again if you still need it.", MaxToolsPerRound)
			}
			out[i] = toolResult(u.ID, msg, true)
			continue
		}
		emit(Event{Kind: "tool", Tool: toolLabel(u)})
		ran[i] = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = e.runTool(ctx, api, u)
		}()
	}
	wg.Wait()
	failed := 0
	for i, r := range out {
		if ran[i] && r["is_error"] == true {
			failed++
		}
	}
	return out, failed
}

func toolResult(id, text string, isErr bool) map[string]any {
	r := map[string]any{"type": "tool_result", "tool_use_id": id, "content": []map[string]any{textBlock(text)}}
	if isErr {
		r["is_error"] = true
	}
	return r
}

func (e *Engine) runTool(ctx context.Context, api mcp.API, u ToolUse) map[string]any {
	var args map[string]any
	if len(u.Input) > 0 {
		if err := json.Unmarshal(u.Input, &args); err != nil {
			return toolResult(u.ID, "The tool input is not a JSON object.", true)
		}
	}
	if !mcp.IsReadTool(u.Name) {
		return toolResult(u.ID, "There is no tool "+fmt.Sprintf("%q", u.Name)+": only the read-only Stackurity tools exist here.", true)
	}
	res, err := mcp.CallRead(ctx, api, u.Name, args)
	if err != nil {
		return toolResult(u.ID, ErrorText(err), true)
	}
	return toolResult(u.ID, ToolResultText(u.Name, res), false)
}

// toolLabel says in a few words what a tool call reads, for the person.
func toolLabel(u ToolUse) string {
	var a map[string]any
	_ = json.Unmarshal(u.Input, &a)
	id := func(k string) string {
		if v, ok := a[k].(float64); ok && v > 0 {
			return fmt.Sprintf(" #%d", int64(v))
		}
		return ""
	}
	switch u.Name {
	case "search":
		return "Searching"
	case "list_assets":
		return "Listing assets"
	case "action_plan", "remediation_plan":
		return "Reading the fixes" + id("asset_id")
	case "asset_stack":
		return "Reading asset" + id("asset_id")
	case "list_findings":
		return "Listing issues"
	case "get_finding", "explain_finding":
		return "Reading issue" + id("finding_id")
	case "find_component":
		return "Finding a package"
	case "upgrade_recommendation":
		return "Checking upgrades"
	case "verify_since":
		return "Checking what changed"
	case "updates_available":
		return "Checking available updates"
	}
	return "Reading"
}
