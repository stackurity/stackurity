package ask

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
	msgs := make([]json.RawMessage, 0, len(history)+2)
	for _, m := range history {
		msgs = append(msgs, m.Content)
	}
	var page json.RawMessage
	if q.Page != nil {
		page, _ = json.Marshal(q.Page)
	}
	um := userMessage(textBlock(contextBlock(e.now(), q.Page, q.Project)), textBlock(q.Text))
	if _, err := e.Store.AppendAskMessage(ctx, q.UserID, c.ID, store.AskMessage{Role: "user", Content: um, VisibleText: q.Text, Page: page}, 0); err != nil {
		return out, err
	}
	msgs = append(msgs, um)

	model := c.Model
	for round := 1; ; round++ {
		res, cost, err := e.call(ctx, q, model, msgs, emit)
		if err != nil {
			return out, err
		}
		out.CostMicros += cost
		out.Usage = append(out.Usage, res.Usage...)
		var prompt int64
		for _, u := range res.Usage {
			prompt = max(prompt, u.PromptTokens())
		}
		am := store.AskMessage{Role: "assistant", Content: res.Message, VisibleText: res.Text, Model: res.ServedBy, StopReason: res.StopReason,
			CostMicros: cost, RequestID: res.RequestID}
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
			return out, nil
		}
		last := round >= MaxRounds || prompt > MaxContextTokens
		results := e.runTools(ctx, q.API, res.ToolUses, last, emit)
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
			return out, nil
		}
	}
}

// call holds spend for one model call, makes it and settles the hold.
func (e *Engine) call(ctx context.Context, q Question, model string, msgs []json.RawMessage, emit func(Event)) (*Result, int64, error) {
	var size int
	for _, m := range msgs {
		size += len(m)
	}
	// About three bytes a token, plus the tools and system prompt.
	prompt := int64(size/3 + 6000)
	hold, err := e.Store.HoldAskSpend(ctx, e.Prices.HoldFor(model, prompt, DefaultMaxTokens, e.Model.Fallbacks()), q.SpendCapMicros, e.Config.GlobalCapMicros)
	if err != nil {
		return nil, 0, err
	}
	res, err := e.Model.Stream(ctx, Call{Model: model, Effort: e.Config.Effort, MaxTokens: DefaultMaxTokens, Messages: msgs}, func(ev StreamEvent) {
		switch {
		case ev.Reset:
			emit(Event{Kind: "reset"})
		case ev.Text != "":
			emit(Event{Kind: "text", Text: ev.Text})
		}
	})
	sctx := context.WithoutCancel(ctx)
	var cost int64
	if res != nil {
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
	if err != nil {
		return nil, cost, err
	}
	return res, cost, nil
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

// runTools runs the tools the model asked for, as the person, and returns
// their results in order, all for one user message. last: the question's
// budget is used up, so each result says so instead of running.
func (e *Engine) runTools(ctx context.Context, api mcp.API, uses []ToolUse, last bool, emit func(Event)) []map[string]any {
	out := make([]map[string]any, len(uses))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxParallelTools)
	for i, u := range uses {
		if last || ctx.Err() != nil {
			msg := "Not run: this question's tool budget is used up. Answer from what you have, and say what is missing."
			if ctx.Err() != nil {
				msg = "Not run: the person stopped the question."
			}
			out[i] = toolResult(u.ID, msg, true)
			continue
		}
		emit(Event{Kind: "tool", Tool: toolLabel(u)})
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = e.runTool(ctx, api, u)
		}()
	}
	wg.Wait()
	return out
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
