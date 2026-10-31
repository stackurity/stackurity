package ask

// This file and client_vertex.go are the only ones that import the
// Anthropic SDK (github.com/anthropics/anthropic-sdk-go/v2, pinned in
// go.mod). The rest
// of the package works with the conversation as JSON: every message is
// stored exactly as it was sent or received and replayed byte for byte
// (param.Override), so the model sees its history unchanged (thinking
// blocks included) and the prompt cache matches.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/bedrock"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
	"github.com/anthropics/anthropic-sdk-go/v2/packages/param"

	"github.com/stackurity/stackurity/internal/mcp"
)

// vertexClient builds the Vertex AI client; set by client_vertex.go in
// builds with the ask_vertex tag, nil otherwise.
var vertexClient func(ctx context.Context, cfg Config, opts []option.RequestOption) (anthropic.BetaMessageService, error)

// Client sends one model call at a time for the engine.
type Client struct {
	provider string
	svc      anthropic.BetaMessageService
	tools    []anthropic.BetaToolUnionParam
	// fallbacks: server-side fallback after a classifier refusal.
	fallbacks bool
}

// requestTimeout bounds one model call, retries included in the caller's
// question deadline.
const requestTimeout = 150 * time.Second

// NewClient builds the client for cfg's provider. The first-party client
// never reads ANTHROPIC_* environment variables or credential files
// (WithoutEnvironmentDefaults): only the key Stackurity was given counts,
// so a stray variable on the host neither turns the assistant on nor
// sends its traffic elsewhere.
func NewClient(ctx context.Context, cfg Config) (*Client, error) {
	c := &Client{provider: cfg.Provider, tools: toolParams()}
	common := []option.RequestOption{option.WithMaxRetries(2), option.WithRequestTimeout(requestTimeout)}
	switch cfg.Provider {
	case ProviderAnthropic:
		opts := append([]option.RequestOption{option.WithoutEnvironmentDefaults(), option.WithAPIKey(cfg.APIKey)}, common...)
		if cfg.BaseURL != "" {
			opts = append(opts, option.WithBaseURL(cfg.BaseURL))
		}
		cl := anthropic.NewClient(opts...)
		c.svc = cl.Beta.Messages
		// Server-side fallback ("default" routing by refusal category) is in
		// beta on the Claude API; checked against
		// https://platform.claude.com/docs/en/build-with-claude/refusals-and-fallback
		// (2026-10-31). Bedrock and Vertex do not have it: there a refusal
		// is shown as one.
		c.fallbacks = !cfg.NoFallbacks
	case ProviderBedrock:
		mc, err := bedrock.NewMantleClient(ctx, bedrock.MantleClientConfig{AWSRegion: cfg.BedrockRegion}, common...)
		if err != nil {
			return nil, fmt.Errorf("Amazon Bedrock: %w", err)
		}
		c.svc = mc.Beta.Messages
	case ProviderVertex:
		if vertexClient == nil {
			return nil, fmt.Errorf("Vertex AI is not in this build: build with -tags ask_vertex (it adds Google's client libraries, about 19 MB)")
		}
		svc, err := vertexClient(ctx, cfg, common)
		if err != nil {
			return nil, fmt.Errorf("Vertex AI: %w", err)
		}
		c.svc = svc
	default:
		return nil, fmt.Errorf("unknown provider %q", cfg.Provider)
	}
	return c, nil
}

// ModelID is the id to send for model on this client's provider: Bedrock
// prefixes "anthropic.".
func (c *Client) ModelID(model string) string {
	if c.provider == ProviderBedrock && !strings.Contains(model, ".") {
		return "anthropic." + model
	}
	return model
}

// Fallbacks reports whether calls ask for server-side fallback.
func (c *Client) Fallbacks() bool { return c.fallbacks }

// toolParams turns the read-only MCP tools into tool definitions, in their
// fixed order. Schemas are maps; encoding/json sorts their keys, so the
// definitions are byte-identical on every call and the prompt cache holds.
// eager_input_streaming stays off: inputs are a few ids and words, and the
// API then still validates them against the schema.
func toolParams() []anthropic.BetaToolUnionParam {
	var out []anthropic.BetaToolUnionParam
	for _, t := range mcp.ReadTools() {
		props, _ := t.InputSchema["properties"].(map[string]any)
		req, _ := t.InputSchema["required"].([]string)
		tp := anthropic.BetaToolParam{
			Name:        t.Name,
			Description: anthropic.String(t.Description),
			InputSchema: anthropic.BetaToolInputSchemaParam{Properties: props, Required: req,
				ExtraFields: map[string]any{"additionalProperties": false}},
		}
		out = append(out, anthropic.BetaToolUnionParam{OfTool: &tp})
	}
	return out
}

// Call is one model call.
type Call struct {
	Model     string
	Effort    string
	MaxTokens int
	// Messages are the conversation so far, each a message as JSON
	// ({"role":..., "content":[...]}), sent byte for byte.
	Messages []json.RawMessage
}

// Result is what one model call returned.
type Result struct {
	// Message is the assistant message as JSON, to store and replay.
	Message json.RawMessage
	// Text is the visible answer: the text blocks after the last point
	// where a fallback model took over.
	Text       string
	StopReason string
	// RefusalCategory is set when StopReason is "refusal".
	RefusalCategory string
	ToolUses        []ToolUse
	// Usage has one entry per model that ran (more than one after a
	// fallback), for pricing.
	Usage     []ModelUsage
	ServedBy  string
	RequestID string
}

// ToolUse is one tool call the model asked for.
type ToolUse struct {
	ID    string
	Name  string
	Input json.RawMessage
}

// ModelUsage is the tokens one model used in a call.
type ModelUsage struct {
	Model      string
	Input      int64
	CacheWrite int64
	CacheRead  int64
	Output     int64
}

// PromptTokens is the size of the prompt the model read.
func (u ModelUsage) PromptTokens() int64 { return u.Input + u.CacheWrite + u.CacheRead }

// StreamEvent is what Stream reports while a call runs.
type StreamEvent struct {
	// Text is a piece of the answer.
	Text string
	// Reset: discard the text reported so far in this call (a refusal or
	// a fallback model taking over).
	Reset bool
}

// ErrUnavailable is the model provider being overloaded, rate limited or
// unreachable: try again later.
var ErrUnavailable = errors.New("the model provider is unavailable")

// ErrRejected is the provider refusing the call itself (bad credentials,
// an invalid request): an operator has to look.
var ErrRejected = errors.New("the model provider rejected the request")

// Stream makes one streaming model call.
func (c *Client) Stream(ctx context.Context, call Call, on func(StreamEvent)) (*Result, error) {
	msgs := make([]anthropic.BetaMessageParam, len(call.Messages))
	for i, m := range call.Messages {
		msgs[i] = param.Override[anthropic.BetaMessageParam](m)
	}
	p := anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(c.ModelID(call.Model)),
		MaxTokens: int64(call.MaxTokens),
		// The frozen system prompt carries the cache breakpoint for the
		// tools and itself; the top-level automatic breakpoint follows the
		// conversation as it grows.
		System:       []anthropic.BetaTextBlockParam{{Text: SystemPrompt, CacheControl: anthropic.NewBetaCacheControlEphemeralParam()}},
		Tools:        c.tools,
		Messages:     msgs,
		OutputConfig: anthropic.BetaOutputConfigParam{Effort: anthropic.BetaOutputConfigEffort(call.Effort)},
		CacheControl: anthropic.NewBetaCacheControlEphemeralParam(),
	}
	if c.fallbacks {
		p.Fallbacks = anthropic.BetaFallbacksParamOfDefault()
		p.Betas = []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01}
	}
	var resp *http.Response
	stream := c.svc.NewStreaming(ctx, p, option.WithResponseInto(&resp))
	defer stream.Close()
	var msg anthropic.BetaMessage
	for stream.Next() {
		ev := stream.Current()
		if err := msg.Accumulate(ev); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRejected, err)
		}
		switch e := ev.AsAny().(type) {
		case anthropic.BetaRawContentBlockStartEvent:
			if e.ContentBlock.Type == "fallback" {
				on(StreamEvent{Reset: true})
			}
		case anthropic.BetaRawContentBlockDeltaEvent:
			if d, ok := e.Delta.AsAny().(anthropic.BetaTextDelta); ok && d.Text != "" {
				on(StreamEvent{Text: d.Text})
			}
		}
	}
	if err := stream.Err(); err != nil {
		return nil, classify(err)
	}
	res := &Result{StopReason: string(msg.StopReason), ServedBy: string(msg.Model)}
	if resp != nil {
		res.RequestID = resp.Header.Get("request-id")
	}
	if res.RequestID == "" {
		res.RequestID = msg.ID
	}
	if msg.StopReason == anthropic.BetaStopReasonRefusal {
		res.RefusalCategory = string(msg.StopDetails.Category)
		on(StreamEvent{Reset: true})
	}
	b, err := json.Marshal(msg.ToParam())
	if err != nil {
		return nil, err
	}
	res.Message = b
	var text strings.Builder
	// The accumulated union carries what the stream built (a tool's input
	// arrives in pieces), so it is read directly.
	for _, blk := range msg.Content {
		switch blk.Type {
		case "text":
			text.WriteString(blk.Text)
		case "fallback":
			text.Reset() // what the refused model wrote is not the answer
		case "tool_use":
			res.ToolUses = append(res.ToolUses, ToolUse{ID: blk.ID, Name: blk.Name, Input: append(json.RawMessage(nil), blk.Input...)})
		}
	}
	res.Text = text.String()
	// Each model that ran is priced at its own price. An iteration may not
	// name its model (the requested model's own iteration): it is then the
	// model asked for.
	if res.ServedBy == "" {
		res.ServedBy = call.Model
	}
	for _, it := range msg.Usage.Iterations {
		m := string(it.Model)
		if m == "" {
			m = call.Model
		}
		res.Usage = append(res.Usage, ModelUsage{Model: m, Input: it.InputTokens, CacheWrite: it.CacheCreationInputTokens,
			CacheRead: it.CacheReadInputTokens, Output: it.OutputTokens})
	}
	if len(res.Usage) == 0 {
		u := msg.Usage
		res.Usage = []ModelUsage{{Model: res.ServedBy, Input: u.InputTokens, CacheWrite: u.CacheCreationInputTokens,
			CacheRead: u.CacheReadInputTokens, Output: u.OutputTokens}}
	}
	return res, nil
}

// classify sorts an SDK error into ErrUnavailable or ErrRejected, keeping
// only the status and the provider's error type: never the request.
func classify(err error) error {
	var apiErr *anthropic.Error
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= 500:
			return fmt.Errorf("%w (status %d)", ErrUnavailable, apiErr.StatusCode)
		default:
			return fmt.Errorf("%w (status %d)", ErrRejected, apiErr.StatusCode)
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}
