//go:build asklive

package ask

// Live checks against Anthropic's API. They spend real money, so they run
// only when asked twice: the build tag asklive and STACKURITY_ASK_LIVE=1.
// The key is read at run time from STACKURITY_ASK_LIVE_KEY_FILE (default
// ~/.config/stackurity/anthropic-api-key) and is never printed. Each test
// logs the tokens and the cost it used. CI never runs them.
//
//	STACKURITY_ASK_LIVE=1 go test -tags asklive -run Live -v ./internal/ask/

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func liveClient(t *testing.T) *Client {
	t.Helper()
	if os.Getenv("STACKURITY_ASK_LIVE") != "1" {
		t.Skip("set STACKURITY_ASK_LIVE=1 to call Anthropic's API")
	}
	f := os.Getenv("STACKURITY_ASK_LIVE_KEY_FILE")
	if f == "" {
		home, _ := os.UserHomeDir()
		f = filepath.Join(home, ".config", "stackurity", "anthropic-api-key")
	}
	b, err := os.ReadFile(f)
	if err != nil {
		t.Skip("no key file") // the path only; never the contents
	}
	c, err := NewClient(context.Background(), Config{Provider: ProviderAnthropic, APIKey: strings.TrimSpace(string(b)), Model: DefaultModel, Effort: "low"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Two identical tiny calls on each plan model: the request is accepted as
// built (tools, cache breakpoints, effort, fallbacks), and the second call
// reads the tools and system prompt from the cache.
func TestLiveRequestAndCache(t *testing.T) {
	c := liveClient(t)
	var p Prices
	var total int64
	for _, model := range []string{"claude-sonnet-5-5", "claude-opus-5-5"} {
		q, _ := json.Marshal(map[string]any{"role": "user", "content": []map[string]any{textBlock("Reply with the single word: ok. Do not use any tool.")}})
		var reads int64
		for i := range 2 {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			res, err := c.Stream(ctx, Call{Model: model, Effort: "low", MaxTokens: 1000, Messages: []json.RawMessage{q}}, func(StreamEvent) {})
			cancel()
			if err != nil {
				t.Fatalf("%s call %d: %v", model, i+1, err)
			}
			for _, u := range res.Usage {
				cost := p.Cost(u)
				total += cost
				t.Logf("%s (served by %s) call %d: stop=%s input=%d cache_write=%d cache_read=%d output=%d cost=$%.6f", u.Model, res.ServedBy, i+1, res.StopReason,
					u.Input, u.CacheWrite, u.CacheRead, u.Output, float64(cost)/1e6)
				if _, known := p.Of(u.Model); !known {
					t.Errorf("usage names no known model: %q", u.Model)
				}
				if i == 1 {
					reads += u.CacheRead
				}
			}
			if res.StopReason != "end_turn" || !strings.Contains(strings.ToLower(res.Text), "ok") {
				t.Errorf("%s call %d: %q (%s)", model, i+1, res.Text, res.StopReason)
			}
		}
		if reads == 0 {
			t.Errorf("%s: the second call read nothing from the cache", model)
		}
	}
	t.Logf("total live spend: $%.6f", float64(total)/1e6)
}
