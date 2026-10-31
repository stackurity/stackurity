package ask

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Price is a model's price in US dollars per million tokens, which is the
// same number as millionths of a dollar (micros) per token.
type Price struct {
	Input, CacheWrite, CacheRead, Output float64
	// LongPrompt applies instead when a call's prompt is over
	// LongPromptTokens (Claude Haiku 5.5).
	LongPrompt       *Price
	LongPromptTokens int64
}

// prices are Anthropic's list prices (5-minute cache writes), from
// https://platform.claude.com/docs/en/about-claude/pricing (2026-10-31).
// The fallback models a refusal can route to are listed too. Bedrock and
// Vertex bill their own prices: set STACKURITY_ASK_PRICES there.
var prices = map[string]Price{
	"claude-opus-5-5":   {Input: 4, CacheWrite: 5, CacheRead: 0.20, Output: 20},
	"claude-sonnet-5-5": {Input: 2, CacheWrite: 2.5, CacheRead: 0.10, Output: 10},
	"claude-haiku-5-5": {Input: 0.10, CacheWrite: 0.125, CacheRead: 0.01, Output: 0.50,
		LongPrompt: &Price{Input: 0.50, CacheWrite: 0.625, CacheRead: 0.05, Output: 2.50}, LongPromptTokens: 100_000},
	"claude-opus-5":    {Input: 5, CacheWrite: 6.25, CacheRead: 0.50, Output: 25},
	"claude-opus-4-8":  {Input: 5, CacheWrite: 6.25, CacheRead: 0.50, Output: 25},
	"claude-sonnet-5":  {Input: 2, CacheWrite: 2.5, CacheRead: 0.20, Output: 10},
	"claude-fable-5-1": {Input: 10, CacheWrite: 12.5, CacheRead: 0.25, Output: 50},
}

// unknownPrice prices a model this table does not know at the most
// expensive model's price, so a cap is never passed by mistake.
var unknownPrice = Price{Input: 10, CacheWrite: 12.5, CacheRead: 1, Output: 50}

// Prices looks up model prices, with overrides first.
type Prices struct{ Overrides map[string]Price }

// Of returns model's price, and whether it is known.
func (p Prices) Of(model string) (Price, bool) {
	model = strings.TrimPrefix(model, "anthropic.") // Bedrock ids
	if x, ok := p.Overrides[model]; ok {
		return x, true
	}
	if x, ok := prices[model]; ok {
		return x, true
	}
	return unknownPrice, false
}

// Cost is what u cost, in micros, rounded up.
func (p Prices) Cost(u ModelUsage) int64 {
	pr, _ := p.Of(u.Model)
	if pr.LongPrompt != nil && u.PromptTokens() > pr.LongPromptTokens {
		pr = *pr.LongPrompt
	}
	c := float64(u.Input)*pr.Input + float64(u.CacheWrite)*pr.CacheWrite + float64(u.CacheRead)*pr.CacheRead + float64(u.Output)*pr.Output
	return int64(math.Ceil(c))
}

// HoldFor is what to hold before a call to model whose prompt is about
// promptTokens and whose answer is at most maxTokens: the whole prompt as a
// cache write and the whole answer, at the dearer of the model and any
// fallback model, so a call can never cost more than its hold.
func (p Prices) HoldFor(model string, promptTokens, maxTokens int64, fallbacks bool) int64 {
	pr, _ := p.Of(model)
	if pr.LongPrompt != nil {
		pr = *pr.LongPrompt
	}
	worst := pr
	if fallbacks {
		for _, f := range []string{"claude-opus-4-8", "claude-opus-5", "claude-sonnet-5"} {
			if x, _ := p.Of(f); x.CacheWrite+x.Output > worst.CacheWrite+worst.Output {
				worst = x
			}
		}
	}
	return int64(math.Ceil(float64(promptTokens)*math.Max(worst.CacheWrite, worst.Input) + float64(maxTokens)*worst.Output))
}

// ParsePrices reads STACKURITY_ASK_PRICES:
// "model=input,cache_write,cache_read,output;..." in USD per million tokens.
func ParsePrices(s string) (map[string]Price, error) {
	out := map[string]Price{}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		model, nums, ok := strings.Cut(part, "=")
		f := strings.Split(nums, ",")
		if !ok || strings.TrimSpace(model) == "" || len(f) != 4 {
			return nil, fmt.Errorf("STACKURITY_ASK_PRICES: %q is not model=input,cache_write,cache_read,output", part)
		}
		var v [4]float64
		for i, x := range f {
			n, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("STACKURITY_ASK_PRICES: %q is not a price", x)
			}
			v[i] = n
		}
		out[strings.TrimSpace(model)] = Price{Input: v[0], CacheWrite: v[1], CacheRead: v[2], Output: v[3]}
	}
	return out, nil
}
