package ask

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFromEnv(t *testing.T) {
	for _, k := range []string{"STACKURITY_ANTHROPIC_API_KEY", "STACKURITY_ANTHROPIC_API_KEY_FILE", "STACKURITY_ASK_PROVIDER", "STACKURITY_ASK_MODEL",
		"STACKURITY_ASK_EFFORT", "STACKURITY_ASK_SPEND_CAP_USD", "STACKURITY_ASK_GLOBAL_SPEND_CAP_USD", "STACKURITY_ASK_QUESTIONS_PER_MONTH", "STACKURITY_ASK_PRICES",
		"STACKURITY_ASK_BEDROCK_REGION", "STACKURITY_ASK_FALLBACKS", "ANTHROPIC_API_KEY"} {
		t.Setenv(k, "")
	}
	// Off by default, even with ANTHROPIC_API_KEY on the host.
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-host")
	c, err := FromEnv()
	if err != nil || c.Enabled() {
		t.Fatalf("default = %+v %v", c, err)
	}
	f := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(f, []byte("sk-ant-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STACKURITY_ANTHROPIC_API_KEY_FILE", f)
	t.Setenv("STACKURITY_ASK_GLOBAL_SPEND_CAP_USD", "300")
	t.Setenv("STACKURITY_ASK_PRICES", "claude-sonnet-5-5=3,3.75,0.3,15")
	c, err = FromEnv()
	if err != nil || c.Provider != ProviderAnthropic || c.APIKey != "sk-ant-from-file" || c.Model != DefaultModel || c.Effort != "low" ||
		*c.GlobalCapMicros != 300_000_000 || c.Prices["claude-sonnet-5-5"].Output != 15 {
		t.Fatalf("with a key file = %+v %v", c, err)
	}
	for k, v := range map[string]string{"STACKURITY_ASK_EFFORT": "extreme", "STACKURITY_ASK_PROVIDER": "openai", "STACKURITY_ASK_SPEND_CAP_USD": "-1",
		"STACKURITY_ASK_PRICES": "m=1,2"} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if _, err := FromEnv(); err == nil {
				t.Errorf("%s=%s accepted", k, v)
			} else if strings.Contains(err.Error(), "sk-ant-from-file") {
				t.Errorf("error shows the key: %v", err)
			}
		})
	}
	t.Setenv("STACKURITY_ANTHROPIC_API_KEY_FILE", "")
	t.Setenv("STACKURITY_ASK_PROVIDER", "bedrock")
	if _, err := FromEnv(); err == nil {
		t.Error("bedrock without a region accepted")
	}
}

func TestPrices(t *testing.T) {
	var p Prices
	// Claude Opus 5.5: $4 in, $5 cache write, $0.20 cache read, $20 out per MTok.
	if got := p.Cost(ModelUsage{Model: "claude-opus-5-5", Input: 1_000_000, CacheWrite: 1_000_000, CacheRead: 1_000_000, Output: 1_000_000}); got != 29_200_000 {
		t.Errorf("opus = %d", got)
	}
	if got := p.Cost(ModelUsage{Model: "anthropic.claude-sonnet-5-5", Output: 1}); got != 10 {
		t.Errorf("bedrock id = %d", got)
	}
	// Haiku 5.5 over 100k tokens of prompt is dearer.
	if a, b := p.Cost(ModelUsage{Model: "claude-haiku-5-5", Input: 100_000}), p.Cost(ModelUsage{Model: "claude-haiku-5-5", Input: 100_001}); b <= a*4 {
		t.Errorf("haiku long prompt = %d vs %d", a, b)
	}
	if _, known := p.Of("claude-unknown-9"); known {
		t.Error("unknown model is known")
	}
	if p.Cost(ModelUsage{Model: "claude-unknown-9", Output: 1}) != 50 {
		t.Error("unknown model not at the highest price")
	}
	// A hold covers the worst case, including a dearer fallback model.
	if with, without := p.HoldFor("claude-sonnet-5-5", 10_000, 8000, true), p.HoldFor("claude-sonnet-5-5", 10_000, 8000, false); with <= without {
		t.Errorf("hold with fallback %d, without %d", with, without)
	}
	o := Prices{Overrides: map[string]Price{"claude-opus-5-5": {Output: 1}}}
	if got := o.Cost(ModelUsage{Model: "claude-opus-5-5", Output: 5}); got != 5 {
		t.Errorf("override = %d", got)
	}
}

func TestToolResultText(t *testing.T) {
	big := strings.Repeat("é", maxToolResult)
	s := ToolResultText("list_findings", map[string]any{"title": big})
	if !strings.HasPrefix(s, dataNote) || !strings.Contains(s, "[cut: the result was longer than 40 KB") || len(s) > maxToolResult+len(dataNote)+200 {
		t.Errorf("long result: %d bytes", len(s))
	}
	if !strings.Contains(s, "é") || strings.Contains(s, "�") {
		t.Error("cut inside a character")
	}
	// asset_stack's members are assets, not people: kept.
	s = ToolResultText("asset_stack", map[string]any{"members": []any{map[string]any{"name": "web-1"}}})
	if !strings.Contains(s, "web-1") {
		t.Errorf("asset members dropped: %s", s)
	}
	s = ToolResultText("get_finding", map[string]any{"history": []any{map[string]any{"actor": map[string]any{"name": "Bob"}, "requested_by": "Bob B"}}, "team_name": "Ops"})
	if strings.Contains(s, "Bob") || !strings.Contains(s, "Ops") {
		t.Errorf("people = %s", s)
	}
}
