// Package ask is Ask Stackurity, the in-app assistant: a person's question
// is answered by a Claude model that reads Stackurity through the
// read-only MCP tools (internal/mcp), run as that person, so it sees what
// they may see and nothing else, and can change nothing.
//
// The engine (engine.go) runs one question: it holds spend against the
// caps before each model call, streams the answer, runs the tools the
// model asks for, cleans what they return (scrub.go), and stores every
// message exactly as sent so the next question replays it unchanged. The
// SDK sits behind client.go alone.
package ask

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Providers.
const (
	ProviderAnthropic = "anthropic"
	ProviderBedrock   = "bedrock"
	ProviderVertex    = "vertex"
)

// Default settings.
const (
	DefaultModel     = "claude-sonnet-5-5"
	DefaultEffort    = "low"
	DefaultMaxTokens = 8000
	// MaxRounds is the model calls one question may make.
	MaxRounds = 8
	// MaxContextTokens: a conversation whose prompt grew past this is
	// closed; the person starts a new one.
	MaxContextTokens = 150_000
)

// Config is the installation's assistant configuration, from the
// environment. Provider "" means the assistant is off.
type Config struct {
	Provider string
	// APIKey is the Anthropic API key (provider anthropic). Never logged.
	APIKey string
	// BaseURL overrides the API address (a proxy; tests).
	BaseURL       string
	BedrockRegion string
	VertexProject string
	VertexRegion  string
	// Model is the default model; an organisation's own (its plan's) wins.
	Model  string
	Effort string
	// NoFallbacks turns off server-side fallback after a refusal.
	NoFallbacks bool
	// QuestionLimit and SpendCapMicros apply to organisations that have no
	// limit of their own (nil: none). GlobalCapMicros caps the whole
	// installation's spend each month (nil: none).
	QuestionLimit   *int64
	SpendCapMicros  *int64
	GlobalCapMicros *int64
	// Prices override or add model prices (STACKURITY_ASK_PRICES), for
	// Bedrock and Vertex, whose prices differ from Anthropic's.
	Prices map[string]Price
}

// Enabled reports whether a provider is configured.
func (c Config) Enabled() bool { return c.Provider != "" }

// FromEnv reads the configuration:
//
//	STACKURITY_ANTHROPIC_API_KEY (or _FILE)  turns it on with Anthropic's API
//	STACKURITY_ASK_PROVIDER                  anthropic, bedrock or vertex
//	STACKURITY_ASK_BEDROCK_REGION            for bedrock (AWS credentials: the default chain)
//	STACKURITY_ASK_VERTEX_PROJECT, _REGION   for vertex (Google application default credentials)
//	STACKURITY_ASK_MODEL, STACKURITY_ASK_EFFORT
//	STACKURITY_ASK_QUESTIONS_PER_MONTH, STACKURITY_ASK_SPEND_CAP_USD, STACKURITY_ASK_GLOBAL_SPEND_CAP_USD
//	STACKURITY_ASK_PRICES                    model=input,cache_write,cache_read,output;... in USD per million tokens
//	STACKURITY_ASK_FALLBACKS                 off to turn server-side fallback off
//	STACKURITY_ASK_BASE_URL                  the API through a proxy
func FromEnv() (Config, error) {
	key, err := envOrFile("STACKURITY_ANTHROPIC_API_KEY")
	if err != nil {
		return Config{}, err
	}
	c := Config{
		APIKey:        key,
		Provider:      strings.ToLower(strings.TrimSpace(os.Getenv("STACKURITY_ASK_PROVIDER"))),
		BaseURL:       strings.TrimSpace(os.Getenv("STACKURITY_ASK_BASE_URL")),
		BedrockRegion: strings.TrimSpace(os.Getenv("STACKURITY_ASK_BEDROCK_REGION")),
		VertexProject: strings.TrimSpace(os.Getenv("STACKURITY_ASK_VERTEX_PROJECT")),
		VertexRegion:  strings.TrimSpace(os.Getenv("STACKURITY_ASK_VERTEX_REGION")),
		Model:         strings.TrimSpace(os.Getenv("STACKURITY_ASK_MODEL")),
		Effort:        strings.ToLower(strings.TrimSpace(os.Getenv("STACKURITY_ASK_EFFORT"))),
		NoFallbacks:   strings.EqualFold(strings.TrimSpace(os.Getenv("STACKURITY_ASK_FALLBACKS")), "off"),
	}
	if c.Provider == "" && c.APIKey != "" {
		c.Provider = ProviderAnthropic
	}
	if c.Model == "" {
		c.Model = DefaultModel
	}
	if c.Effort == "" {
		c.Effort = DefaultEffort
	}
	if c.QuestionLimit, err = envInt("STACKURITY_ASK_QUESTIONS_PER_MONTH"); err != nil {
		return c, err
	}
	if c.SpendCapMicros, err = envUSD("STACKURITY_ASK_SPEND_CAP_USD"); err != nil {
		return c, err
	}
	if c.GlobalCapMicros, err = envUSD("STACKURITY_ASK_GLOBAL_SPEND_CAP_USD"); err != nil {
		return c, err
	}
	if c.Prices, err = ParsePrices(os.Getenv("STACKURITY_ASK_PRICES")); err != nil {
		return c, err
	}
	return c, c.Check()
}

// Check reports a configuration that cannot work.
func (c Config) Check() error {
	switch c.Effort {
	case "low", "medium", "high", "xhigh", "max":
	default:
		return fmt.Errorf("STACKURITY_ASK_EFFORT must be low, medium, high, xhigh or max, not %q", c.Effort)
	}
	switch c.Provider {
	case "":
	case ProviderAnthropic:
		if c.APIKey == "" {
			return fmt.Errorf("STACKURITY_ASK_PROVIDER=anthropic needs STACKURITY_ANTHROPIC_API_KEY or STACKURITY_ANTHROPIC_API_KEY_FILE")
		}
	case ProviderBedrock:
		if c.BedrockRegion == "" {
			return fmt.Errorf("STACKURITY_ASK_PROVIDER=bedrock needs STACKURITY_ASK_BEDROCK_REGION")
		}
	case ProviderVertex:
		if c.VertexProject == "" || c.VertexRegion == "" {
			return fmt.Errorf("STACKURITY_ASK_PROVIDER=vertex needs STACKURITY_ASK_VERTEX_PROJECT and STACKURITY_ASK_VERTEX_REGION")
		}
	default:
		return fmt.Errorf("STACKURITY_ASK_PROVIDER must be anthropic, bedrock or vertex, not %q", c.Provider)
	}
	return nil
}

func envOrFile(name string) (string, error) {
	v := os.Getenv(name)
	if f := os.Getenv(name + "_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("read %s_FILE: %w", name, err)
		}
		v = string(b)
	}
	return strings.TrimSpace(v), nil
}

func envInt(name string) (*int64, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return nil, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return nil, fmt.Errorf("%s must be a whole number of 0 or more, not %q", name, v)
	}
	return &n, nil
}

func envUSD(name string) (*int64, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return nil, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 {
		return nil, fmt.Errorf("%s must be an amount in US dollars, not %q", name, v)
	}
	n := int64(f * 1e6)
	return &n, nil
}
