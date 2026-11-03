package main

import (
	"context"
	"log/slog"

	"github.com/stackurity/stackurity/internal/ask"
	"github.com/stackurity/stackurity/internal/store"
)

// askEngine sets up Ask Stackurity, the in-app assistant, from the
// STACKURITY_ASK_* and STACKURITY_ANTHROPIC_API_KEY settings
// (internal/ask/config.go). It is off (nil) unless a model provider is
// configured; organisations then still turn it on themselves.
func askEngine(ctx context.Context, st *store.Store, log *slog.Logger) (*ask.Engine, error) {
	cfg, err := ask.FromEnv()
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled() {
		return nil, nil
	}
	client, err := ask.NewClient(ctx, cfg)
	if err != nil {
		return nil, err
	}
	attrs := []any{"provider", cfg.Provider, "default_model", cfg.Model, "effort", cfg.Effort, "server_side_fallback", client.Fallbacks()}
	if cfg.GlobalCapMicros != nil {
		attrs = append(attrs, "monthly_cap_usd", float64(*cfg.GlobalCapMicros)/1e6)
	} else {
		log.Warn("Ask Stackurity has no monthly spend cap for the whole server: set STACKURITY_ASK_GLOBAL_SPEND_CAP_USD")
	}
	log.Info("Ask Stackurity enabled: organisations can turn it on under Settings → AI assistants", attrs...)
	return &ask.Engine{Model: client, Store: st, Prices: ask.Prices{Overrides: cfg.Prices}, Config: cfg, Log: log}, nil
}
