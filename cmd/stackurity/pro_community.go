//go:build !ee

package main

import (
	"log/slog"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/worker"
)

// The Community build has no paid features to set up; the licensed build
// replaces this file (docs/design/open-core.md).

func proConfig(log *slog.Logger) (api.ProConfig, error) {
	log.Info("Stackurity Community build: automatic fixing, the evidence report and single sign-on are in the licensed build")
	return api.ProConfig{}, nil
}

func registerPro(w *worker.Worker, st *store.Store, log *slog.Logger, gate *license.Gate) {}
