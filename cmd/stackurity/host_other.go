//go:build !windows && !darwin

package main

import (
	"context"

	"github.com/stackurity/stackurity/internal/model"
)

// hostCollector returns the inventory collector for this platform.
func hostCollector(o *hostOptions) (func(context.Context) ([]*model.ObservationBatch, error), error) {
	return linuxHostCollector(o)
}
