//go:build windows

package main

import (
	"context"
	"errors"
	"os"

	"github.com/stackurity/stackurity/internal/collect/windows"
	"github.com/stackurity/stackurity/internal/model"
)

func hostCollector(o *hostOptions) (func(context.Context) ([]*model.ObservationBatch, error), error) {
	if o.root != "/" && o.root != "" {
		return nil, errors.New("--root is not supported on Windows")
	}
	if len(o.appDirs) > 0 || o.discoverApps {
		return nil, errors.New("application scanning is not supported on Windows yet")
	}
	col := &windows.Collector{Reg: windows.System{}, Version: version}
	return func(ctx context.Context) ([]*model.ObservationBatch, error) {
		host, _ := os.Hostname()
		b, err := col.Collect(ctx, host)
		if err != nil {
			return nil, err
		}
		return []*model.ObservationBatch{b}, nil
	}, nil
}
