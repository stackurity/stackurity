//go:build !windows

package main

import "context"

// runAgent runs the agent. Only Windows has a service manager to report to
// (service_windows.go); systemd needs nothing from the process.
func runAgent(ctx context.Context, run func(context.Context) error) error {
	return run(ctx)
}
