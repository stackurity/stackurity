//go:build windows

package engine

import "github.com/stackurity/stackurity/internal/collect/windows"

// LiveWindowsRegistry is this machine's registry, read-only. It is only
// available on Windows; elsewhere it returns an error.
func LiveWindowsRegistry() (WindowsRegistry, error) { return windows.System{}, nil }
