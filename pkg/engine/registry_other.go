//go:build !windows

package engine

import "errors"

// LiveWindowsRegistry is this machine's registry, read-only. It is only
// available on Windows; elsewhere it returns an error.
func LiveWindowsRegistry() (WindowsRegistry, error) {
	return nil, errors.New("the Windows registry is only readable on Windows")
}
