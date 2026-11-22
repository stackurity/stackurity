//go:build unix

package confcheck

import (
	"errors"
	"os"
	"syscall"
)

// errNotRegular is a path that is not a regular file: a FIFO, a device, a
// directory or a symbolic link.
var errNotRegular = errors.New("not a regular file")

// openRegular opens a regular file for reading without following a final
// symbolic link and without blocking: a FIFO in a user's home (or one
// swapped in after a check) is refused instead of stalling the root agent.
// Same pattern as internal/collect/apps.
func openRegular(name string) (*os.File, error) {
	f, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, errNotRegular
	}
	return f, nil
}
