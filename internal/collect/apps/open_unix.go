//go:build unix

package apps

import (
	"errors"
	"os"
	"syscall"
)

// openRegular opens a regular file for reading without following a link
// and without blocking: a file swapped for a FIFO or a link after the walk
// listed it is refused instead of stalling the scan or leaving the root.
func openRegular(name string) (*os.File, error) {
	f, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("not a regular file")
	}
	return f, nil
}
