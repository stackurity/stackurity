//go:build !unix

package apps

import (
	"errors"
	"os"
)

// openRegular opens a regular file for reading; anything else is refused.
func openRegular(name string) (*os.File, error) {
	if fi, err := os.Lstat(name); err != nil || !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("not a regular file")
	}
	return f, nil
}
