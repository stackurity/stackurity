//go:build !unix

package confcheck

import (
	"errors"
	"os"
)

// errNotRegular is a path that is not a regular file.
var errNotRegular = errors.New("not a regular file")

// openRegular opens a regular file for reading; a link or anything else is
// refused.
func openRegular(name string) (*os.File, error) {
	if fi, err := os.Lstat(name); err != nil || !fi.Mode().IsRegular() {
		return nil, errNotRegular
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, errNotRegular
	}
	return f, nil
}
