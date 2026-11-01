//go:build !(linux || darwin || freebsd)

package diag

import "errors"

func diskSpace(string) (int64, int64, error) {
	return 0, 0, errors.New("free space is read on Linux, macOS and FreeBSD only")
}
