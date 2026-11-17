//go:build unix

package linux

import "golang.org/x/sys/unix"

// fileCaps: the file at path has file capabilities (setcap), which give
// whoever starts it privileges, like setuid.
func fileCaps(path string) bool {
	n, err := unix.Lgetxattr(path, "security.capability", nil)
	return err == nil && n > 0
}
