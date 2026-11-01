//go:build linux || darwin || freebsd

package diag

import "syscall"

// diskSpace returns the bytes available to unprivileged users, and the
// size, of the file system holding path.
func diskSpace(path string) (free, total int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), int64(st.Blocks) * int64(st.Bsize), nil
}
