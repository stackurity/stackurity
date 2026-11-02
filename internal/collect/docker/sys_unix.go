//go:build unix

package docker

import "syscall"

const noFollow = syscall.O_NOFOLLOW

// freeBytes is the space an unprivileged user may still write under dir.
func freeBytes(dir string) (int64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return int64(uint64(st.Bavail) * uint64(st.Bsize)), true
}
