//go:build unix

package limits

import (
	"os/exec"
	"syscall"
	"time"
)

// KillGroup runs cmd in its own process group, makes cancelling its context
// (a deadline or a size limit) kill the whole group, git's helpers or
// Syft's workers included, and stops waiting for output pipes a few seconds
// after that.
func KillGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
}
