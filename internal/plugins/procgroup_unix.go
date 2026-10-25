//go:build unix

package plugins

import (
	"os/exec"
	"syscall"
)

// killGroup runs the plugin in its own process group and makes context
// cancellation kill the whole group.
func killGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
