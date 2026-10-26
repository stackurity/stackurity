//go:build !unix

package limits

import (
	"os/exec"
	"time"
)

// KillGroup stops waiting for output pipes a few seconds after cmd's
// context ends; process groups are Unix only.
func KillGroup(cmd *exec.Cmd) { cmd.WaitDelay = 5 * time.Second }
