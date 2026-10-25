//go:build !unix

package plugins

import "os/exec"

func killGroup(cmd *exec.Cmd) {}
