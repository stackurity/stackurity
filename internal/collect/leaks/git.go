package leaks

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Repo scans a project directory. In a Git checkout only the files Git
// tracks are read: a developer's own .env, ignored by Git, is not the
// repository's leak. Elsewhere, or when git cannot list the files, every
// file is read.
func Repo(ctx context.Context, dir string) Result {
	if tracked, ok := trackedFiles(ctx, dir); ok {
		return Dir(ctx, dir, Options{Files: tracked})
	}
	return Dir(ctx, dir, Options{})
}

// trackedFiles lists the files Git tracks under dir, relative to dir.
func trackedFiles(ctx context.Context, dir string) ([]string, bool) {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return nil, false
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, false
	}
	// The checkout may be anyone's (a pull request in CI): its own
	// configuration must not make git run a program. core.fsmonitor is the
	// one ls-files would run; it is turned off. Names come as they are,
	// NUL-separated.
	cmd := exec.CommandContext(ctx, git, "-c", "core.fsmonitor=false", "-c", "core.quotePath=false", "-C", dir,
		"ls-files", "-z", "--cached", "--", ".")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		return nil, false
	}
	files := []string{}
	for _, f := range bytes.Split(out, []byte{0}) {
		if s := strings.TrimSpace(string(f)); s != "" {
			files = append(files, s)
		}
	}
	return files, true
}
