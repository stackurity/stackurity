package confcheck

import (
	"bufio"
	"bytes"
	"os"
	"path"
	"strings"
)

// gitTree returns the top of the Git working tree that holds host path p,
// or "" when p is in none. It looks for a .git entry in p's directory and
// each one above it.
func (h *hostFS) gitTree(p string) string {
	dir := path.Dir(path.Clean(p))
	for i := 0; i < 64; i++ {
		if h.exists(path.Join(dir, ".git")) {
			return dir
		}
		if dir == "/" {
			return ""
		}
		dir = path.Dir(dir)
	}
	return ""
}

// gitRemotes are the URLs of a working tree's remotes, with any password
// or token in them masked. A .git file (a linked worktree or a submodule)
// is followed to its Git directory, and a linked worktree to the main
// repository's configuration.
func (h *hostFS) gitRemotes(tree string) []string {
	gitDir := path.Join(tree, ".git")
	if st, ok := h.regular(gitDir); ok && st.Size() < 4096 {
		data, _ := h.read(gitDir, 4096)
		target, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir:")
		if !ok {
			return nil
		}
		target = strings.TrimSpace(target)
		if !path.IsAbs(target) {
			target = path.Join(tree, target)
		}
		gitDir = path.Clean(target)
		if !h.gitDirOK(gitDir) {
			return nil
		}
		if common, _ := h.read(path.Join(gitDir, "commondir"), 4096); len(common) > 0 {
			c := strings.TrimSpace(string(common))
			if !path.IsAbs(c) {
				c = path.Join(gitDir, c)
			}
			gitDir = path.Clean(c)
			if !h.gitDirOK(gitDir) {
				return nil
			}
		}
	}
	data, _ := h.read(path.Join(gitDir, "config"), 1<<20)
	return parseGitRemotes(data)
}

// gitDirOK reports whether a Git directory named by a .git file or a
// commondir file is a directory that, with its links resolved, stays inside
// a mounted root (on the live host links are followed as written).
func (h *hostFS) gitDirOK(dir string) bool {
	real, err := h.resolve(dir)
	if err != nil {
		return false
	}
	st, err := os.Stat(real)
	return err == nil && st.IsDir()
}

// parseGitRemotes reads the url of each [remote "..."] section of a Git
// configuration file.
func parseGitRemotes(data []byte) []string {
	var out []string
	inRemote := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(l, "[") {
			inRemote = strings.HasPrefix(strings.ToLower(l), "[remote ")
			continue
		}
		if !inRemote {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "url") {
			if u := strings.Trim(strings.TrimSpace(v), `"`); u != "" {
				out = append(out, RedactCommand(u))
			}
		}
	}
	return out
}
