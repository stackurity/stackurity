package confcheck

import (
	"os"
	"path/filepath"
	"strings"
)

// within reports whether path p is dir or under it. Both must already have
// their symbolic links resolved.
func within(dir, p string) bool {
	r, err := filepath.Rel(dir, p)
	return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) && !filepath.IsAbs(r)
}

// insideDir resolves the symbolic links of p, a path under dir, and returns
// the result when it stays inside dir: a checked-in .claude -> /root/.claude
// or .github -> /etc must not make the scan read the scanning machine's
// files.
func insideDir(dir, p string) (string, bool) {
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", false
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil || !within(realDir, real) {
		return "", false
	}
	if st, err := os.Lstat(real); err != nil || !st.Mode().IsRegular() {
		return "", false
	}
	return real, true
}
