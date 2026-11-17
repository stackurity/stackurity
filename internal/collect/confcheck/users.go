package confcheck

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// hostFS reads a host's files under Root ("/" for this host, or where a
// host's filesystem is mounted). Paths given to it and reported by it are
// the host's own (/root/.ssh/authorized_keys), never Root-prefixed.
type hostFS struct {
	Root string
	// problems are files that exist but could not be read: the scan is not
	// complete when there are any.
	problems []string
	// realRoot is Root with its links resolved, set on first use.
	realRoot string
}

func (h *hostFS) full(p string) string { return filepath.Join(h.Root, filepath.FromSlash(p)) }

// live reports whether the host is the one the agent runs on, so symbolic
// links can be followed as they are written.
func (h *hostFS) live() bool { return h.Root == "" || h.Root == "/" }

// errOutsideRoot is a host path whose symbolic links lead out of a mounted
// root: its target is the scanning machine's file, not the host's.
var errOutsideRoot = errors.New("leads outside the mounted root")

// resolve returns where host path p is on this machine with every
// symbolic link followed. On a mounted root the result must stay inside
// the root (a link to /root/.claude there names the scanning machine's
// file); on the live host links are followed as they are written.
func (h *hostFS) resolve(p string) (string, error) {
	real, err := filepath.EvalSymlinks(h.full(p))
	if err != nil || h.live() {
		return real, err
	}
	if h.realRoot == "" {
		r, err := filepath.EvalSymlinks(h.Root)
		if err != nil {
			return "", err
		}
		h.realRoot = r
	}
	if !within(h.realRoot, real) {
		return "", errOutsideRoot
	}
	return real, nil
}

// open opens a host file that is a regular file, after resolve, without
// blocking on a FIFO and without following a link swapped in since.
func (h *hostFS) open(p string) (*os.File, error) {
	real, err := h.resolve(p)
	if err != nil {
		return nil, err
	}
	return openRegular(real)
}

// skipped are open errors that mean "not a file to read" rather than "could
// not read it": missing, not a regular file, or a link out of the root.
func skipped(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrInvalid) || errors.Is(err, errNotRegular) ||
		errors.Is(err, errOutsideRoot)
}

// read reads a host file of at most limit bytes. A missing file, or one
// that is not a regular file (a FIFO, a device, a link out of a mounted
// root), is (nil, nil); one that cannot be read or is too big is noted as
// a problem.
func (h *hostFS) read(p string, limit int64) ([]byte, error) {
	f, err := h.open(p)
	if skipped(err) {
		return nil, nil
	}
	if err != nil {
		h.problem(p, "cannot be read")
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		h.problem(p, "cannot be read")
		return nil, err
	}
	if int64(len(data)) > limit {
		h.problem(p, "is larger than "+strconv.FormatInt(limit>>20, 10)+" MiB")
		return nil, errTooBig
	}
	return data, nil
}

var errTooBig = errors.New("file too big")

func (h *hostFS) problem(p, what string) {
	if len(h.problems) < 20 {
		h.problems = append(h.problems, p+" "+what)
	}
}

// exists reports whether a host path exists (without following a final
// symbolic link out of a mounted root).
func (h *hostFS) exists(p string) bool {
	_, err := os.Lstat(h.full(p))
	return err == nil
}

// regular reports whether a host path is a regular file. On a mounted root
// a symbolic link is not followed: its target is the host's, not ours.
func (h *hostFS) regular(p string) (fs.FileInfo, bool) {
	stat := os.Lstat
	if h.live() {
		stat = os.Stat
	}
	st, err := stat(h.full(p))
	if err != nil || !st.Mode().IsRegular() {
		return nil, false
	}
	return st, true
}

// account is a local user who can log in.
type account struct {
	Name string
	UID  int
	Home string
}

// noLogin are shells that refuse an interactive login.
var noLogin = map[string]bool{"/usr/sbin/nologin": true, "/sbin/nologin": true, "/bin/false": true, "/usr/bin/false": true,
	"/bin/sync": true, "/usr/bin/nologin": true, "/sbin/halt": true, "/sbin/shutdown": true, "": false}

// accounts are root and the users with a login shell and a home directory
// (from /etc/passwd), root first.
func (h *hostFS) accounts() []account {
	data, _ := h.read("/etc/passwd", 4<<20)
	out := []account{}
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 7 || strings.HasPrefix(f[0], "#") {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		home, shell := path.Clean(f[5]), strings.TrimSpace(f[6])
		if uid != 0 && (noLogin[shell] || shell == "") {
			continue
		}
		if home == "/" || home == "." || seen[home] || !strings.HasPrefix(home, "/") {
			continue
		}
		seen[home] = true
		a := account{Name: f[0], UID: uid, Home: home}
		if uid == 0 && f[0] == "root" {
			out = append([]account{a}, out...)
			continue
		}
		out = append(out, a)
	}
	if len(out) == 0 || out[0].Name != "root" {
		if !seen["/root"] {
			out = append([]account{{Name: "root", UID: 0, Home: "/root"}}, out...)
		}
	}
	return out
}
