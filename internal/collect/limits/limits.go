// Package limits bounds what a scan outside the packs sandbox may use on
// disk while it runs: a git clone, or the image layers Syft downloads.
// Neither git nor Syft has a size limit of its own, so the directory they
// write to is measured while they run and the scan is stopped when it grows
// past the limit.
package limits

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"
)

// ErrTooLarge is the cause of a scan stopped for using too much disk.
var ErrTooLarge = errors.New("too large")

// DirSize returns the bytes held by regular files under dir, stopping early
// (with over true) once the total passes max. Files that vanish while it
// walks are skipped: the tool may be moving them.
func DirSize(dir string, max int64) (size int64, over bool) {
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			size += info.Size()
		}
		if max > 0 && size > max {
			over = true
			return fs.SkipAll
		}
		return nil
	})
	return size, over
}

// WatchDir measures dir every interval while ctx lives and cancels the
// returned context, with a cause wrapping ErrTooLarge, once it holds more
// than max bytes. stop ends the watch; call it when the tool has finished.
func WatchDir(ctx context.Context, dir string, max int64, interval time.Duration, what string) (watched context.Context, stop func()) {
	watched, cancel := context.WithCancelCause(ctx)
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-watched.Done():
				return
			case <-t.C:
				if _, over := DirSize(dir, max); over {
					cancel(fmt.Errorf("%w: %s used more than %s on disk", ErrTooLarge, what, Bytes(max)))
					return
				}
			}
		}
	}()
	return watched, func() {
		close(done)
		cancel(nil)
	}
}

// Cause returns the reason ctx ended when it was a limit, else err.
func Cause(ctx context.Context, err error) error {
	if c := context.Cause(ctx); c != nil && errors.Is(c, ErrTooLarge) {
		return c
	}
	return err
}

// Bytes formats a size the way the limits are configured ("1 GiB").
func Bytes(n int64) string {
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return fmt.Sprintf("%d GiB", n>>30)
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	}
	return fmt.Sprintf("%d bytes", n)
}
