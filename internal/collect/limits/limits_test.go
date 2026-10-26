package limits

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDirSize(t *testing.T) {
	dir := t.TempDir()
	for i, n := range []int{100, 200, 300} {
		if err := os.WriteFile(filepath.Join(dir, string(rune('a'+i))), make([]byte, n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if size, over := DirSize(dir, 0); size != 600 || over {
		t.Errorf("size %d over %v", size, over)
	}
	if _, over := DirSize(dir, 250); !over {
		t.Error("not over 250")
	}
}

// A tool that writes past the limit has its context cancelled with
// ErrTooLarge as the cause.
func TestWatchDirStopsAGrowingTool(t *testing.T) {
	dir := t.TempDir()
	ctx, stop := WatchDir(context.Background(), dir, 1<<20, 10*time.Millisecond, "the clone")
	defer stop()
	if err := os.WriteFile(filepath.Join(dir, "big"), make([]byte, 2<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("not stopped")
	}
	err := Cause(ctx, errors.New("signal: killed"))
	if !errors.Is(err, ErrTooLarge) || err.Error() != "too large: the clone used more than 1 MiB on disk" {
		t.Fatalf("cause: %v", err)
	}
	// Within the limit, the watch never cancels, and stop is not a limit.
	ctx2, stop2 := WatchDir(context.Background(), t.TempDir(), 1<<20, 10*time.Millisecond, "x")
	time.Sleep(50 * time.Millisecond)
	if ctx2.Err() != nil {
		t.Fatal("cancelled within the limit")
	}
	stop2()
	if errors.Is(Cause(ctx2, nil), ErrTooLarge) {
		t.Fatal("stop reported as a limit")
	}
}
