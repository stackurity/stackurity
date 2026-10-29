package store_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
)

// A pass writes in chunks. When it stops after a chunk, the chunks written
// stay written and the rest keep their old result; the next pass finishes
// the job without rewriting what is already done.
func TestPrioritizeChunksResume(t *testing.T) {
	ctx, s, _ := riskFixture(t)
	old := store.PrioritizeChunk
	store.PrioritizeChunk = 1
	defer func() { store.PrioritizeChunk = old }()
	p1 := risk.DefaultPolicy()
	if n, err := s.Prioritize(ctx, p1, time.Now()); err != nil || n != 4 {
		t.Fatalf("first pass: %d %v", n, err)
	}
	p2 := p1
	p2.EPSSThreshold = 0.2 // a new policy version: every finding is rewritten
	type row struct{ policy, xmin string }
	read := func() map[int64]row {
		t.Helper()
		rows, err := s.Pool.Query(ctx, `SELECT id, priority_policy, xmin::text FROM findings ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[int64]row{}
		for rows.Next() {
			var id int64
			var r row
			if err := rows.Scan(&id, &r.policy, &r.xmin); err != nil {
				t.Fatal(err)
			}
			out[id] = r
		}
		return out
	}
	crash := errors.New("stopped")
	undo := store.SetAfterPriorityChunk(func(n int) error {
		if n == 2 {
			return crash
		}
		return nil
	})
	if _, err := s.Prioritize(ctx, p2, time.Now()); !errors.Is(err, crash) {
		t.Fatalf("interrupted pass: %v", err)
	}
	undo()
	mid := read()
	var done []int64
	for id, r := range mid {
		if r.policy == p2.Version() {
			done = append(done, id)
		} else if r.policy != p1.Version() {
			t.Errorf("finding %d has policy %q", id, r.policy)
		}
	}
	if len(done) != 2 {
		t.Fatalf("after the interruption %d findings have the new policy, want 2", len(done))
	}
	// The resumed pass writes only the other two.
	if n, err := s.Prioritize(ctx, p2, time.Now()); err != nil || n != 4 {
		t.Fatalf("resumed pass: %d %v", n, err)
	}
	after := read()
	for id, r := range after {
		if r.policy != p2.Version() {
			t.Errorf("finding %d not rescored: %q", id, r.policy)
		}
		if slices.Contains(done, id) && r.xmin != mid[id].xmin {
			t.Errorf("finding %d was written twice", id)
		}
	}
	// The chunked pass stores what a single pass does.
	store.PrioritizeChunk = old
	if _, err := s.Prioritize(ctx, p2, time.Now()); err != nil {
		t.Fatal(err)
	}
	for id, r := range read() {
		if r.xmin != after[id].xmin {
			t.Errorf("finding %d rewritten by a pass in one chunk", id)
		}
	}
}
