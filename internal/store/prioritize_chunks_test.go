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

// A chunk is written a while after the pass read its findings. It must not
// rescore a finding resolved in between (which keeps the priority it closed
// with), nor overwrite what an evaluation wrote in between (the evaluation
// rescores the findings it changes, from the new evidence).
func TestPrioritizeChunksDoNotOverwrite(t *testing.T) {
	ctx, s, host := riskFixture(t)
	old := store.PrioritizeChunk
	store.PrioritizeChunk = 1
	defer func() { store.PrioritizeChunk = old }()
	p1 := risk.DefaultPolicy()
	if _, err := s.Prioritize(ctx, p1, time.Now()); err != nil {
		t.Fatal(err)
	}
	var ids []int64
	rows, err := s.Pool.Query(ctx, `SELECT id FROM findings WHERE status = 'open' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id int64
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) != 4 {
		t.Fatalf("%d open findings", len(ids))
	}
	resolved, changed := ids[1], ids[3]
	var wasKEV bool
	if err := s.Pool.QueryRow(ctx, `SELECT COALESCE((evidence->>'known_exploited')::boolean, false) FROM findings WHERE id = $1`, changed).Scan(&wasKEV); err != nil {
		t.Fatal(err)
	}
	xmin := func(id int64) string {
		t.Helper()
		var x string
		if err := s.Pool.QueryRow(ctx, `SELECT xmin::text FROM findings WHERE id = $1`, id).Scan(&x); err != nil {
			t.Fatal(err)
		}
		return x
	}

	p2 := p1
	p2.EPSSThreshold = 0.2 // a new policy version: every open finding is rewritten
	var evaluated string   // the changed finding's row version as the evaluation left it
	done := false
	undo := store.SetAfterPriorityChunk(func(n int) error {
		if done {
			return nil
		}
		done = true
		// After the first chunk: one finding is resolved, and an evaluation
		// changes another's evidence (it becomes known exploited, or stops
		// being) and rescores the asset's findings, as the evaluate job does.
		if _, err := s.Pool.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = now() WHERE id = $1`, resolved); err != nil {
			return err
		}
		if _, err := s.Pool.Exec(ctx, `UPDATE findings SET evidence = evidence || jsonb_build_object('known_exploited', $2::boolean) WHERE id = $1`,
			changed, !wasKEV); err != nil {
			return err
		}
		if _, err := s.PrioritizeAsset(ctx, p2, time.Now(), host); err != nil {
			return err
		}
		evaluated = xmin(changed)
		return nil
	})
	_, err = s.Prioritize(ctx, p2, time.Now())
	undo()
	if err != nil {
		t.Fatal(err)
	}

	var policy string
	if err := s.Pool.QueryRow(ctx, `SELECT priority_policy FROM findings WHERE id = $1`, resolved).Scan(&policy); err != nil {
		t.Fatal(err)
	}
	if policy != p1.Version() {
		t.Errorf("a finding resolved during the pass was rescored (policy %q)", policy)
	}
	if got := xmin(changed); got != evaluated {
		t.Error("the pass overwrote what the evaluation wrote during it")
	}
	var factors string
	if err := s.Pool.QueryRow(ctx, `SELECT priority_factors::text FROM findings WHERE id = $1`, changed).Scan(&factors); err != nil {
		t.Fatal(err)
	}
	if got := slices.Contains(factorNames(t, factors), "Known exploited"); got == wasKEV {
		t.Errorf("the finding changed during the pass is scored from its old evidence: known exploited factor %v", got)
	}
	// The next pass finds nothing to change on it.
	if _, err := s.Prioritize(ctx, p2, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := xmin(changed); got != evaluated {
		t.Error("the next pass rewrote the finding changed during the pass")
	}
}
