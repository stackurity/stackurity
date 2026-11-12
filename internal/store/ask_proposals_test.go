package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// "Ask may propose changes" (migration 0105): off for the organisations
// that existed when the migration ran, on for those created afterwards.
func TestAskProposeDefault(t *testing.T) {
	f := newAskFixture(t)
	old := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if a, err := f.s.AskSettings(old); err != nil || a.Propose {
		t.Errorf("the organisation that existed before the migration = %+v %v, want off", a, err)
	}
	for _, ctx := range []context.Context{f.ws1, f.ws2} {
		if a, err := f.s.AskSettings(ctx); err != nil || !a.Propose {
			t.Errorf("an organisation created after the migration = %+v %v, want on", a, err)
		}
	}
	if err := f.s.SetAskPropose(f.ws1, false); err != nil {
		t.Fatal(err)
	}
	if a, _ := f.s.AskSettings(f.ws1); a.Propose {
		t.Error("turned off, still on")
	}
	if b, _ := f.s.AskSettings(f.ws2); !b.Propose {
		t.Error("the other organisation changed")
	}
}

func newProposal(t *testing.T, f askFixture, user int64) (*store.AskConversation, *store.AskProposal) {
	t.Helper()
	c, err := f.s.CreateAskConversation(f.ws1, user, nil, "claude-haiku-5-5", "t")
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.s.CreateAskProposal(f.ws1, user, c.ID, store.NewAskProposal{QuestionSeq: 1, Tool: "assign",
		Args: map[string]any{"finding_ids": []int{1}, "assignee": "me"}, Summary: "Assign 1 issue to you", Code: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	return c, p
}

// A proposal is its person's own, is applied at most once (of two clicks
// at the same moment one wins), and cannot be applied after it expires.
func TestAskProposalLifecycle(t *testing.T) {
	f := newAskFixture(t)
	c, p := newProposal(t, f, f.alice)
	if p.Status != "proposed" || p.Code != "abc123" || p.ExpiresAt.Sub(p.CreatedAt) != store.AskProposalTTL {
		t.Fatalf("created = %+v", p)
	}
	// Another person of the same organisation, and another organisation.
	if _, err := f.s.GetAskProposal(f.ws1, f.bob, c.ID, p.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob reads alice's proposal: %v", err)
	}
	if _, err := f.s.ClaimAskProposal(f.ws1, f.bob, c.ID, p.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob claims alice's proposal: %v", err)
	}
	if _, err := f.s.ClaimAskProposal(f.ws2, f.alice, c.ID, p.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("claimed from another organisation: %v", err)
	}
	if _, err := f.s.CreateAskProposal(f.ws1, f.bob, c.ID, store.NewAskProposal{QuestionSeq: 1, Tool: "assign", Args: map[string]any{}, Summary: "x", Code: "x"}); err == nil {
		t.Error("a proposal was stored in another person's conversation")
	}

	var wg sync.WaitGroup
	wins := make(chan int64, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := f.s.ClaimAskProposal(f.ws1, f.alice, c.ID, p.ID); err == nil {
				wins <- got.ID
			} else if !errors.Is(err, store.ErrAskProposalState) {
				t.Errorf("claim: %v", err)
			}
		}()
	}
	wg.Wait()
	close(wins)
	if len(wins) != 1 {
		t.Fatalf("claims won = %d, want 1", len(wins))
	}
	done, err := f.s.FinishAskProposal(f.ws1, p.ID, true, map[string]any{"applied": 1}, "", "/findings/1", nil)
	if err != nil || done.Status != "applied" || done.Link != "/findings/1" || done.CanUndo {
		t.Fatalf("finish = %+v %v", done, err)
	}
	var se *store.AskProposalStateError
	if _, err := f.s.ClaimAskProposal(f.ws1, f.alice, c.ID, p.ID); !errors.As(err, &se) || se.Proposal.Status != "applied" {
		t.Errorf("applied again: %v", err)
	}
	if _, err := f.s.DismissAskProposal(f.ws1, f.alice, c.ID, p.ID); !errors.As(err, &se) {
		t.Errorf("dismissed after apply: %v", err)
	}

	// Expired: still stored, shown as expired, never applied.
	_, q := newProposal(t, f, f.alice)
	if _, err := f.s.Pool.Exec(tenant.System(context.Background()), `UPDATE ask_proposals SET expires_at = now() - interval '1 second' WHERE id = $1`, q.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.ClaimAskProposal(f.ws1, f.alice, q.ConversationID, q.ID); !errors.As(err, &se) || se.Proposal.Status != "expired" {
		t.Errorf("expired proposal claimed: %v", err)
	}

	// A changed preview goes back to proposed with the new code.
	_, r := newProposal(t, f, f.alice)
	if _, err := f.s.ClaimAskProposal(f.ws1, f.alice, r.ConversationID, r.ID); err != nil {
		t.Fatal(err)
	}
	again, err := f.s.ReproposeAskProposal(f.ws1, r.ID, "Assign 2 issues to you", map[string]any{"issues": 2}, nil, "def456")
	if err != nil || again.Status != "proposed" || !again.Changed || again.Code != "def456" {
		t.Fatalf("re-proposed = %+v %v", again, err)
	}
	// Dismissed, and listed with the conversation for History.
	if d, err := f.s.DismissAskProposal(f.ws1, f.alice, r.ConversationID, r.ID); err != nil || d.Status != "dismissed" {
		t.Fatalf("dismiss = %+v %v", d, err)
	}
	if list, err := f.s.AskProposals(f.ws1, f.alice, r.ConversationID); err != nil || len(list) != 1 || list[0].Status != "dismissed" {
		t.Errorf("listed = %+v %v", list, err)
	}
	if list, _ := f.s.AskProposals(f.ws1, f.bob, r.ConversationID); len(list) != 0 {
		t.Errorf("bob lists alice's proposals: %+v", list)
	}
	// Deleted with the conversation.
	if err := f.s.DeleteAskConversation(f.ws1, f.alice, r.ConversationID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.GetAskProposal(f.ws1, f.alice, r.ConversationID, r.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("proposal outlived its conversation: %v", err)
	}
}
