package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// askConvWithAnswer makes a conversation of user's with a question (seq 1)
// and an answer (seq 2).
func askConvWithAnswer(t *testing.T, s *store.Store, ctx context.Context, user int64, stop string) *store.AskConversation {
	t.Helper()
	c, err := s.CreateAskConversation(ctx, user, nil, "claude-sonnet-5-5", "q")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendAskMessage(ctx, user, c.ID, store.AskMessage{Role: "user", Content: json.RawMessage(`{}`), VisibleText: "Which hosts run openssl 3.0?"}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendAskMessage(ctx, user, c.ID, store.AskMessage{Role: "assistant", Content: json.RawMessage(`{}`), VisibleText: "web-1 and db-1.",
		Model: "claude-sonnet-5-5", StopReason: stop}, 0); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAskFeedbackExplicit(t *testing.T) {
	f := newAskFixture(t)
	c := askConvWithAnswer(t, f.s, f.ws1, f.alice, "end_turn")
	snap := []store.AskSnapshotMessage{{Seq: 1, Role: "user", Text: "Which hosts run openssl 3.0?"}, {Seq: 2, Role: "assistant", Text: "web-1 and db-1."}}
	ws1, _ := tenant.Workspace(f.ws1)
	var call int64
	if err := f.s.Pool.QueryRow(f.ws1, `INSERT INTO ask_api_calls (workspace_id, user_id, conversation_id, kind, model, prompt_version)
		VALUES ($1, $2, $3, 'answer', 'claude-sonnet-5-5', 'v1') RETURNING id`, ws1, f.alice, c.ID).Scan(&call); err != nil {
		t.Fatal(err)
	}

	// A thumbs down with the form, consent given: kept with its snapshot.
	fb, err := f.s.AddAskFeedback(f.ws1, store.AskFeedbackInput{UserID: f.alice, ConversationID: c.ID, Seq: 2, Rating: "down", Category: "wrong",
		Text: "db-1 runs 1.1", Consent: true, Snapshot: snap, PromptVersion: "2026-11-a", Model: "claude-sonnet-5-5", PagePath: "/assets/3", Viewport: "390x844"})
	if err != nil {
		t.Fatal(err)
	}
	if fb.Kind != "explicit" || fb.Scope != "answer" || fb.MessageID == nil || !fb.Consent || !strings.Contains(string(fb.Snapshot), "db-1") || fb.Status != "new" ||
		fb.UsageCallID == nil || *fb.UsageCallID != call {
		t.Fatalf("feedback = %+v", fb)
	}
	// Without consent no snapshot is kept, whatever the caller sends.
	fb, err = f.s.AddAskFeedback(f.ws1, store.AskFeedbackInput{UserID: f.alice, ConversationID: c.ID, Scope: "chat", Category: "slow", Snapshot: snap})
	if err != nil || fb.Snapshot != nil || fb.MessageID != nil {
		t.Fatalf("no consent = %+v %v", fb, err)
	}
	// Another person's conversation, a question's seq, and bad input are refused.
	if _, err := f.s.AddAskFeedback(f.ws1, store.AskFeedbackInput{UserID: f.bob, ConversationID: c.ID, Scope: "chat", Rating: "up"}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another person's conversation: %v", err)
	}
	if _, err := f.s.AddAskFeedback(f.ws2, store.AskFeedbackInput{UserID: f.alice, ConversationID: c.ID, Scope: "chat", Rating: "up"}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another organisation: %v", err)
	}
	if _, err := f.s.AddAskFeedback(f.ws1, store.AskFeedbackInput{UserID: f.alice, ConversationID: c.ID, Seq: 1, Rating: "up"}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a question as the answer: %v", err)
	}
	for _, in := range []store.AskFeedbackInput{
		{UserID: f.alice, ConversationID: c.ID, Seq: 2, Rating: "meh"},
		{UserID: f.alice, ConversationID: c.ID, Seq: 2, Category: "boring"},
		{UserID: f.alice, ConversationID: c.ID, Scope: "page", Rating: "up"},
		{UserID: f.alice, ConversationID: c.ID, Scope: "answer", Rating: "up"},
		{UserID: f.alice, ConversationID: c.ID, Scope: "chat"},
		{UserID: f.alice, ConversationID: c.ID, Scope: "chat", Text: strings.Repeat("x", 2001)},
	} {
		if _, err := f.s.AddAskFeedback(f.ws1, in); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%+v: %v", in, err)
		}
	}
	// Row-level security: the other organisation sees none; the operator's
	// list (system scope) sees both, newest first, and filters.
	var n int
	if err := f.s.Pool.QueryRow(f.ws2, `SELECT count(*) FROM ask_feedback`).Scan(&n); err != nil || n != 0 {
		t.Errorf("other organisation sees %d rows (%v)", n, err)
	}
	all, err := f.s.ListAskFeedback(context.Background(), store.AskFeedbackFilter{})
	if err != nil || len(all) != 2 || all[0].Category != "slow" {
		t.Fatalf("list = %+v %v", all, err)
	}
	down, _ := f.s.ListAskFeedback(context.Background(), store.AskFeedbackFilter{Rating: "down", PromptVersion: "2026-11-a"})
	page, _ := f.s.ListAskFeedback(context.Background(), store.AskFeedbackFilter{Before: all[0].ID, Limit: 1})
	if len(down) != 1 || len(page) != 1 || page[0].ID != all[1].ID {
		t.Errorf("filters: down %d, page %+v", len(down), page)
	}
	// Review.
	st, notes := "triaged", "looking at db-1's inventory"
	got, err := f.s.ReviewAskFeedback(context.Background(), all[1].ID, &st, &notes)
	if err != nil || got.Status != "triaged" || got.ResolutionNotes != notes {
		t.Fatalf("review = %+v %v", got, err)
	}
	bad := "done"
	if _, err := f.s.ReviewAskFeedback(context.Background(), all[1].ID, &bad, nil); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("bad status: %v", err)
	}
	// Deleting the conversation keeps the feedback and its snapshot.
	if err := f.s.DeleteAskConversation(f.ws1, f.alice, c.ID); err != nil {
		t.Fatal(err)
	}
	kept, err := f.s.GetAskFeedback(context.Background(), all[1].ID)
	if err != nil || kept.ConversationID != nil || kept.Snapshot == nil {
		t.Errorf("after the conversation was deleted: %+v %v", kept, err)
	}
}

func TestAskSignalsOnceAndAbandoned(t *testing.T) {
	f := newAskFixture(t)
	c := askConvWithAnswer(t, f.s, f.ws1, f.alice, "end_turn")
	for range 2 {
		if _, err := f.s.AddAskSignal(f.ws1, store.AskSignal{UserID: f.alice, ConversationID: c.ID, Seq: 2, Category: store.AskSignalToolError}); err != nil {
			t.Fatal(err)
		}
	}
	if added, err := f.s.AddAskSignal(f.ws1, store.AskSignal{UserID: f.alice, ConversationID: c.ID, Category: store.AskSignalStopped}); err != nil || !added {
		t.Fatalf("conversation-level signal: %v %v", added, err)
	}
	if _, err := f.s.AddAskSignal(f.ws1, store.AskSignal{UserID: f.bob, ConversationID: c.ID, Category: store.AskSignalStopped}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.AddAskSignal(f.ws1, store.AskSignal{UserID: f.alice, ConversationID: c.ID, Category: "bored"}); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("unknown signal: %v", err)
	}
	rows, _ := f.s.ListAskFeedback(context.Background(), store.AskFeedbackFilter{Kind: "implicit"})
	if len(rows) != 2 {
		t.Fatalf("implicit rows = %+v (once each; nothing for another person's conversation)", rows)
	}
	for _, r := range rows {
		if r.Text != "" || r.Snapshot != nil || r.Rating != nil {
			t.Errorf("implicit row carries content: %+v", r)
		}
	}

	// Abandonment: a refused answer, then quiet for 40 minutes; a good
	// answer quiet as long; a refused answer quiet only 10 minutes; one
	// quiet for 8 hours (judged long ago).
	sys := tenant.System(context.Background())
	refused := askConvWithAnswer(t, f.s, f.ws1, f.alice, "refusal")
	fine := askConvWithAnswer(t, f.s, f.ws1, f.alice, "end_turn")
	recent := askConvWithAnswer(t, f.s, f.ws1, f.alice, "refusal")
	old := askConvWithAnswer(t, f.s, f.ws1, f.alice, "refusal")
	unanswered, _ := f.s.CreateAskConversation(f.ws1, f.alice, nil, "claude-sonnet-5-5", "q")
	_, _ = f.s.AppendAskMessage(f.ws1, f.alice, unanswered.ID, store.AskMessage{Role: "user", Content: json.RawMessage(`{}`), VisibleText: "stopped one"}, 0)
	for id, ago := range map[int64]time.Duration{refused.ID: 40 * time.Minute, fine.ID: 40 * time.Minute, recent.ID: 10 * time.Minute,
		old.ID: 8 * time.Hour, unanswered.ID: time.Hour} {
		if _, err := f.s.Pool.Exec(sys, `UPDATE ask_conversations SET updated_at = now() - make_interval(secs => $2) WHERE id = $1`, id, ago.Seconds()); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if _, err := f.s.DetectAskAbandoned(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	ab, _ := f.s.ListAskFeedback(context.Background(), store.AskFeedbackFilter{Category: store.AskSignalAbandoned})
	got := map[int64]bool{}
	for _, r := range ab {
		got[*r.ConversationID] = true
	}
	if len(ab) != 2 || !got[refused.ID] || !got[unanswered.ID] {
		t.Errorf("abandoned = %v (want the refused one and the unanswered one, once each)", got)
	}
}

func TestAskFeedbackPurge(t *testing.T) {
	f := newAskFixture(t)
	c := askConvWithAnswer(t, f.s, f.ws1, f.alice, "end_turn")
	snap := []store.AskSnapshotMessage{{Seq: 2, Role: "assistant", Text: "web-1"}}
	mk := func() int64 {
		fb, err := f.s.AddAskFeedback(f.ws1, store.AskFeedbackInput{UserID: f.alice, ConversationID: c.ID, Seq: 2, Rating: "down", Category: "wrong",
			Consent: true, Snapshot: snap})
		if err != nil {
			t.Fatal(err)
		}
		return fb.ID
	}
	fresh, aged, ancient := mk(), mk(), mk()
	sys := tenant.System(context.Background())
	for id, days := range map[int64]int{aged: 91, ancient: 366} {
		if _, err := f.s.Pool.Exec(sys, `UPDATE ask_feedback SET created_at = now() - make_interval(days => $2) WHERE id = $1`, id, days); err != nil {
			t.Fatal(err)
		}
	}
	snaps, rows, err := f.s.PurgeAskFeedback(context.Background())
	if err != nil || snaps != 2 || rows != 1 {
		t.Fatalf("purge = %d snapshots, %d rows, %v", snaps, rows, err)
	}
	if fb, _ := f.s.GetAskFeedback(context.Background(), fresh); fb.Snapshot == nil {
		t.Error("a fresh snapshot was removed")
	}
	if fb, _ := f.s.GetAskFeedback(context.Background(), aged); fb == nil || fb.Snapshot != nil || fb.Category != "wrong" {
		t.Errorf("91 days: %+v (row kept, snapshot gone)", fb)
	}
	if _, err := f.s.GetAskFeedback(context.Background(), ancient); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a year old: %v", err)
	}
}

func TestAskFeedbackReviewTokens(t *testing.T) {
	f := newAskFixture(t)
	tok, secret, err := f.s.CreateAskFeedbackReviewToken(context.Background(), "triage bot", f.alice, 24*time.Hour)
	if err != nil || !strings.HasPrefix(secret, store.AskFeedbackReviewTokenKind+"_") || tok.ExpiresAt == nil {
		t.Fatalf("create = %+v %q %v", tok, secret, err)
	}
	if got, err := f.s.AskFeedbackReviewPrincipal(context.Background(), secret); err != nil || got.ID != tok.ID || got.LastUsedAt == nil {
		t.Fatalf("principal = %+v %v", got, err)
	}
	if _, err := f.s.AskFeedbackReviewPrincipal(context.Background(), secret+"x"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("wrong secret: %v", err)
	}
	// The secret is never stored.
	var n int
	if err := f.s.Pool.QueryRow(tenant.System(context.Background()), `SELECT count(*) FROM ask_feedback_review_tokens WHERE token_hash::text LIKE '%' || $1 || '%'`, secret).Scan(&n); err != nil || n != 0 {
		t.Errorf("secret stored: %d %v", n, err)
	}
	// An organisation cannot read the table at all.
	if err := f.s.Pool.QueryRow(f.ws1, `SELECT count(*) FROM ask_feedback_review_tokens`).Scan(&n); err != nil || n != 0 {
		t.Errorf("organisation sees %d tokens (%v)", n, err)
	}
	if err := f.s.RevokeAskFeedbackReviewToken(context.Background(), tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.AskFeedbackReviewPrincipal(context.Background(), secret); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("revoked token: %v", err)
	}
	expired, secret2, _ := f.s.CreateAskFeedbackReviewToken(context.Background(), "old", f.alice, time.Hour)
	if _, err := f.s.Pool.Exec(tenant.System(context.Background()), `UPDATE ask_feedback_review_tokens SET expires_at = now() - interval '1 minute' WHERE id = $1`, expired.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.AskFeedbackReviewPrincipal(context.Background(), secret2); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired token: %v", err)
	}
}
