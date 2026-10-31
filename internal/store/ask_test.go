package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

type askFixture struct {
	s          *store.Store
	ws1, ws2   context.Context
	alice, bob int64 // both in ws1
	carol      int64 // ws2
}

func newAskFixture(t *testing.T) askFixture {
	t.Helper()
	s := store.New(testdb.New(t))
	bg := context.Background()
	w1, a, err := s.CreateWorkspace(bg, "One", "one", "alice@example.com", "Alice", "pw-alice-123456")
	if err != nil {
		t.Fatal(err)
	}
	w2, c, err := s.CreateWorkspace(bg, "Two", "two", "carol@example.com", "Carol", "pw-carol-123456")
	if err != nil {
		t.Fatal(err)
	}
	ws1 := tenant.WithWorkspace(bg, w1.ID)
	if _, err := s.AddMember(ws1, "bob@example.com", "Bob", auth.RoleViewer, "pw-bob-1234567"); err != nil {
		t.Fatal(err)
	}
	var bob int64
	if err := s.Pool.QueryRow(tenant.System(bg), `SELECT id FROM users WHERE email = 'bob@example.com'`).Scan(&bob); err != nil {
		t.Fatal(err)
	}
	return askFixture{s: s, ws1: ws1, ws2: tenant.WithWorkspace(bg, w2.ID), alice: a.ID, bob: bob, carol: c.ID}
}

func p64(n int64) *int64 { return &n }

func TestAskSettings(t *testing.T) {
	f := newAskFixture(t)
	a, err := f.s.AskSettings(f.ws1)
	if err != nil || !a.Enabled || a.QuestionLimit != nil || a.SpendCapMicros != nil || a.Model != "" {
		t.Fatalf("defaults = %+v %v", a, err)
	}
	ws, _ := tenant.Workspace(f.ws1)
	if err := f.s.SetAskLimits(f.ws1, ws, store.AskLimits{QuestionLimit: p64(20), SpendCapMicros: p64(5_000_000), Model: "claude-sonnet-5-5"}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetAskEnabled(f.ws1, false); err != nil {
		t.Fatal(err)
	}
	a, _ = f.s.AskSettings(f.ws1)
	if a.Enabled || *a.QuestionLimit != 20 || a.QuestionPeriod != "month" || *a.SpendCapMicros != 5_000_000 || a.Model != "claude-sonnet-5-5" {
		t.Errorf("after set = %+v", a)
	}
	if b, _ := f.s.AskSettings(f.ws2); !b.Enabled || b.QuestionLimit != nil {
		t.Errorf("the other workspace changed: %+v", b)
	}
	for _, bad := range []store.AskLimits{{QuestionLimit: p64(-1)}, {SpendCapMicros: p64(-1)}, {Model: "a model; drop"}, {QuestionPeriod: "week"}} {
		if err := f.s.SetAskLimits(f.ws1, ws, bad); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("SetAskLimits(%+v) = %v", bad, err)
		}
	}
}

// Conversations are their owner's only: another member of the same
// organisation, and anyone in another organisation, gets ErrNotFound for
// every read, append and delete, and sees none of them in a list.
func TestAskConversationsArePrivate(t *testing.T) {
	f := newAskFixture(t)
	c, err := f.s.CreateAskConversation(f.ws1, f.alice, nil, "claude-opus-5-5", "Which hosts run openssl 3.0?")
	if err != nil {
		t.Fatal(err)
	}
	// Content is kept byte for byte (tool input keys in their order).
	content := json.RawMessage(`[{"type":"tool_use","id":"t1","name":"search","input":{"query":"openssl","limit":5}}]`)
	if _, err := f.s.AppendAskMessage(f.ws1, f.alice, c.ID, store.AskMessage{Role: "user", Content: json.RawMessage(`[{"type":"text","text":"hi"}]`), VisibleText: "hi",
		Page: json.RawMessage(`{"kind":"finding","id":7}`)}, 0); err != nil {
		t.Fatal(err)
	}
	seq, err := f.s.AppendAskMessage(f.ws1, f.alice, c.ID, store.AskMessage{Role: "assistant", Content: content, Model: "claude-opus-5-5",
		Usage: store.AskTokens{Input: 10, CacheWrite: 20, CacheRead: 30, Output: 40}, CostMicros: 1234, RequestID: "req_1"}, 5000)
	if err != nil || seq != 2 {
		t.Fatalf("append = %d %v", seq, err)
	}
	ms, err := f.s.AskMessages(f.ws1, f.alice, c.ID)
	if err != nil || len(ms) != 2 || ms[0].VisibleText != "hi" || string(ms[1].Content) != string(content) || ms[1].Usage.Output != 40 || ms[1].CostMicros != 1234 {
		t.Fatalf("messages = %+v %v", ms, err)
	}
	if got, _ := f.s.AskConversation(f.ws1, f.alice, c.ID); got.ContextTokens != 5000 || got.ExpiresAt.Sub(got.CreatedAt) != store.AskRetention {
		t.Errorf("conversation = %+v", got)
	}

	for name, try := range map[string]struct {
		ctx  context.Context
		user int64
	}{"bob, same organisation": {f.ws1, f.bob}, "carol, other organisation": {f.ws2, f.carol}, "alice in the other organisation": {f.ws2, f.alice}} {
		if _, err := f.s.AskConversation(try.ctx, try.user, c.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s: read conversation: %v", name, err)
		}
		if _, err := f.s.AskMessages(try.ctx, try.user, c.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s: read messages: %v", name, err)
		}
		if _, err := f.s.AppendAskMessage(try.ctx, try.user, c.ID, store.AskMessage{Role: "user", Content: json.RawMessage(`[]`)}, 0); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s: append: %v", name, err)
		}
		if err := f.s.DeleteAskConversation(try.ctx, try.user, c.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s: delete: %v", name, err)
		}
		if l, err := f.s.ListAskConversations(try.ctx, try.user, 0); err != nil || len(l) != 0 {
			t.Errorf("%s: list = %v %v", name, l, err)
		}
		if n, err := f.s.DeleteAskConversations(try.ctx, try.user); err != nil || n != 0 {
			t.Errorf("%s: delete mine = %d %v", name, n, err)
		}
	}
	if l, _ := f.s.ListAskConversations(f.ws1, f.alice, 0); len(l) != 1 || l[0].Title != "Which hosts run openssl 3.0?" {
		t.Errorf("alice's list = %+v", l)
	}
	// The other organisation's "delete everything" does not reach it.
	if n, err := f.s.DeleteAllAskConversations(f.ws2); err != nil || n != 0 {
		t.Errorf("delete all in ws2 = %d %v", n, err)
	}
	// An admin of the organisation deletes everyone's, learning only how many.
	if _, err := f.s.CreateAskConversation(f.ws1, f.bob, nil, "claude-opus-5-5", "bob's"); err != nil {
		t.Fatal(err)
	}
	if n, err := f.s.DeleteAllAskConversations(f.ws1); err != nil || n != 2 {
		t.Errorf("delete all in ws1 = %d %v", n, err)
	}
	if _, err := f.s.AskConversation(f.ws1, f.alice, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after delete all: %v", err)
	}
}

func TestAskPurge(t *testing.T) {
	f := newAskFixture(t)
	old, _ := f.s.CreateAskConversation(f.ws1, f.alice, nil, "m", "old")
	fresh, _ := f.s.CreateAskConversation(f.ws1, f.alice, nil, "m", "fresh")
	if _, err := f.s.AppendAskMessage(f.ws1, f.alice, old.ID, store.AskMessage{Role: "user", Content: json.RawMessage(`[]`)}, 0); err != nil {
		t.Fatal(err)
	}
	sys := tenant.System(context.Background())
	if _, err := f.s.Pool.Exec(sys, `UPDATE ask_conversations SET created_at = now() - interval '30 days 1 minute' WHERE id = $1`, old.ID); err != nil {
		t.Fatal(err)
	}
	n, err := f.s.PurgeAsk(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("purge = %d %v", n, err)
	}
	var left int
	_ = f.s.Pool.QueryRow(sys, `SELECT count(*) FROM ask_messages WHERE conversation_id = $1`, old.ID).Scan(&left)
	if left != 0 {
		t.Errorf("messages of a purged conversation left: %d", left)
	}
	if _, err := f.s.AskConversation(f.ws1, f.alice, fresh.ID); err != nil {
		t.Errorf("fresh conversation purged: %v", err)
	}
}

func TestAskQuestionQuota(t *testing.T) {
	f := newAskFixture(t)
	for i := int64(1); i <= 2; i++ {
		if n, err := f.s.CountAskQuestion(f.ws1, p64(2), "month"); err != nil || n != i {
			t.Fatalf("question %d = %d %v", i, n, err)
		}
	}
	if _, err := f.s.CountAskQuestion(f.ws1, p64(2), "month"); !errors.Is(err, store.ErrAskQuota) {
		t.Fatalf("over the limit: %v", err)
	}
	if _, err := f.s.CountAskQuestion(f.ws2, p64(0), "month"); !errors.Is(err, store.ErrAskQuota) {
		t.Errorf("limit 0 (not included): %v", err)
	}
	if err := f.s.RefundAskQuestion(f.ws1); err != nil {
		t.Fatal(err)
	}
	if n, err := f.s.CountAskQuestion(f.ws1, p64(2), "month"); err != nil || n != 2 {
		t.Errorf("after a refund = %d %v", n, err)
	}
	if n, err := f.s.CountAskQuestion(f.ws1, nil, "month"); err != nil || n != 3 {
		t.Errorf("no limit = %d %v", n, err)
	}
	if u, err := f.s.AskUsageNow(f.ws1); err != nil || u.Questions != 3 {
		t.Errorf("usage = %+v %v", u, err)
	}
	if u, _ := f.s.AskUsageNow(f.ws2); u.Questions != 0 {
		t.Errorf("ws2 usage = %+v", u)
	}

	// A total allowance (a trial) counts every month, and never renews.
	sys := tenant.System(context.Background())
	ws2, _ := tenant.Workspace(f.ws2)
	if _, err := f.s.Pool.Exec(sys, `INSERT INTO ask_usage (workspace_id, month, questions) VALUES ($1, date_trunc('month', now() - interval '40 days')::date, 9)`, ws2); err != nil {
		t.Fatal(err)
	}
	if n, err := f.s.CountAskQuestion(f.ws2, p64(10), "total"); err != nil || n != 10 {
		t.Errorf("10th of a total of 10 = %d %v", n, err)
	}
	if _, err := f.s.CountAskQuestion(f.ws2, p64(10), "total"); !errors.Is(err, store.ErrAskQuota) {
		t.Errorf("11th of a total of 10: %v", err)
	}
	if n, err := f.s.CountAskQuestion(f.ws2, p64(10), "month"); err != nil || n != 2 {
		t.Errorf("the same usage as a monthly limit = %d %v", n, err)
	}
}

// Organisations that exist when 0067 runs start with the assistant off;
// new ones start with it on.
func TestAskOptInForExistingOrganisations(t *testing.T) {
	f := newAskFixture(t)
	if a, err := f.s.AskSettings(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)); err != nil || a.Enabled {
		t.Errorf("the workspace that existed before the migration = %+v %v", a, err)
	}
	if a, _ := f.s.AskSettings(f.ws1); !a.Enabled {
		t.Error("a workspace created after the migration is off")
	}
}

func TestAskSpendCaps(t *testing.T) {
	f := newAskFixture(t)
	h, err := f.s.HoldAskSpend(f.ws1, 600, p64(1000), nil)
	if err != nil {
		t.Fatal(err)
	}
	// What is held counts: a second call would pass the cap.
	var ce *store.AskSpendCapError
	if _, err := f.s.HoldAskSpend(f.ws1, 500, p64(1000), nil); !errors.As(err, &ce) || ce.Scope != "workspace" || !errors.Is(err, store.ErrAskSpendCap) {
		t.Fatalf("second hold = %v", err)
	}
	lvl, err := f.s.SettleAskSpend(f.ws1, h, 300)
	if err != nil || lvl.WorkspaceSpent != 300 || lvl.GlobalSpent != 300 || *lvl.WorkspaceCap != 1000 {
		t.Fatalf("settle = %+v %v", lvl, err)
	}
	h2, err := f.s.HoldAskSpend(f.ws1, 700, p64(1000), nil)
	if err != nil {
		t.Fatalf("hold within the cap after settling: %v", err)
	}
	if _, err := f.s.SettleAskSpend(f.ws1, h2, 700); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.HoldAskSpend(f.ws1, 1, p64(1000), nil); !errors.As(err, &ce) {
		t.Errorf("at the cap: %v", err)
	}
	// The installation's cap counts every organisation.
	if _, err := f.s.HoldAskSpend(f.ws2, 100, nil, p64(1050)); !errors.As(err, &ce) || ce.Scope != "global" || ce.Spent != 1000 {
		t.Errorf("global cap = %v", err)
	}
	if u, _ := f.s.AskUsageNow(f.ws1); u.CostMicros != 1000 {
		t.Errorf("ws1 spend = %+v", u)
	}

	// Calls made at once never pass a cap together.
	var ok atomic.Int64
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.s.HoldAskSpend(f.ws2, 200, p64(1000), nil); err == nil {
				ok.Add(1)
			} else if !errors.Is(err, store.ErrAskSpendCap) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 5 {
		t.Errorf("concurrent holds granted = %d, want 5", ok.Load())
	}
	// A hold nobody settled stops counting after ten minutes.
	sys := tenant.System(context.Background())
	if _, err := f.s.Pool.Exec(sys, `UPDATE ask_holds SET created_at = now() - interval '11 minutes'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.HoldAskSpend(f.ws2, 1000, p64(1000), nil); err != nil {
		t.Errorf("stale holds still count: %v", err)
	}
}

func TestAskAlertsAndNotice(t *testing.T) {
	f := newAskFixture(t)
	for _, scope := range []string{"workspace", "global"} {
		for _, level := range []int{80, 100} {
			if first, err := f.s.MarkAskAlert(f.ws1, scope, level); err != nil || !first {
				t.Errorf("%s %d first = %v %v", scope, level, first, err)
			}
			if first, err := f.s.MarkAskAlert(f.ws1, scope, level); err != nil || first {
				t.Errorf("%s %d again = %v %v", scope, level, first, err)
			}
		}
	}
	if first, _ := f.s.MarkAskAlert(f.ws2, "workspace", 80); !first {
		t.Error("another organisation's alert was taken as sent")
	}
	if _, err := f.s.MarkAskAlert(f.ws1, "workspace", 50); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("level 50: %v", err)
	}

	if ok, err := f.s.AskNoticeAccepted(f.ws1, f.alice, "2026-11"); err != nil || ok {
		t.Fatalf("before = %v %v", ok, err)
	}
	if err := f.s.AcceptAskNotice(f.ws1, f.alice, "2026-11"); err != nil {
		t.Fatal(err)
	}
	if err := f.s.AcceptAskNotice(f.ws1, f.alice, "2026-11"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.s.AskNoticeAccepted(f.ws1, f.alice, "2026-11"); !ok {
		t.Error("not recorded")
	}
	if ok, _ := f.s.AskNoticeAccepted(f.ws2, f.alice, "2026-11"); ok {
		t.Error("accepted in one organisation counts in another")
	}
	if ok, _ := f.s.AskNoticeAccepted(f.ws1, f.alice, "2027-01"); ok {
		t.Error("a new version counts as accepted")
	}
}
