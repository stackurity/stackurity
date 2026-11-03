package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Call rows: an organisation sees only its own; the operator sees all; a
// deleted conversation leaves its rows with no conversation.
func TestAskAPICallsScope(t *testing.T) {
	f := newAskFixture(t)
	conv, err := f.s.CreateAskConversation(f.ws1, f.alice, nil, "claude-sonnet-5-5", "t")
	if err != nil {
		t.Fatal(err)
	}
	cid := conv.ID
	if _, err := f.s.RecordAskAPICall(f.ws1, store.AskAPICall{UserID: &f.alice, ConversationID: &cid, Kind: "answer", Model: "claude-sonnet-5-5",
		InputTokens: 100, CostMicros: 7, ToolNames: []string{"list_assets"}, ToolCalls: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RecordAskAPICall(f.ws2, store.AskAPICall{UserID: &f.carol, Kind: "summary", Model: "claude-haiku-5-5"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RecordAskAPICall(f.ws1, store.AskAPICall{Kind: "chat"}); err == nil {
		t.Error("an unknown kind was stored")
	}
	one, err := f.s.ListAskAPICalls(f.ws1, store.AskCallFilter{})
	if err != nil || len(one) != 1 || one[0].ToolNames[0] != "list_assets" || one[0].CostMicros != 7 {
		t.Fatalf("organisation one: %+v %v", one, err)
	}
	all, err := f.s.ListAskAPICalls(tenant.System(context.Background()), store.AskCallFilter{})
	if err != nil || len(all) != 2 {
		t.Fatalf("operator: %d %v", len(all), err)
	}
	if n, cost, err := f.s.AskConversationTotals(f.ws1, f.alice, cid); err != nil || n != 0 || cost != 7 {
		t.Errorf("totals: %d %d %v", n, cost, err)
	}
	if _, _, err := f.s.AskConversationTotals(f.ws1, f.bob, cid); err == nil {
		t.Error("another person read the conversation's totals")
	}
	if err := f.s.DeleteAskConversation(f.ws1, f.alice, cid); err != nil {
		t.Fatal(err)
	}
	if one, _ = f.s.ListAskAPICalls(f.ws1, store.AskCallFilter{}); len(one) != 1 || one[0].ConversationID != nil {
		t.Errorf("after the conversation was deleted: %+v", one)
	}
}

// Housekeeping folds finished days into daily totals, deletes detailed
// rows after 90 days and daily totals after two years, and can run twice.
func TestRollUpAskAPICalls(t *testing.T) {
	f := newAskFixture(t)
	sys := tenant.System(context.Background())
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	ws1, _ := tenant.Workspace(f.ws1)
	at := func(ts time.Time, model string, cost int64, errCode string) {
		t.Helper()
		if _, err := f.s.Pool.Exec(sys, `INSERT INTO ask_api_calls (workspace_id, kind, model, cost_micros, input_tokens, error_code, summary_used, created_at)
			VALUES ($1, 'answer', $2, $3, 10, $4, true, $5)`, ws1, model, cost, errCode, ts); err != nil {
			t.Fatal(err)
		}
	}
	yesterday := now.Add(-24 * time.Hour)
	at(yesterday, "claude-sonnet-5-5", 100, "")
	at(yesterday.Add(time.Hour), "claude-sonnet-5-5", 50, "timeout")
	at(now.Add(-time.Hour), "claude-sonnet-5-5", 999, "")     // today: not rolled up yet
	at(now.Add(-100*24*time.Hour), "claude-opus-5-5", 30, "") // past 90 days, never rolled up
	if _, err := f.s.Pool.Exec(sys, `INSERT INTO ask_api_calls_daily (workspace_id, day, model, kind, calls) VALUES ($1, $2, 'claude-opus-5', 'answer', 1)`,
		ws1, now.Add(-3*365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for run := range 2 {
		deleted, deletedDaily, err := f.s.RollUpAskAPICalls(context.Background(), now)
		if err != nil {
			t.Fatal(err)
		}
		if run == 0 && (deleted != 1 || deletedDaily != 1) {
			t.Errorf("first run deleted %d detailed and %d daily rows", deleted, deletedDaily)
		}
		if run == 1 && (deleted != 0 || deletedDaily != 0) {
			t.Errorf("second run deleted %d and %d", deleted, deletedDaily)
		}
	}
	type day struct {
		calls, errors, summaries int
		cost                     int64
	}
	get := func(d time.Time, model string) (day, bool) {
		var x day
		err := f.s.Pool.QueryRow(sys, `SELECT calls, errors, summaries_used, cost_micros FROM ask_api_calls_daily WHERE workspace_id = $1 AND day = $2 AND model = $3`,
			ws1, d.Format("2006-01-02"), model).Scan(&x.calls, &x.errors, &x.summaries, &x.cost)
		return x, err == nil
	}
	if d, ok := get(yesterday, "claude-sonnet-5-5"); !ok || d != (day{calls: 2, errors: 1, summaries: 2, cost: 150}) {
		t.Errorf("yesterday: %+v %v", d, ok)
	}
	if _, ok := get(now, "claude-sonnet-5-5"); ok {
		t.Error("today was rolled up before it ended")
	}
	if d, ok := get(now.Add(-100*24*time.Hour), "claude-opus-5-5"); !ok || d.cost != 30 {
		t.Errorf("a day rolled up only as its rows were deleted: %+v %v", d, ok)
	}
	var detailed int
	_ = f.s.Pool.QueryRow(sys, `SELECT count(*) FROM ask_api_calls`).Scan(&detailed)
	if detailed != 3 {
		t.Errorf("detailed rows left: %d", detailed)
	}
	// Organisation two cannot see one's totals.
	var seen int
	_ = f.s.Pool.QueryRow(f.ws2, `SELECT count(*) FROM ask_api_calls_daily`).Scan(&seen)
	if seen != 0 {
		t.Errorf("organisation two sees %d daily rows", seen)
	}
}
