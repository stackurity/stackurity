package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Threat evidence comes from open config findings of the threat's rules
// and open vulnerability findings of its CVEs (through advisory aliases);
// connections count live assets per kind.
func TestThreatEvidenceAndConnections(t *testing.T) {
	bg := context.Background()
	s := store.New(testdb.New(t))
	sys := tenant.System(bg)
	w1, _, err := s.CreateWorkspace(bg, "One", "one", "alice@example.com", "Alice", "Pw-alice-123456")
	if err != nil {
		t.Fatal(err)
	}
	w2, _, err := s.CreateWorkspace(bg, "Two", "two", "carol@example.com", "Carol", "Pw-carol-123456")
	if err != nil {
		t.Fatal(err)
	}
	ctx := tenant.WithWorkspace(bg, w1.ID)

	if f, a, _, ids, err := s.ThreatEvidence(ctx, []string{"attack-tool-artex"}, []string{"CVE-2024-0099"}, nil); err != nil || f != 0 || a != 0 || len(ids) != 0 {
		t.Fatalf("empty: %d %d %v %v", f, a, ids, err)
	}

	// A server with the tool; both servers report through the agent.
	tool := configFinding("a", "attack-tool-artex", "high")
	r, err := s.Ingest(ctx, configBatch("web-1", true, tool), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(sys, `UPDATE assets SET report_source = 'agent' WHERE id = $1`, r.AssetID); err != nil {
		t.Fatal(err)
	}
	// Another server with a finding of an advisory whose alias is the CVE.
	b := batch([]model.Identifier{{Scheme: "machine-id", Value: "m2"}}, true, "pkg:deb/debian/bash@5.2")
	b.Asset.Name = "db-1"
	r2, err := s.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureFeed(sys, "osv:Debian", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertAdvisories(sys, "osv:Debian", []*osv.Vulnerability{
		{ID: "DSA-9999-1", Aliases: []string{"CVE-2024-0099"}, Modified: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(sys, `INSERT INTO findings (workspace_id, kind, key, inventory_id, asset_id, component_id, status, verification, severity)
		SELECT i.workspace_id, 'vulnerability', 'DSA-9999-1', i.id, i.asset_id, i.component_id, 'open', 'confirmed', 'high'
		FROM inventory i WHERE i.asset_id = $1`, r2.AssetID); err != nil {
		t.Fatal(err)
	}

	f, a, _, ids, err := s.ThreatEvidence(ctx, []string{"attack-tool-artex"}, nil, nil)
	if err != nil || f != 1 || a != 1 || len(ids) != 1 || ids[0] != r.AssetID {
		t.Errorf("rules: %d %d %v %v", f, a, ids, err)
	}
	if f, a, _, _, err = s.ThreatEvidence(ctx, nil, []string{"CVE-2024-0099"}, nil); err != nil || f != 1 || a != 1 {
		t.Errorf("CVE through an alias: %d %d %v", f, a, err)
	}
	if f, a, _, _, err = s.ThreatEvidence(ctx, []string{"attack-tool-artex"}, []string{"CVE-2024-0099"}, nil); err != nil || f != 2 || a != 2 {
		t.Errorf("both: %d %d %v", f, a, err)
	}
	// Another organisation sees none of it.
	if f, _, _, _, err = s.ThreatEvidence(tenant.WithWorkspace(bg, w2.ID), []string{"attack-tool-artex"}, []string{"CVE-2024-0099"}, nil); err != nil || f != 0 {
		t.Errorf("other workspace: %d %v", f, err)
	}

	// A signal rule counts as a signal only.
	if _, _, sig, _, err := s.ThreatEvidence(ctx, nil, nil, []string{"attack-tool-artex"}); err != nil || sig != 1 {
		t.Errorf("signals: %d %v", sig, err)
	}

	// Connections by the collector version of each asset's latest complete
	// collection.
	if _, err := s.Pool.Exec(sys, `UPDATE collections SET collector_version = CASE WHEN asset_id = $1 THEN 'v0.20.17' ELSE '' END`, r.AssetID); err != nil {
		t.Fatal(err)
	}
	vs, err := s.ThreatConnectionVersions(ctx)
	got := map[string]int{}
	for _, v := range vs {
		got[v.Connection+"/"+v.Collector+"@"+v.Version] += v.Assets
	}
	if err != nil || got["host_agent/test@v0.20.17"] != 1 || got["host_agent/test@"] != 1 || len(got) != 2 {
		t.Errorf("connection versions: %v %v", got, err)
	}
}

// A notice is told once; telling again (worsened) restarts every channel's
// delivery and shows a hidden banner again. Dismissals are per person and
// per verdict, and notices stay in their organisation.
func TestThreatNotices(t *testing.T) {
	bg := context.Background()
	s := store.New(testdb.New(t))
	sys := tenant.System(bg)
	w1, alice, err := s.CreateWorkspace(bg, "One", "one", "alice@example.com", "Alice", "Pw-alice-123456")
	if err != nil {
		t.Fatal(err)
	}
	w2, carol, err := s.CreateWorkspace(bg, "Two", "two", "carol@example.com", "Carol", "Pw-carol-123456")
	if err != nil {
		t.Fatal(err)
	}
	ctx, ctx2 := tenant.WithWorkspace(bg, w1.ID), tenant.WithWorkspace(bg, w2.ID)
	if err := s.RecordThreatsSeen(sys, []store.ThreatSeen{{ID: "artex", Name: "ARTEX", Revision: 1, Source: "embedded"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetThreatNotice(ctx, "artex"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no notice yet: %v", err)
	}
	n, err := s.SaveThreatNotice(ctx, store.ThreatNotice{ThreatID: "artex", Verdict: "covered", Connected: map[string]int{"host_agent": 2},
		Missing: []string{"repository"}}, store.NoticeTell)
	if err != nil || n.Verdict != "covered" || n.NotifiedVerdict != "covered" || n.EmailAt != nil || n.Connected["host_agent"] != 2 {
		t.Fatalf("first: %+v %v", n, err)
	}
	if err := s.ThreatNoticeEmailed(ctx, n.ID, "sent", 2); err != nil {
		t.Fatal(err)
	}
	if err := s.ThreatNoticeQueued(ctx, n.ID, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.DismissThreatNotice(ctx, n.ID, alice.ID); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListThreatNotices(ctx, alice.ID)
	if err != nil || len(list) != 1 || !list[0].Dismissed || list[0].EmailResult != "sent" || list[0].ChannelsQueued != 1 {
		t.Fatalf("list: %+v %v", list, err)
	}

	// A quiet change keeps the delivery and the dismissal.
	n, err = s.SaveThreatNotice(ctx, store.ThreatNotice{ThreatID: "artex", Verdict: "needs_connection"}, store.NoticeQuiet)
	if err != nil || n.Verdict != "needs_connection" || n.NotifiedVerdict != "covered" || n.EmailAt == nil {
		t.Fatalf("quiet: %+v %v", n, err)
	}
	// Told again: every channel starts over, the banner shows again.
	n, err = s.SaveThreatNotice(ctx, store.ThreatNotice{ThreatID: "artex", Verdict: "found", Findings: 1, Assets: 1}, store.NoticeTell)
	if err != nil || n.NotifiedVerdict != "found" || n.EmailAt != nil || n.ChannelsAt != nil || n.EmailResult != "" {
		t.Fatalf("worsened: %+v %v", n, err)
	}
	if list, _ := s.ListThreatNotices(ctx, alice.ID); len(list) != 1 || list[0].Dismissed {
		t.Errorf("a found notice shows again: %+v", list)
	}

	// A failed email is tried again until ThreatEmailAttempts.
	for i := 1; i <= store.ThreatEmailAttempts; i++ {
		if err := s.ThreatNoticeEmailed(ctx, n.ID, "failed", 2); err != nil {
			t.Fatal(err)
		}
		got, _ := s.GetThreatNotice(ctx, "artex")
		if (got.EmailAt == nil) != (i < store.ThreatEmailAttempts) || got.EmailAttempts != i {
			t.Fatalf("attempt %d: email_at %v, attempts %d", i, got.EmailAt, got.EmailAttempts)
		}
	}
	// Told again, the email fails once, then fixed: the pending retry
	// (about "found") is given up.
	n, err = s.SaveThreatNotice(ctx, store.ThreatNotice{ThreatID: "artex", Verdict: "found", Findings: 1, Assets: 1}, store.NoticeTell)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ThreatNoticeEmailed(ctx, n.ID, "failed", 2); err != nil {
		t.Fatal(err)
	}
	// Fixed: the told verdict follows quietly, so "found" is news again.
	r, err := s.SaveThreatNotice(ctx, store.ThreatNotice{ThreatID: "artex", Verdict: "covered"}, store.NoticeReset)
	if err != nil || r.NotifiedVerdict != "covered" || !r.BannerAt.Equal(n.BannerAt) || r.EmailAt == nil {
		t.Fatalf("reset: %+v %v", r, err)
	}

	// Other organisations neither see nor hide it.
	if list, err := s.ListThreatNotices(ctx2, carol.ID); err != nil || len(list) != 0 {
		t.Errorf("other organisation sees %+v %v", list, err)
	}
	if err := s.DismissThreatNotice(ctx2, n.ID, carol.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("dismiss from another organisation: %v", err)
	}
	// A person of another organisation cannot be recorded on it.
	if err := s.DismissThreatNotice(ctx, n.ID, carol.ID); err == nil {
		t.Error("dismissal by a non-member")
	}

	// The operator's copy: due once no notice is new, claimed once.
	if _, err := s.SaveThreatNotice(ctx2, store.ThreatNotice{ThreatID: "artex", Verdict: "covered"}, store.NoticeTell); err != nil {
		t.Fatal(err)
	}
	if due, err := s.ThreatCopiesDue(sys, time.Hour); err != nil || len(due) != 0 {
		t.Fatalf("not settled: %+v %v", due, err)
	}
	due, err := s.ThreatCopiesDue(sys, 0)
	if err != nil || len(due) != 1 || due[0].Counts["covered"] != 2 || due[0].Example.Verdict == "" {
		t.Fatalf("due: %+v %v", due, err)
	}
	if ok, err := s.ClaimThreatCopy(sys, "artex", due[0].Counts); err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	if ok, _ := s.ClaimThreatCopy(sys, "artex", due[0].Counts); ok {
		t.Error("claimed twice")
	}
	if due, _ := s.ThreatCopiesDue(sys, 0); len(due) != 0 {
		t.Errorf("due after the claim: %+v", due)
	}
	if err := s.ReleaseThreatCopy(sys, "artex"); err != nil {
		t.Fatal(err)
	}
	if due, _ := s.ThreatCopiesDue(sys, 0); len(due) != 1 {
		t.Errorf("released copy is due again: %+v", due)
	}
}
