package store_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func configFinding(c, rule, severity string) model.ConfigFinding {
	return model.ConfigFinding{Rule: rule, Category: model.ConfigCI, Title: "t " + c, Severity: severity,
		Path: ".github/workflows/deploy.yml", Line: 9, Subject: "s " + c, Why: "why " + c, Fix: "fix " + c, Fingerprint: fp(c)}
}

func configBatch(name string, complete bool, found ...model.ConfigFinding) *model.ObservationBatch {
	b := batch(mid, true, "pkg:deb/debian/bash@5.2")
	b.Asset.Name = name
	b.ConfigFindings = &model.ConfigScan{Found: found, Complete: complete}
	if !complete {
		b.ConfigFindings.Reason = "/root/.ssh/authorized_keys cannot be read"
	}
	b.ObservedAt = time.Now().UTC()
	if err := b.Validate(); err != nil {
		panic(err)
	}
	return b
}

func configIncident(t *testing.T, s *store.Store, ctx context.Context, assetID int64) *store.SystemIncident {
	t.Helper()
	sys, err := s.DetectSystemProblems(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range sys {
		if sys[i].Kind == "config" && sys[i].Key == "asset:"+strconv.FormatInt(assetID, 10) {
			return &sys[i]
		}
	}
	return nil
}

func TestConfigFindingIngest(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))

	hi := configFinding("a", "gha-pull-request-target-checkout", "high")
	med := configFinding("b", "gha-action-unpinned-secrets", "medium")
	r, err := s.Ingest(ctx, configBatch("web-1", true, hi, med, med), 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.ConfigFound != 3 || r.ConfigGone != 0 {
		t.Errorf("first scan: %+v", r)
	}
	id := r.AssetID
	list, total, err := s.ListConfigFindings(ctx, store.ConfigFindingFilter{AssetID: id})
	if err != nil || total != 2 || list[0].Severity != "high" || list[0].DocURL == "" || list[1].Why != "why b" {
		t.Fatalf("list: %+v %d %v", list, total, err)
	}
	// Only high raises an incident.
	in := configIncident(t, s, ctx, id)
	if in == nil || in.Priority != "P2" || in.Detail["count"] != 1 || in.Detail["why"] != "why a" {
		t.Fatalf("incident: %+v", in)
	}

	// An incomplete scan that misses one does not resolve it.
	if r, err = s.Ingest(ctx, configBatch("web-1", false, med), 0); err != nil || r.ConfigGone != 0 {
		t.Fatalf("incomplete: %+v %v", r, err)
	}
	// A complete one does, and the incident goes with it.
	if r, err = s.Ingest(ctx, configBatch("web-1", true, med), 0); err != nil || r.ConfigGone != 1 {
		t.Fatalf("complete: %+v %v", r, err)
	}
	if in := configIncident(t, s, ctx, id); in != nil {
		t.Errorf("incident after the fix: %+v", in)
	}
	scans, err := s.ConfigScans(ctx, id)
	if err != nil || len(scans) != 1 || !scans[0].Complete || scans[0].Found != 1 {
		t.Errorf("scans: %+v %v", scans, err)
	}

	// Dismissed stays dismissed when seen again; undismiss opens it.
	open, _, _ := s.ListConfigFindings(ctx, store.ConfigFindingFilter{AssetID: id})
	if _, err := s.DismissConfigFinding(ctx, open[0].ID, nil, "known deploy key"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest(ctx, configBatch("web-1", true, med), 0); err != nil {
		t.Fatal(err)
	}
	c, err := s.GetConfigFinding(ctx, open[0].ID)
	if err != nil || c.Resolution != "dismissed" || c.ResolutionNote != "known deploy key" {
		t.Errorf("after a scan: %+v %v", c, err)
	}
	if c, err = s.UndismissConfigFinding(ctx, c.ID); err != nil || c.Status != "open" {
		t.Errorf("undismiss: %+v %v", c, err)
	}
	if _, err := s.UndismissConfigFinding(ctx, c.ID); !errors.Is(err, store.ErrConflict) {
		t.Errorf("undismiss an open one: %v", err)
	}

	sum, err := s.SummariseConfigFindings(ctx, 0)
	if err != nil || sum.BySeverity["medium"] != 1 || sum.ByCategory[model.ConfigCI] != 1 || sum.ScannedAssets != 1 {
		t.Errorf("summary: %+v %v", sum, err)
	}
	if _, _, err := s.ListConfigFindings(ctx, store.ConfigFindingFilter{Severity: "critical"}); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("bad severity: %v", err)
	}
}
