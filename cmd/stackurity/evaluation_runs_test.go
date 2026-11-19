package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/intel"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
	"github.com/stackurity/stackurity/internal/worker"
)

// Every evaluation job is recorded with its trigger, counts and sources,
// and a failed one with its error class.
func TestEvaluateJobRecordsRuns(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	sys := tenant.System(context.Background())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eval := &intel.Evaluator{Store: st}

	b := model.NewBatch(model.Collector{ID: "t", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "web-1",
		Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "web-1"}}})
	b.Observations = []model.Observation{{Purl: "pkg:npm/lodash@4.17.15", Confidence: model.ConfidenceConfirmed}}
	b.Complete = true
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	res, err := st.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnsureFeed(sys, "osv:npm", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.FeedResult(sys, "osv:npm", "", 0, nil); err != nil {
		t.Fatal(err)
	}

	payload := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
	if err := evaluateJob(ctx, st, eval, log, payload(map[string]any{"asset_id": res.AssetID})); err != nil {
		t.Fatal(err)
	}
	if err := evaluateJob(ctx, st, eval, log, payload(map[string]any{"component_ids": []int64{1}, "feed": "osv:npm"})); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := evaluateJob(cancelled, st, eval, log, payload(map[string]any{"all": true})); err == nil {
		t.Fatal("a cancelled evaluation succeeded")
	}

	// Another evaluation holds the workspace's lock: the job is deferred,
	// and a deferral is not a run.
	release, err := st.LockEvaluationsWait(ctx, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var deferred *worker.Deferred
	if err := evaluateJob(ctx, st, eval, log, payload(map[string]any{"asset_id": res.AssetID})); !errors.As(err, &deferred) {
		t.Errorf("busy lock: %v, want a deferral", err)
	}
	release()

	runs, err := st.EvaluationRuns(ctx, time.Now().Add(-time.Hour), time.Now().Add(time.Minute), 10)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for i := len(runs) - 1; i >= 0; i-- {
		r := runs[i]
		feeds := ""
		for _, f := range r.Feeds {
			feeds += f.Name
			if f.LastSuccess == nil {
				feeds += "(never)"
			}
		}
		got = append(got, fmt.Sprintf("%s ok=%v %s assets=%d feeds=%s", r.Trigger, r.OK, r.ErrorClass, r.AssetsEvaluated, feeds))
	}
	want := []string{"ingest ok=true  assets=1 feeds=osv:npm", "feed_sync ok=true  assets=1 feeds=osv:npm", "daily ok=false canceled assets=0 feeds=osv:npm"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("runs:\n%q\nwant\n%q", got, want)
	}
}
