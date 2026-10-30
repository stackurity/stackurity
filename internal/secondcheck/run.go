package secondcheck

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

// DefaultBatch bounds one run: the findings checked per workspace per run.
// Each needs one or two small queries; a run of 500 takes about a
// second on 130,000 findings, and the periodic task runs every minute.
const DefaultBatch = 500

// Runner checks a bounded batch of the caller's workspace's high-impact
// findings that have no current check and records the results. It never
// changes a finding's verification, priority or SOS.
type Runner struct {
	Store *store.Store
	Log   *slog.Logger
	Now   func() time.Time
	Batch int
	// All checks every open finding, not only the high-impact ones.
	All bool
}

// Stats counts one run's results.
type Stats struct {
	Checked, Agreed, Disagreed, CouldNotCheck int
}

func (r *Runner) Run(ctx context.Context) (Stats, error) {
	var st Stats
	batch := r.Batch
	if batch <= 0 {
		batch = DefaultBatch
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	cands, err := r.Store.SecondCheckCandidates(ctx, batch, r.All)
	if err != nil || len(cands) == 0 {
		return st, err
	}
	recCache := map[string][]store.RawAdvisoryRecord{}
	cycleCache := map[string][]store.LifecycleCycle{}
	results := make([]store.SecondCheckResult, 0, len(cands))
	for _, c := range cands {
		var ev map[string]any
		_ = json.Unmarshal(c.Evidence, &ev)
		claim := Claim{Kind: c.Kind, Key: c.Key, Verification: c.Verification, FixedVersion: c.FixedVersion, Sources: c.Sources, Evidence: ev}
		obs := Observed{Purl: c.Purl, Version: c.Version, Evidence: c.InvEvidence}
		var out Outcome
		m, _ := ev["match"].(map[string]any)
		switch {
		case c.Kind == "vulnerability" && m["rule"] == "behind_latest_release":
			// A version behind its release line's latest release, from the
			// lifecycle data rather than an advisory (WordPress core).
			product, _ := ev["product"].(string)
			cycles, ok := cycleCache[product]
			if !ok && product != "" {
				if cycles, err = r.Store.LifecycleCycles(ctx, product); err != nil {
					return st, err
				}
				cycleCache[product] = cycles
			}
			out = CheckBehindRelease(claim, obs, cycles)
		case c.Kind == "vulnerability":
			recs, ok := recCache[c.Key]
			if !ok {
				if recs, err = r.Store.RawAdvisoryRecords(ctx, c.Key, c.Sources); err != nil {
					return st, err
				}
				recCache[c.Key] = recs
			}
			out = CheckVulnerability(claim, obs, recs)
			out.Records = recs
		case c.Kind == "end_of_life":
			product, _ := ev["product"].(string)
			cycles, ok := cycleCache[product]
			if !ok && product != "" {
				if cycles, err = r.Store.LifecycleCycles(ctx, product); err != nil {
					return st, err
				}
				cycleCache[product] = cycles
			}
			out = CheckEndOfLife(claim, obs, cycles, now)
		default:
			continue
		}
		res := store.SecondCheckResult{FindingID: c.FindingID, AssetID: c.AssetID, Basis: c.Basis, Result: out.Result,
			Reason: out.Reason, Differences: out.Differences, Independent: out.Independent,
			Kind: c.Kind, Key: c.Key, Purl: c.Purl, Version: c.Version}
		st.Checked++
		switch out.Result {
		case store.SecondCheckAgreed:
			st.Agreed++
		case store.SecondCheckCouldNotCheck:
			st.CouldNotCheck++
		case store.SecondCheckDisagreed:
			st.Disagreed++
			res.Inputs = disagreementInputs(c, ev, out)
			if r.Log != nil {
				r.Log.Warn("second check disagreed", "finding", c.FindingID, "key", c.Key, "purl", c.Purl, "version", c.Version,
					"reason", out.Reason)
			}
		}
		results = append(results, res)
	}
	_, err = r.Store.RecordSecondChecks(ctx, results)
	return st, err
}

// disagreementInputs is what a corpus case needs: the observation, the
// finding's claim and the raw records both sides read (bounded).
func disagreementInputs(c store.SecondCheckCandidate, ev map[string]any, out Outcome) map[string]any {
	recs := out.Records
	if len(recs) > 20 {
		recs = recs[:20]
	}
	return map[string]any{
		"observed": map[string]any{"purl": c.Purl, "version": c.Version, "evidence": c.InvEvidence, "confidence": c.Confidence,
			"component_type": c.ComponentType},
		"claim": map[string]any{"kind": c.Kind, "key": c.Key, "fixed_version": c.FixedVersion, "sources": c.Sources,
			"verification": c.Verification, "evidence": ev},
		"records": recs,
	}
}
