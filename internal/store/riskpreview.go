package store

import (
	"context"
	"errors"
	"math"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/risk"
)

// RiskPolicyPreview is what a proposed risk policy would do to the
// workspace's open findings, compared with the policy in force. Both sides are
// scored in memory from the same inputs, so every difference comes from the
// policy change alone.
type RiskPolicyPreview struct {
	CurrentVersion  string   `json:"current_version"`
	ProposedVersion string   `json:"proposed_version"`
	ChangedFields   []string `json:"changed_fields"` // top-level policy fields that differ
	// Findings is the number of open findings scored.
	Findings int            `json:"findings"`
	Before   map[string]int `json:"before"` // per priority, P1..P4
	After    map[string]int `json:"after"`
	// SOSBefore and SOSAfter count SOS findings.
	SOSBefore int `json:"sos_before"`
	SOSAfter  int `json:"sos_after"`
	// PriorityChanged counts findings whose priority changes; Raised and
	// Lowered split it by direction. SOSChanged counts findings that gain or
	// lose SOS, ScoreChanged findings whose score moves at all.
	PriorityChanged int `json:"priority_changed"`
	Raised          int `json:"raised"`
	Lowered         int `json:"lowered"`
	SOSChanged      int `json:"sos_changed"`
	ScoreChanged    int `json:"score_changed"`
	// StoredDiffers counts findings whose stored priority is not what the
	// current policy gives today (inputs changed since the last scoring);
	// they move on the next cycle whether or not the policy changes.
	StoredDiffers int `json:"stored_differs"`
	// Sample holds the changed findings with the largest priority moves
	// first, at most SampleLimit of them.
	Sample      []PreviewFinding `json:"sample"`
	SampleLimit int              `json:"sample_limit"`
}

// PreviewFinding is one finding whose priority or SOS changes.
type PreviewFinding struct {
	ID          int64         `json:"id"`
	Key         string        `json:"key"`
	Title       string        `json:"title"`
	AssetID     int64         `json:"asset_id"`
	AssetName   string        `json:"asset_name"`
	Before      string        `json:"before"`
	After       string        `json:"after"`
	ScoreBefore float64       `json:"score_before"`
	ScoreAfter  float64       `json:"score_after"`
	SOSBefore   bool          `json:"sos_before"`
	SOSAfter    bool          `json:"sos_after"`
	Factors     []FactorDelta `json:"factors"` // factors whose points differ
}

// FactorDelta is one risk factor's points under each policy (0 when absent).
type FactorDelta struct {
	Name   string  `json:"name"`
	Before float64 `json:"before"`
	After  float64 `json:"after"`
}

// PreviewSampleLimit bounds the changed findings a preview lists.
const PreviewSampleLimit = 50

var previewRank = map[string]int{"P1": 4, "P2": 3, "P3": 2, "P4": 1}

// PreviewRiskPolicy scores the workspace's open findings under the current
// and the proposed policy and reports the difference. It runs in a read-only
// transaction: nothing is written, whatever happens.
func (s *Store) PreviewRiskPolicy(ctx context.Context, current, proposed risk.Policy, now time.Time) (*RiskPolicyPreview, error) {
	current, proposed = current.Normalize(), proposed.Normalize()
	pv := &RiskPolicyPreview{CurrentVersion: current.Version(), ProposedVersion: proposed.Version(),
		ChangedFields: changedFields(current, proposed), SampleLimit: PreviewSampleLimit,
		Before: map[string]int{"P1": 0, "P2": 0, "P3": 0, "P4": 0}, After: map[string]int{"P1": 0, "P2": 0, "P3": 0, "P4": 0},
		Sample: []PreviewFinding{}}
	var rows []riskRow
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		rows, err = riskRows(ctx, tx, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	var changed []PreviewFinding
	for _, r := range rows {
		b, a := current.Evaluate(r.in), proposed.Evaluate(r.in)
		pv.Findings++
		pv.Before[b.Priority]++
		pv.After[a.Priority]++
		if b.SOS {
			pv.SOSBefore++
		}
		if a.SOS {
			pv.SOSAfter++
		}
		if r.priority != b.Priority {
			pv.StoredDiffers++
		}
		if a.Score != b.Score {
			pv.ScoreChanged++
		}
		prio, sos := a.Priority != b.Priority, a.SOS != b.SOS
		switch {
		case previewRank[a.Priority] > previewRank[b.Priority]:
			pv.Raised++
		case previewRank[a.Priority] < previewRank[b.Priority]:
			pv.Lowered++
		}
		if prio {
			pv.PriorityChanged++
		}
		if sos {
			pv.SOSChanged++
		}
		if !prio && !sos {
			continue
		}
		changed = append(changed, PreviewFinding{ID: r.id, Key: r.key, Title: r.title, AssetID: r.assetID, AssetName: r.assetName,
			Before: b.Priority, After: a.Priority, ScoreBefore: b.Score, ScoreAfter: a.Score, SOSBefore: b.SOS, SOSAfter: a.SOS,
			Factors: factorDeltas(b.Factors, a.Factors)})
	}
	// Largest moves first, then the most urgent result, then SOS changes.
	sort.SliceStable(changed, func(i, j int) bool {
		di := abs(previewRank[changed[i].After] - previewRank[changed[i].Before])
		dj := abs(previewRank[changed[j].After] - previewRank[changed[j].Before])
		if di != dj {
			return di > dj
		}
		if ri, rj := previewRank[changed[i].After], previewRank[changed[j].After]; ri != rj {
			return ri > rj
		}
		return changed[i].ID < changed[j].ID
	})
	if len(changed) > PreviewSampleLimit {
		changed = changed[:PreviewSampleLimit]
	}
	pv.Sample = append(pv.Sample, changed...)
	return pv, nil
}

// PolicyChangeRef says who last changed a policy and when, from the audit log.
type PolicyChangeRef struct {
	At            time.Time `json:"at"`
	ActorType     string    `json:"actor_type"`
	ActorName     string    `json:"actor_name"`
	AfterVersion  string    `json:"version"`
	BeforeVersion string    `json:"previous_version"`
	Changed       []string  `json:"changed"`
}

// LastRiskPolicyChange returns the workspace's latest risk_policy.update
// audit event, or nil when the policy has never been changed.
func (s *Store) LastRiskPolicyChange(ctx context.Context) (*PolicyChangeRef, error) {
	var ref PolicyChangeRef
	err := s.Pool.QueryRow(ctx, `SELECT at, actor_type, actor_name, COALESCE(detail->>'after_version', ''),
		COALESCE(detail->>'before_version', ''), COALESCE(ARRAY(SELECT jsonb_array_elements_text(CASE WHEN jsonb_typeof(detail->'changed') = 'array'
		  THEN detail->'changed' ELSE '[]' END)), '{}')
		FROM audit_events WHERE action = 'risk_policy.update' ORDER BY at DESC, id DESC LIMIT 1`).Scan(
		&ref.At, &ref.ActorType, &ref.ActorName, &ref.AfterVersion, &ref.BeforeVersion, &ref.Changed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ref, nil
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// factorDeltas lists the factors whose points differ between two results, in
// the order the model applies them.
func factorDeltas(before, after []risk.Factor) []FactorDelta {
	var order []string
	b, a := map[string]float64{}, map[string]float64{}
	for _, f := range before {
		if _, ok := b[f.Name]; !ok {
			order = append(order, f.Name)
		}
		b[f.Name] += f.Points
	}
	for _, f := range after {
		if _, ok := b[f.Name]; !ok {
			if _, seen := a[f.Name]; !seen {
				order = append(order, f.Name)
			}
		}
		a[f.Name] += f.Points
	}
	out := []FactorDelta{}
	for _, n := range order {
		if b[n] != a[n] {
			out = append(out, FactorDelta{Name: n, Before: round2(b[n]), After: round2(a[n])})
		}
	}
	return out
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
