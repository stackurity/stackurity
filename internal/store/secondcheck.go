package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// The second check re-derives high-impact findings from the raw stored
// advisory record and the raw observed version through a separate code path
// (internal/secondcheck), and records the outcome here, apart from
// detection. See docs/verification.md.

// Second check results.
const (
	SecondCheckAgreed        = "agreed"
	SecondCheckDisagreed     = "disagreed"
	SecondCheckCouldNotCheck = "could_not_check"
)

// secondCheckWanted selects the open findings the second check covers. Keep
// it in step with the findings_second_check index (migration 0034).
const secondCheckWanted = `f.status = 'open' AND f.kind IN ('vulnerability', 'end_of_life') AND (
	f.priority = 'P1' OR f.sos OR f.regressed_at IS NOT NULL OR f.verification = 'needs_validation'
	OR (f.evidence->>'known_exploited') = 'true' OR f.evidence->'match' ? 'ambiguous')`

// SecondCheckRules is the version of internal/secondcheck's rules, stored
// with each result (independent.checker). Raise it whenever those rules
// change: every check made under older rules is then redone on the next
// runs, so a false disagreement clears itself (2: kernel source packages).
const SecondCheckRules = 2

// secondCheckMaxAge is how long a check stands when the match has not
// changed: advisory records can change without changing the match.
const secondCheckMaxAge = 7 * 24 * time.Hour

// matchBasis is a SQL expression hashing what a finding claims (kind, key,
// fixed version, sources and evidence without its timestamps) for the
// table alias x, which is findings or want_findings. A check applies only
// while the basis it checked is the finding's basis.
func matchBasis(x string) string {
	return fmt.Sprintf(`md5(%[1]s.kind || '|' || %[1]s.key || '|' || COALESCE(%[1]s.fixed_version, '') || '|' ||
		COALESCE(array_to_string(%[1]s.sources, ','), '') || '|' ||
		COALESCE((CASE WHEN jsonb_typeof(%[1]s.evidence) = 'object' THEN %[1]s.evidence - 'feed_last_success' - 'feed_stale'
		  ELSE %[1]s.evidence END)::text, ''))`, x)
}

// SecondCheckCandidate is one finding to check, with the raw inputs the
// second check reads: the inventory row as observed and the finding's claim.
type SecondCheckCandidate struct {
	FindingID    int64
	AssetID      int64
	Kind         string
	Key          string
	Verification string
	FixedVersion string
	Sources      []string
	Evidence     json.RawMessage // the finding's claim, including "match"
	Basis        string
	// The inventory row as the collector reported it.
	Purl          string
	Version       string
	Confidence    string
	InvEvidence   map[string]string
	ComponentType string
}

// SecondCheckCandidates returns up to limit open high-impact findings in the
// caller's workspace with no current check, most urgent first. all widens
// it to every open vulnerability and end-of-life finding (tests, and
// checking a whole workspace on request).
func (s *Store) SecondCheckCandidates(ctx context.Context, limit int, all bool) ([]SecondCheckCandidate, error) {
	wanted := secondCheckWanted
	if all {
		wanted = `f.status = 'open' AND f.kind IN ('vulnerability', 'end_of_life')`
	}
	rows, err := s.Pool.Query(ctx, `SELECT f.id, f.asset_id, f.kind, f.key, f.verification, f.fixed_version, f.sources, f.evidence,
		  `+matchBasis("f")+`, i.purl, i.version, i.confidence, i.evidence, c.type
		FROM findings f JOIN inventory i ON i.id = f.inventory_id JOIN components c ON c.id = f.component_id
		JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		WHERE `+wanted+`
		  -- NOT IN, not NOT EXISTS: one hashed scan of the (small) checks table
		  -- whatever its statistics say, instead of a nested loop per finding.
		  AND f.id NOT IN (SELECT s.finding_id FROM second_checks s WHERE s.checked_at > now() - make_interval(secs => $2)
		    AND s.independent->>'checker' = $3)
		ORDER BY f.sos DESC, f.priority, f.id LIMIT $1`, limit, secondCheckMaxAge.Seconds(), strconv.Itoa(SecondCheckRules))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecondCheckCandidate
	for rows.Next() {
		var c SecondCheckCandidate
		var inv []byte
		if err := rows.Scan(&c.FindingID, &c.AssetID, &c.Kind, &c.Key, &c.Verification, &c.FixedVersion, &c.Sources, &c.Evidence,
			&c.Basis, &c.Purl, &c.Version, &c.Confidence, &inv, &c.ComponentType); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(inv, &c.InvEvidence)
		out = append(out, c)
	}
	return out, rows.Err()
}

// SecondCheckWaiting reports whether any finding in the caller's workspace
// is waiting for a second check, so a job is queued only when there is work.
func (s *Store) SecondCheckWaiting(ctx context.Context) (bool, error) {
	var waiting bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		WHERE `+secondCheckWanted+`
		  AND f.id NOT IN (SELECT s.finding_id FROM second_checks s WHERE s.checked_at > now() - make_interval(secs => $1)
		    AND s.independent->>'checker' = $2))`,
		secondCheckMaxAge.Seconds(), strconv.Itoa(SecondCheckRules)).Scan(&waiting)
	return waiting, err
}

// RawAdvisoryRecord is one stored affected entry exactly as the feed
// published it (its ranges and listed versions), with its advisory's
// identity.
type RawAdvisoryRecord struct {
	ID        string          `json:"id"`
	GroupKey  string          `json:"group_key"`
	Feed      string          `json:"feed"`
	Withdrawn bool            `json:"withdrawn,omitempty"`
	Ecosystem string          `json:"ecosystem"`
	Name      string          `json:"name"`
	Affected  json.RawMessage `json:"affected"`
}

// RawAdvisoryRecords returns every stored affected entry of the advisories
// in a group (by group key) or named by id, for any package.
func (s *Store) RawAdvisoryRecords(ctx context.Context, key string, ids []string) ([]RawAdvisoryRecord, error) {
	if ids == nil {
		ids = []string{}
	}
	rows, err := s.Pool.Query(ctx, `SELECT a.id, a.group_key, a.feed, a.withdrawn IS NOT NULL, p.ecosystem, p.name, `+affectedColumn+`
		FROM advisories a JOIN advisory_packages p ON p.advisory_id = a.id
		`+affectedJoin+`
		WHERE a.id IN (SELECT id FROM advisories WHERE group_key = $1 UNION SELECT $1 UNION SELECT unnest($2::text[]))
		ORDER BY a.id, p.ecosystem, p.name, p.ctid`, key, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[RawAdvisoryRecord])
}

// SecondCheckDifference is one thing the second check derived differently.
type SecondCheckDifference struct {
	Field       string `json:"field"`       // affected, fixed_version, package, release_line, end_of_life
	Matcher     string `json:"matcher"`     // what the finding claims
	Independent string `json:"independent"` // what the second check derived
	Note        string `json:"note,omitempty"`
}

// SecondCheckResult is the outcome of checking one candidate.
type SecondCheckResult struct {
	FindingID   int64
	AssetID     int64
	Basis       string
	Result      string
	Reason      string
	Differences []SecondCheckDifference
	Independent map[string]any
	// Inputs are logged with a disagreement for corpus work.
	Kind, Key, Purl, Version string
	Inputs                   map[string]any
}

// RecordSecondChecks stores results. A result is dropped when the finding's
// match changed since it was read (the basis differs). A disagreement adds
// a history event and is logged; it never changes the finding's
// verification, priority or SOS (the verifier is deliberately simple, so a
// defect in it must not hide a real issue from urgent alerts). It returns
// the assets with new disagreements.
func (s *Store) RecordSecondChecks(ctx context.Context, results []SecondCheckResult) (changedAssets []int64, err error) {
	seen := map[int64]bool{}
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		// Every result in one round trip; a result whose finding's match
		// changed since it was read inserts nothing.
		batch := &pgx.Batch{}
		diffsOf := make([][]byte, len(results))
		for i, r := range results {
			diffsOf[i], _ = json.Marshal(noNilSlice(r.Differences))
			independent := map[string]any{}
			for k, v := range r.Independent {
				independent[k] = v
			}
			independent["checker"] = SecondCheckRules
			ind, _ := json.Marshal(independent)
			batch.Queue(`INSERT INTO second_checks (finding_id, basis, result, reason, differences, independent, checked_at)
				SELECT f.id, $2, $3, $4, $5, $6, now() FROM findings f WHERE f.id = $1 AND `+matchBasis("f")+` = $2
				ON CONFLICT (finding_id) DO UPDATE SET basis = EXCLUDED.basis, result = EXCLUDED.result, reason = EXCLUDED.reason,
				  differences = EXCLUDED.differences, independent = EXCLUDED.independent, checked_at = EXCLUDED.checked_at`,
				r.FindingID, r.Basis, r.Result, truncateText(r.Reason, 1000), diffsOf[i], ind)
		}
		br := tx.SendBatch(ctx, batch)
		stored := make([]bool, len(results))
		for i := range results {
			tag, err := br.Exec()
			if err != nil {
				br.Close()
				return err
			}
			stored[i] = tag.RowsAffected() > 0
		}
		if err := br.Close(); err != nil {
			return err
		}
		for i, r := range results {
			if !stored[i] || r.Result != SecondCheckDisagreed {
				continue
			}
			diffs := diffsOf[i]
			inputs, _ := json.Marshal(r.Inputs)
			if r.Inputs == nil {
				inputs = []byte("{}")
			}
			if _, err := tx.Exec(ctx, `INSERT INTO second_check_disagreements (finding_id, asset_id, kind, key, purl, version, differences, inputs)
				SELECT $1, asset_id, $2, $3, $4, $5, $6, $7 FROM findings WHERE id = $1`, r.FindingID, r.Kind, r.Key, r.Purl, r.Version, diffs, inputs); err != nil {
				return err
			}
			if !seen[r.AssetID] {
				seen[r.AssetID] = true
				changedAssets = append(changedAssets, r.AssetID)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO finding_events (workspace_id, finding_id, actor_type, actor_name, action, note, detail)
				SELECT workspace_id, id, 'system', 'second check', 'second_check_disagreed', $2, jsonb_build_object('differences', $3::jsonb)
				FROM findings WHERE id = $1`, r.FindingID, truncateText("independent second check disagreed: "+r.Reason, 1000), diffs); err != nil {
				return err
			}
		}
		return nil
	})
	return changedAssets, err
}

func noNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// SecondCheck is a finding's current second check.
type SecondCheck struct {
	Result      string                  `json:"result"`
	Reason      string                  `json:"reason"`
	Differences []SecondCheckDifference `json:"differences"`
	Independent map[string]any          `json:"independent"`
	CheckedAt   time.Time               `json:"checked_at"`
}

// FindingSecondCheck returns the finding's current check, nil when it has
// none (not high impact, or not checked yet).
func (s *Store) FindingSecondCheck(ctx context.Context, findingID int64) (*SecondCheck, error) {
	var c SecondCheck
	var diffs, ind []byte
	err := s.Pool.QueryRow(ctx, `SELECT result, reason, differences, independent, checked_at FROM second_checks WHERE finding_id = $1`,
		findingID).Scan(&c.Result, &c.Reason, &diffs, &ind, &c.CheckedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(diffs, &c.Differences)
	_ = json.Unmarshal(ind, &c.Independent)
	c.Differences = noNilSlice(c.Differences)
	return &c, nil
}

// SecondCheckDisagreement is one logged disagreement.
type SecondCheckDisagreement struct {
	ID          int64                   `json:"id"`
	FindingID   *int64                  `json:"finding_id"`
	Kind        string                  `json:"kind"`
	Key         string                  `json:"key"`
	Purl        string                  `json:"purl"`
	Version     string                  `json:"version"`
	Differences []SecondCheckDifference `json:"differences"`
	Inputs      json.RawMessage         `json:"inputs"`
	CreatedAt   time.Time               `json:"created_at"`
}

// SecondCheckSummary counts the second checks of open findings.
type SecondCheckSummary struct {
	Agreed        int64 `json:"agreed"`
	Disagreed     int64 `json:"disagreed"`
	CouldNotCheck int64 `json:"could_not_check"`
	// Pending counts open findings the check covers that have no current
	// check yet (it runs in the background, a bounded batch a minute).
	Pending int64 `json:"pending"`
	// Logged30d counts disagreements logged in the last 30 days, including
	// those on findings that have since changed or closed.
	Logged30d int64 `json:"logged_30d"`
	// Recent lists the latest logged disagreements (at most 50).
	Recent []SecondCheckDisagreement `json:"recent"`
}

func (s *Store) SummarizeSecondChecks(ctx context.Context) (*SecondCheckSummary, error) {
	sum := &SecondCheckSummary{}
	err := s.Pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE s.result = 'agreed'), count(*) FILTER (WHERE s.result = 'disagreed'),
		count(*) FILTER (WHERE s.result = 'could_not_check')
		FROM second_checks s JOIN findings f ON f.id = s.finding_id JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		WHERE f.status = 'open'`).Scan(&sum.Agreed, &sum.Disagreed, &sum.CouldNotCheck)
	if err != nil {
		return nil, err
	}
	if err := s.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		  WHERE `+secondCheckWanted+` AND f.id NOT IN (SELECT s.finding_id FROM second_checks s)),
		(SELECT count(*) FROM second_check_disagreements WHERE created_at > now() - interval '30 days')`).
		Scan(&sum.Pending, &sum.Logged30d); err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT id, finding_id, kind, key, purl, version, differences, inputs, created_at
		FROM second_check_disagreements ORDER BY created_at DESC, id DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sum.Recent = []SecondCheckDisagreement{}
	for rows.Next() {
		var d SecondCheckDisagreement
		var diffs []byte
		if err := rows.Scan(&d.ID, &d.FindingID, &d.Kind, &d.Key, &d.Purl, &d.Version, &diffs, &d.Inputs, &d.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(diffs, &d.Differences)
		d.Differences = noNilSlice(d.Differences)
		sum.Recent = append(sum.Recent, d)
	}
	return sum, rows.Err()
}

// CountSecondChecks counts second checks of open findings by result in
// every workspace, for /metrics.
func (s *Store) CountSecondChecks(ctx context.Context) (map[string]int64, error) {
	out := map[string]int64{SecondCheckAgreed: 0, SecondCheckDisagreed: 0, SecondCheckCouldNotCheck: 0}
	rows, err := s.Pool.Query(ctx, `SELECT s.result, count(*) FROM second_checks s JOIN findings f ON f.id = s.finding_id
		WHERE f.status = 'open' GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r string
		var n int64
		if err := rows.Scan(&r, &n); err != nil {
			return nil, err
		}
		out[r] = n
	}
	return out, rows.Err()
}

// CountSecondCheckDisagreementsLogged counts every logged disagreement in
// every workspace (a counter for /metrics; rows are never deleted except
// with their workspace).
func (s *Store) CountSecondCheckDisagreementsLogged(ctx context.Context) (int64, error) {
	var n int64
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM second_check_disagreements`).Scan(&n)
	return n, err
}

// InventoryProvenance is where and when a finding's installed version was
// observed.
type InventoryProvenance struct {
	CollectorID string
	Location    string
	Confidence  string
	Evidence    map[string]string
	LastSeen    *time.Time
}

// WhyInputs are what the why-it-matched explanation reads besides the
// finding itself.
type WhyInputs struct {
	Inventory   InventoryProvenance
	Feed        *Feed
	SecondCheck *SecondCheck
	// Covered: the finding is one the second check covers.
	Covered bool
}

// FindingWhyInputs reads the inventory row, the source feed named in the
// evidence (feed, or source for end of life) and the second check.
func (s *Store) FindingWhyInputs(ctx context.Context, f *Finding, feedName string) (*WhyInputs, error) {
	in := &WhyInputs{}
	var ev []byte
	var last time.Time
	err := s.Pool.QueryRow(ctx, `SELECT i.collector_id, i.location, i.confidence, i.evidence, i.last_seen,
		  EXISTS (SELECT 1 FROM findings f WHERE f.id = $2 AND `+secondCheckWanted+`)
		FROM inventory i WHERE i.id = $1`, f.InventoryID, f.ID).
		Scan(&in.Inventory.CollectorID, &in.Inventory.Location, &in.Inventory.Confidence, &ev, &last, &in.Covered)
	if err != nil {
		return nil, notFound(err)
	}
	in.Inventory.LastSeen = &last
	_ = json.Unmarshal(ev, &in.Inventory.Evidence)
	if feedName != "" {
		if fd, err := s.GetFeed(ctx, feedName); err == nil {
			in.Feed = fd
		} else if err != ErrNotFound {
			return nil, err
		}
	}
	if in.SecondCheck, err = s.FindingSecondCheck(ctx, f.ID); err != nil {
		return nil, err
	}
	return in, nil
}
