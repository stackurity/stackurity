package store

// The second check of leaked keys and risky settings (internal/secondcheck,
// migration 0120): each leak and config finding gets a verdict with a
// one-line reason and the version of the rules that gave it. The latest is
// kept on the row (recheck_*); every verdict ever given is kept, append
// only, in second_check_verdicts. See docs/verification.md, "Second check".

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Verdicts of the second check of leaks and config findings.
const (
	VerdictConfirmed           = "confirmed"
	VerdictLikelyFalsePositive = "likely_false_positive"
	VerdictFixed               = "fixed"
	VerdictCouldNotCheck       = "could_not_check"
	// VerdictUnchecked, in a filter, selects rows with no verdict yet.
	VerdictUnchecked = "unchecked"
)

// LeakCheckRules and ConfigCheckRules are the versions of the second
// check's rules for leaks and config findings, stored with each verdict.
// Raise one whenever its rules change: every row is then checked again on
// the next runs, and a changed verdict is added to the history.
const (
	LeakCheckRules   = "leaks/1"
	ConfigCheckRules = "config/1"
)

// recheckInterval is how often a row is checked again when nothing about
// it changed.
const recheckInterval = 24 * time.Hour

// RecheckVerdict is a second check's verdict as shown: on a leak or config
// finding (its latest) and in its history.
type RecheckVerdict struct {
	ID        int64          `json:"id,omitempty"`
	Verdict   string         `json:"verdict"`
	Reason    string         `json:"reason"`
	Checker   string         `json:"checker"`
	CheckedAt time.Time      `json:"checked_at"`
	Inputs    map[string]any `json:"inputs,omitempty"`
}

// ValidVerdictFilter checks a comma-separated second_check filter.
func ValidVerdictFilter(v string) error {
	for _, x := range strings.Split(v, ",") {
		switch x {
		case VerdictConfirmed, VerdictLikelyFalsePositive, VerdictFixed, VerdictCouldNotCheck, VerdictUnchecked:
		default:
			return fmt.Errorf("second_check must be confirmed, likely_false_positive, fixed, could_not_check or unchecked, "+
				"or several comma-separated: %w", ErrInvalid)
		}
	}
	return nil
}

// verdictCond adds the second_check filter for the table alias x.
func verdictCond(w *where, x, v string) {
	var vals []string
	for _, s := range strings.Split(v, ",") {
		if s == VerdictUnchecked {
			s = ""
		}
		vals = append(vals, s)
	}
	w.add(x+".recheck_verdict = ANY(?)", vals)
}

func latestVerdict(verdict, reason, checker string, at *time.Time) *RecheckVerdict {
	if verdict == "" || at == nil {
		return nil
	}
	return &RecheckVerdict{Verdict: verdict, Reason: reason, Checker: checker, CheckedAt: *at}
}

// recheckDue is the condition under which a row (alias x, with its
// collector's last scan as alias sc) is checked again: never checked,
// checked under older rules, seen, resolved or scanned since, or a day ago.
func recheckDue(x, rules string) string {
	return fmt.Sprintf(`(%[1]s.recheck_at IS NULL OR %[1]s.recheck_checker <> '%[2]s' OR %[1]s.recheck_at < %[1]s.last_seen
		OR %[1]s.recheck_at < %[1]s.resolved_at OR %[1]s.recheck_at < sc.scanned_at
		OR %[1]s.recheck_at < now() - interval '%[3]d hours')`, x, rules, int(recheckInterval.Hours()))
}

// RecheckScan is the last scan the collector that found a row made of its
// asset: nil when there is none on record.
type RecheckScan struct {
	Complete  bool      `json:"complete"`
	Reason    string    `json:"reason,omitempty"`
	ScannedAt time.Time `json:"scanned_at"`
}

// LeakRecheckInput is one leak to check, with what the check reads. There
// is no value: only the signals the collector's value check sent.
type LeakRecheckInput struct {
	ID           int64
	AssetID      int64
	AssetKind    string
	Rule         string
	Path         string
	Name         string
	Severity     string
	Exposure     string
	Status       string
	Resolution   string
	ResolvedAt   *time.Time
	LastSeen     time.Time
	ValueChecker string
	ValueSignals []string
	Scan         *RecheckScan
}

// LeakRecheckCandidates returns up to limit leaks due a second check, of
// one asset or (0) all.
func (s *Store) LeakRecheckCandidates(ctx context.Context, assetID int64, limit int) ([]LeakRecheckInput, error) {
	return collectRechecks(ctx, s, `SELECT l.id, l.asset_id, a.kind, l.rule, l.path, l.name, l.severity, l.exposure, l.status,
		  l.resolution, l.resolved_at, l.last_seen, l.value_checker, l.value_signals, sc.complete, sc.reason, sc.scanned_at
		FROM leaks l JOIN assets a ON a.id = l.asset_id AND a.merged_into IS NULL
		LEFT JOIN leak_scans sc ON sc.asset_id = l.asset_id AND sc.collector_id = l.collector_id
		WHERE ($2 = 0 OR l.asset_id = $2) AND `+recheckDue("l", LeakCheckRules)+`
		ORDER BY l.recheck_at NULLS FIRST, l.id LIMIT $1`, limit, assetID,
		func(c *LeakRecheckInput) []any {
			return []any{&c.ID, &c.AssetID, &c.AssetKind, &c.Rule, &c.Path, &c.Name, &c.Severity, &c.Exposure, &c.Status,
				&c.Resolution, &c.ResolvedAt, &c.LastSeen, &c.ValueChecker, &c.ValueSignals}
		},
		func(c *LeakRecheckInput, sc *RecheckScan) { c.Scan = sc })
}

// collectRechecks runs a candidates query whose last three columns are the
// collector's last scan (complete, reason, scanned_at; NULL when none).
func collectRechecks[T any](ctx context.Context, s *Store, sql string, limit int, assetID int64, dest func(*T) []any,
	setScan func(*T, *RecheckScan)) ([]T, error) {
	rows, err := s.Pool.Query(ctx, sql, limit, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		var c T
		var complete *bool
		var reason *string
		var scanned *time.Time
		if err := rows.Scan(append(dest(&c), &complete, &reason, &scanned)...); err != nil {
			return nil, err
		}
		if scanned != nil {
			setScan(&c, &RecheckScan{Complete: complete != nil && *complete, Reason: deref(reason), ScannedAt: *scanned})
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ConfigRecheckInput is one config finding to check, with the evidence the
// collector stored.
type ConfigRecheckInput struct {
	ID         int64
	AssetID    int64
	AssetKind  string
	Rule       string
	Category   string
	Severity   string
	Path       string
	Line       int
	Subject    string
	Why        string
	Status     string
	Resolution string
	ResolvedAt *time.Time
	LastSeen   time.Time
	Scan       *RecheckScan
}

// ConfigRecheckCandidates returns up to limit config findings due a second
// check, of one asset or (0) all.
func (s *Store) ConfigRecheckCandidates(ctx context.Context, assetID int64, limit int) ([]ConfigRecheckInput, error) {
	return collectRechecks(ctx, s, `SELECT c.id, c.asset_id, a.kind, c.rule, c.category, c.severity, c.path, c.line, c.subject,
		  c.why, c.status, c.resolution, c.resolved_at, c.last_seen, sc.complete, sc.reason, sc.scanned_at
		FROM config_findings c JOIN assets a ON a.id = c.asset_id AND a.merged_into IS NULL
		LEFT JOIN config_scans sc ON sc.asset_id = c.asset_id AND sc.collector_id = c.collector_id
		WHERE ($2 = 0 OR c.asset_id = $2) AND `+recheckDue("c", ConfigCheckRules)+`
		ORDER BY c.recheck_at NULLS FIRST, c.id LIMIT $1`, limit, assetID,
		func(c *ConfigRecheckInput) []any {
			return []any{&c.ID, &c.AssetID, &c.AssetKind, &c.Rule, &c.Category, &c.Severity, &c.Path, &c.Line, &c.Subject,
				&c.Why, &c.Status, &c.Resolution, &c.ResolvedAt, &c.LastSeen}
		},
		func(c *ConfigRecheckInput, sc *RecheckScan) { c.Scan = sc })
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// RecheckWaiting reports whether any leak or config finding in the
// caller's workspace is due a second check, so a job is queued only when
// there is work.
func (s *Store) RecheckWaiting(ctx context.Context) (bool, error) {
	var waiting bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM leaks l JOIN assets a ON a.id = l.asset_id AND a.merged_into IS NULL
		  LEFT JOIN leak_scans sc ON sc.asset_id = l.asset_id AND sc.collector_id = l.collector_id WHERE `+recheckDue("l", LeakCheckRules)+`)
		OR EXISTS (SELECT 1 FROM config_findings c JOIN assets a ON a.id = c.asset_id AND a.merged_into IS NULL
		  LEFT JOIN config_scans sc ON sc.asset_id = c.asset_id AND sc.collector_id = c.collector_id WHERE `+recheckDue("c", ConfigCheckRules)+`)`).
		Scan(&waiting)
	return waiting, err
}

// RecheckResult is one verdict to record. ID is the leak's or the config
// finding's.
type RecheckResult struct {
	ID      int64
	AssetID int64
	Verdict string
	Reason  string
	Checker string
	Inputs  map[string]any
}

// RecordLeakRechecks stores leak verdicts: each becomes the leak's latest,
// and one that differs from the latest before it (verdict, reason or
// rules) is added to the history. It returns how many were added.
func (s *Store) RecordLeakRechecks(ctx context.Context, results []RecheckResult) (int, error) {
	return s.recordRechecks(ctx, "leaks", "leak_id", results)
}

// RecordConfigRechecks is RecordLeakRechecks for config findings.
func (s *Store) RecordConfigRechecks(ctx context.Context, results []RecheckResult) (int, error) {
	return s.recordRechecks(ctx, "config_findings", "config_finding_id", results)
}

func (s *Store) recordRechecks(ctx context.Context, table, fk string, results []RecheckResult) (int, error) {
	if len(results) == 0 {
		return 0, nil
	}
	added := 0
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		batch := &pgx.Batch{}
		for _, r := range results {
			inputs, _ := json.Marshal(r.Inputs)
			if r.Inputs == nil {
				inputs = []byte("{}")
			}
			// The asset first, in the order a deletion takes its locks:
			// a row being deleted with its asset is skipped, not failed.
			batch.Queue(`SELECT 1 FROM assets WHERE id = $1 FOR KEY SHARE`, r.AssetID)
			// Every CTE sees the row as it was before the update, so prev
			// is the verdict this one replaces.
			batch.Queue(`WITH prev AS (SELECT recheck_verdict, recheck_reason, recheck_checker FROM `+table+` WHERE id = $1),
				upd AS (UPDATE `+table+` SET recheck_verdict = $2, recheck_reason = $3, recheck_checker = $4, recheck_at = now()
				  WHERE id = $1 RETURNING asset_id)
				INSERT INTO second_check_verdicts (asset_id, `+fk+`, verdict, reason, checker, inputs)
				SELECT upd.asset_id, $1, $2, $3, $4, $5 FROM upd, prev
				WHERE (prev.recheck_verdict, prev.recheck_reason, prev.recheck_checker) IS DISTINCT FROM ($2, $3, $4)`,
				r.ID, r.Verdict, truncateText(r.Reason, 1000), r.Checker, inputs)
		}
		br := tx.SendBatch(ctx, batch)
		for range results {
			if _, err := br.Exec(); err != nil {
				br.Close()
				return err
			}
			tag, err := br.Exec()
			if err != nil {
				br.Close()
				return err
			}
			added += int(tag.RowsAffected())
		}
		return br.Close()
	})
	return added, err
}

// LeakVerdicts returns every second check verdict a leak was given, newest
// first.
func (s *Store) LeakVerdicts(ctx context.Context, leakID int64) ([]RecheckVerdict, error) {
	return s.verdicts(ctx, "leak_id", leakID)
}

// ConfigVerdicts returns every second check verdict a config finding was
// given, newest first.
func (s *Store) ConfigVerdicts(ctx context.Context, id int64) ([]RecheckVerdict, error) {
	return s.verdicts(ctx, "config_finding_id", id)
}

// maxVerdicts bounds a history: a verdict is added only when it changes.
const maxVerdicts = 200

func (s *Store) verdicts(ctx context.Context, fk string, id int64) ([]RecheckVerdict, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, verdict, reason, checker, checked_at, inputs FROM second_check_verdicts
		WHERE `+fk+` = $1 ORDER BY id DESC LIMIT $2`, id, maxVerdicts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RecheckVerdict{}
	for rows.Next() {
		var v RecheckVerdict
		var inputs []byte
		if err := rows.Scan(&v.ID, &v.Verdict, &v.Reason, &v.Checker, &v.CheckedAt, &inputs); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(inputs, &v.Inputs)
		out = append(out, v)
	}
	return out, rows.Err()
}
