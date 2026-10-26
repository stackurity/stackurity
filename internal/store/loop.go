package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// This file holds release 0.7's loop: regressed issues, ignore rules
// (scope and expiry), snoozing until a fix ships, check again, and the
// approval inbox for ignore requests. See docs/api.md, "The loop".

// fixedByInventory is true when a resolved finding (alias a) was closed
// because the component was upgraded or removed, not because the
// intelligence changed ("no longer affected (re-evaluated ...)"). Only an
// issue fixed this way can regress.
func fixedByInventory(a string) string {
	return a + `.resolution NOT LIKE 'no longer affected%'`
}

// freeFix is true when finding a has a fixed version that needs no paid
// subscription; the risk model's "fix available" uses the same test.
func freeFix(a string) string {
	return `(` + a + `.fixed_version <> '' AND NOT COALESCE((` + a + `.evidence->>'requires_ubuntu_pro')::boolean, false)
		AND COALESCE(` + a + `.evidence->>'requires_subscription', '') = '')`
}

// twin matches another finding p of the same issue (component and
// advisory) on the same asset as f.
const twin = `p.asset_id = f.asset_id AND p.component_id = f.component_id AND p.key = f.key AND p.kind = f.kind AND p.id <> f.id`

// markRegressed flags the findings SyncFindings has just inserted (first
// seen in this transaction) whose issue was fixed on the asset before the
// new inventory row appeared: an upgrade that left the component
// vulnerable keeps an open or just-resolved twin and is not a regression.
// Findings reopened by the upsert were flagged by it. Both get an event.
func markRegressed(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `UPDATE findings f SET regressed_at = now()
		FROM inventory i
		WHERE f.status = 'open' AND f.first_seen = now() AND f.regressed_at IS NULL AND i.id = f.inventory_id
		  AND EXISTS (SELECT 1 FROM findings p WHERE `+twin+` AND p.status = 'resolved' AND `+fixedByInventory("p")+`
		    AND p.resolved_at < i.first_seen)
		  AND NOT EXISTS (SELECT 1 FROM findings p LEFT JOIN inventory pi ON pi.id = p.inventory_id WHERE `+twin+`
		    AND (p.status = 'open' OR p.resolved_at >= i.first_seen OR pi.removed_at >= i.first_seen))`); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO finding_events (workspace_id, finding_id, actor_type, actor_name, action, note)
		SELECT f.workspace_id, f.id, 'system', 'matcher', 'regressed', 'fixed before and found again on this asset'
		FROM findings f WHERE f.status = 'open' AND f.regressed_at = now()
		  AND f.asset_id IN (SELECT DISTINCT asset_id FROM want_findings)`)
	return err
}

// applyExceptions applies active ignore rules (one rule, or all when ruleID
// is 0) to the open, active findings they cover that no rule has covered
// before, and records an event on each. cond limits the findings (SQL on f).
func applyExceptions(ctx context.Context, db q, ruleID int64, cond string) (int64, error) {
	if cond == "" {
		cond = "true"
	}
	tag, err := db.Exec(ctx, `WITH m AS (
		  SELECT DISTINCT ON (f.id) f.id AS fid, f.state AS from_state, e.id AS rid, e.reason, e.note, e.mitigation,
		    e.expires_at, e.until_fix, e.asset_id IS NULL AS everywhere
		  FROM finding_exceptions e JOIN findings f ON f.component_id = e.component_id AND f.key = e.key AND f.kind = e.kind
		    AND (e.asset_id IS NULL OR f.asset_id = e.asset_id)
		  WHERE e.ended_at IS NULL AND (e.expires_at IS NULL OR e.expires_at > now()) AND ($1::bigint = 0 OR e.id = $1)
		    AND f.status = 'open' AND f.state IN ('new', 'acknowledged', 'in_progress') AND f.exception_id IS DISTINCT FROM e.id
		    AND NOT (e.until_fix AND `+freeFix("f")+`) AND (`+cond+`)
		  ORDER BY f.id, e.created_at DESC),
		u AS (
		  UPDATE findings f SET state = 'risk_accepted', ignore_reason = m.reason, state_reason = m.note, mitigation = m.mitigation,
		    suppressed_until = m.expires_at, until_fix = m.until_fix, exception_id = m.rid,
		    verification_before = CASE WHEN m.reason = 'false_positive' AND f.verification_before = '' THEN f.verification ELSE f.verification_before END,
		    verification = CASE WHEN m.reason = 'false_positive' THEN 'rejected' ELSE f.verification END
		  FROM m WHERE f.id = m.fid
		  RETURNING f.workspace_id, f.id, m.from_state, m.rid, m.reason, m.everywhere)
		INSERT INTO finding_events (workspace_id, finding_id, actor_type, actor_name, action, from_state, to_state, note, detail)
		SELECT workspace_id, id, 'system', 'ignore rule', 'ignored', from_state, 'risk_accepted', 'ignore rule #' || rid,
		  jsonb_build_object('rule_id', rid, 'reason', reason, 'scope', CASE WHEN everywhere THEN 'everywhere' ELSE 'asset' END)
		FROM u`, ruleID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ApplyExceptions applies every active ignore rule to findings it does not
// cover yet (found since, or on assets added since). The dispatcher runs it
// each cycle; SyncFindings applies rules to what it opens right away.
func (s *Store) ApplyExceptions(ctx context.Context) (int64, error) {
	return applyExceptions(ctx, s.Pool, 0, "")
}

// unIgnore is the SET list that returns a finding from an ignore or snooze:
// its expiry, until-fix flag and reason go, and a false positive's
// verification is restored.
const unIgnore = `suppressed_until = NULL, until_fix = false, ignore_reason = '',
	verification = CASE WHEN verification_before <> '' THEN verification_before ELSE verification END, verification_before = ''`

// ExpireSuppressions returns findings to 'new' so they are reviewed again
// when their snooze or acceptance lapses, or, when they wait for a fix,
// when a free fixed version appears. Ignore rules past their expiry end.
func (s *Store) ExpireSuppressions(ctx context.Context) (int64, error) {
	var n int64
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		lapsed, err := tx.Exec(ctx, `WITH o AS (
			  SELECT id, state FROM findings WHERE state IN ('suppressed', 'risk_accepted') AND suppressed_until <= now() FOR UPDATE),
			u AS (UPDATE findings f SET state = 'new', `+unIgnore+` FROM o WHERE f.id = o.id
			  RETURNING f.workspace_id, f.id, o.state AS from_state, f.state_reason)
			INSERT INTO finding_events (workspace_id, finding_id, actor_type, actor_name, action, from_state, to_state, note)
			SELECT workspace_id, id, 'system', 'expiry', 'expired', from_state, 'new', 'expired: ' || state_reason FROM u`)
		if err != nil {
			return err
		}
		shipped, err := tx.Exec(ctx, `WITH o AS (
			  SELECT f.id, f.state FROM findings f WHERE f.state IN ('suppressed', 'risk_accepted') AND f.until_fix
			    AND f.status = 'open' AND `+freeFix("f")+` FOR UPDATE),
			u AS (UPDATE findings f SET state = 'new', `+unIgnore+` FROM o WHERE f.id = o.id
			  RETURNING f.workspace_id, f.id, o.state AS from_state, f.fixed_version)
			INSERT INTO finding_events (workspace_id, finding_id, actor_type, actor_name, action, from_state, to_state, note)
			SELECT workspace_id, id, 'system', 'expiry', 'fix_available', from_state, 'new', 'a fixed version is available: ' || fixed_version FROM u`)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE finding_exceptions SET ended_at = now(), ended_by_name = 'expiry', ended_reason = 'expired'
			WHERE ended_at IS NULL AND expires_at <= now()`); err != nil {
			return err
		}
		n = lapsed.RowsAffected() + shipped.RowsAffected()
		return nil
	})
	return n, err
}

// --- ignore: reasons, scopes and expiries

// Ignore reasons.
const (
	ReasonAcceptedRisk  = "accepted_risk"
	ReasonFalsePositive = "false_positive"
	ReasonMitigated     = "mitigated"
	ReasonNoFix         = "no_fix"
)

// Ignore scopes and expiries.
const (
	ScopeAsset       = "asset"
	ScopeEverywhere  = "everywhere"
	ExpiryDate       = "date"
	ExpiryUntilFix   = "until_fix"
	ExpiryNever      = "never"
	appliedNote      = "applied, waiting for a check"
	checkExpiryDays  = 7
	maxRequestIssues = 2000
)

var ignoreReasons = map[string]bool{ReasonAcceptedRisk: true, ReasonFalsePositive: true, ReasonMitigated: true, ReasonNoFix: true}

// IgnoreSpec is how to ignore issues: why, where and until when.
type IgnoreSpec struct {
	Reason     string     `json:"reason"`
	Scope      string     `json:"scope"`  // asset or everywhere
	Expiry     string     `json:"expiry"` // date, until_fix or never
	Until      *time.Time `json:"until"`  // the date, for expiry date
	Note       string     `json:"note"`
	Mitigation string     `json:"mitigation"`
}

// resolve validates the spec and returns when the ignore lapses: the date,
// the exception limit as a backstop when it waits for a fix, or nil for
// never (false positives only).
func (sp *IgnoreSpec) resolve(maxDays int, now time.Time) (*time.Time, error) {
	if maxDays <= 0 {
		maxDays = DefaultExceptionMaxDays
	}
	if !ignoreReasons[sp.Reason] {
		return nil, fmt.Errorf("%w: reason must be accepted_risk, false_positive, mitigated or no_fix", ErrInvalidAction)
	}
	if sp.Scope == "" {
		sp.Scope = ScopeAsset
	}
	if sp.Scope != ScopeAsset && sp.Scope != ScopeEverywhere {
		return nil, fmt.Errorf("%w: scope must be asset or everywhere", ErrInvalidAction)
	}
	if strings.TrimSpace(sp.Note) == "" {
		return nil, fmt.Errorf("%w: a reason is required", ErrInvalidAction)
	}
	limit := now.AddDate(0, 0, maxDays)
	switch sp.Expiry {
	case ExpiryDate:
		if sp.Until == nil || !sp.Until.After(now) || sp.Until.After(limit) {
			return nil, fmt.Errorf("%w: an expiry within the next %d days is required", ErrInvalidAction, maxDays)
		}
		u := *sp.Until
		return &u, nil
	case ExpiryUntilFix:
		return &limit, nil
	case ExpiryNever:
		if sp.Reason != ReasonFalsePositive {
			return nil, fmt.Errorf("%w: only a false positive can be ignored with no expiry; choose a date or until a fix ships (at most %d days)", ErrInvalidAction, maxDays)
		}
		return nil, nil
	}
	return nil, fmt.Errorf("%w: expiry must be date, until_fix or never", ErrInvalidAction)
}

// ignoreFinding ignores finding id inside tx: it records a rule for the
// issue on the finding's asset or everywhere (ending an earlier rule with
// the same scope), applies it to the finding, then to every other finding
// the rule covers. It returns the rule id.
func ignoreFinding(ctx context.Context, tx pgx.Tx, id int64, sp IgnoreSpec, expires *time.Time, actor Actor, requestID int64) (int64, error) {
	var kind, key string
	var assetID, componentID int64
	var hasFix bool
	if err := tx.QueryRow(ctx, `SELECT f.kind, f.key, f.asset_id, f.component_id, `+freeFix("f")+` FROM findings f WHERE f.id = $1`, id).
		Scan(&kind, &key, &assetID, &componentID, &hasFix); err != nil {
		return 0, notFound(err)
	}
	if sp.Expiry == ExpiryUntilFix && hasFix {
		return 0, fmt.Errorf("%w: a fixed version already exists; install it, or choose a date", ErrInvalidAction)
	}
	var scopeAsset *int64
	if sp.Scope == ScopeAsset {
		scopeAsset = &assetID
	}
	rows, err := tx.Query(ctx, `UPDATE finding_exceptions SET ended_at = now(), ended_by_name = $5, ended_reason = 'replaced'
		WHERE ended_at IS NULL AND kind = $1 AND key = $2 AND component_id = $3 AND asset_id IS NOT DISTINCT FROM $4 RETURNING id`,
		kind, key, componentID, scopeAsset, actor.Name)
	if err != nil {
		return 0, err
	}
	replaced, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return 0, err
	}
	var req *int64
	if requestID > 0 {
		req = &requestID
	}
	var rule int64
	if err := tx.QueryRow(ctx, `INSERT INTO finding_exceptions (kind, key, component_id, asset_id, reason, note, mitigation, expires_at,
		until_fix, created_by, created_by_name, request_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
		kind, key, componentID, scopeAsset, sp.Reason, sp.Note, sp.Mitigation, expires, sp.Expiry == ExpiryUntilFix,
		userIDOnly(actor), actor.Name, req).Scan(&rule); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE findings SET state = 'risk_accepted', ignore_reason = $2, state_reason = $3, mitigation = $4,
		suppressed_until = $5, until_fix = $6, exception_id = $7,
		verification_before = CASE WHEN $2 = 'false_positive' AND verification_before = '' THEN verification ELSE verification_before END,
		verification = CASE WHEN $2 = 'false_positive' THEN 'rejected' ELSE verification END
		WHERE id = $1`, id, sp.Reason, sp.Note, sp.Mitigation, expires, sp.Expiry == ExpiryUntilFix, rule); err != nil {
		return 0, err
	}
	// What the replaced rules ignored now follows the new one.
	if len(replaced) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE findings SET ignore_reason = $2, state_reason = $3, mitigation = $4,
			suppressed_until = $5, until_fix = $6, exception_id = $7,
			verification_before = CASE WHEN $2 = 'false_positive' AND verification_before = '' THEN verification
			  WHEN $2 <> 'false_positive' THEN '' ELSE verification_before END,
			verification = CASE WHEN $2 = 'false_positive' THEN 'rejected'
			  WHEN verification_before <> '' THEN verification_before ELSE verification END
			WHERE exception_id = ANY($1) AND state = 'risk_accepted'`, replaced, sp.Reason, sp.Note, sp.Mitigation, expires,
			sp.Expiry == ExpiryUntilFix, rule); err != nil {
			return 0, err
		}
	}
	if _, err := applyExceptions(ctx, tx, rule, ""); err != nil {
		return 0, err
	}
	return rule, nil
}

// IgnoreRule is an ignore decision for one issue on one asset or everywhere.
type IgnoreRule struct {
	ID            int64      `json:"id"`
	Kind          string     `json:"kind"`
	Key           string     `json:"key"`
	ComponentID   int64      `json:"component_id"`
	ComponentName string     `json:"component_name"`
	AssetID       *int64     `json:"asset_id"` // null: every asset
	AssetName     string     `json:"asset_name"`
	Scope         string     `json:"scope"`
	Reason        string     `json:"reason"`
	Note          string     `json:"note"`
	Mitigation    string     `json:"mitigation"`
	ExpiresAt     *time.Time `json:"expires_at"`
	UntilFix      bool       `json:"until_fix"`
	CreatedByName string     `json:"created_by"`
	RequestID     *int64     `json:"request_id"`
	CreatedAt     time.Time  `json:"created_at"`
	EndedAt       *time.Time `json:"ended_at"`
	EndedByName   string     `json:"ended_by"`
	EndedReason   string     `json:"ended_reason"`
	// Findings counts the open findings the rule ignores now.
	Findings int64 `json:"findings"`
}

const ruleCols = `e.id, e.kind, e.key, e.component_id, CASE WHEN c.namespace = '' THEN c.name ELSE c.namespace || '/' || c.name END,
	e.asset_id, COALESCE(a.name, ''), CASE WHEN e.asset_id IS NULL THEN 'everywhere' ELSE 'asset' END, e.reason, e.note, e.mitigation,
	e.expires_at, e.until_fix, e.created_by_name, e.request_id, e.created_at, e.ended_at, e.ended_by_name, e.ended_reason,
	(SELECT count(*) FROM findings f WHERE f.exception_id = e.id AND f.status = 'open' AND f.state = 'risk_accepted')`

const ruleFrom = ` FROM finding_exceptions e JOIN components c ON c.id = e.component_id LEFT JOIN assets a ON a.id = e.asset_id`

// ListIgnoreRules lists ignore rules, the active ones (all false) or every one.
func (s *Store) ListIgnoreRules(ctx context.Context, all bool, p Page) ([]IgnoreRule, int64, error) {
	w := &where{}
	if !all {
		w.conds = append(w.conds, "e.ended_at IS NULL")
	}
	var total int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM finding_exceptions e`+w.sql(), w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	p = p.norm()
	rows, err := s.Pool.Query(ctx, `SELECT `+ruleCols+ruleFrom+w.sql()+fmt.Sprintf(` ORDER BY e.created_at DESC, e.id DESC LIMIT %d OFFSET %d`, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[IgnoreRule])
	return out, total, err
}

// EndIgnoreRule ends a rule: the findings it ignores return to new.
func (s *Store) EndIgnoreRule(ctx context.Context, id int64, actor Actor) (int64, error) {
	var n int64
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE finding_exceptions SET ended_at = now(), ended_by_name = $2, ended_reason = 'ended'
			WHERE id = $1 AND ended_at IS NULL`, id, actor.Name)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM finding_exceptions WHERE id = $1)`, id).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return ErrNotFound
			}
			return fmt.Errorf("%w: the rule has already ended", ErrConflict)
		}
		// Fixed findings it covered lose the ignore quietly, so they do not
		// stay ignored if they come back.
		if _, err := tx.Exec(ctx, `UPDATE findings SET state = 'new', `+unIgnore+`
			WHERE exception_id = $1 AND state = 'risk_accepted' AND status = 'resolved'`, id); err != nil {
			return err
		}
		res, err := tx.Exec(ctx, `WITH u AS (UPDATE findings SET state = 'new', `+unIgnore+`
			  WHERE exception_id = $1 AND state = 'risk_accepted' AND status = 'open' RETURNING workspace_id, id)
			INSERT INTO finding_events (workspace_id, finding_id, actor_type, actor_id, actor_name, action, from_state, to_state, note, detail)
			SELECT workspace_id, id, $2, $3, $4, 'reopen', 'risk_accepted', 'new', 'ignore rule ended', jsonb_build_object('rule_id', $1::bigint) FROM u`,
			id, actor.Type, userIDOnly(actor), actor.Name)
		if err != nil {
			return err
		}
		n = res.RowsAffected()
		return nil
	})
	return n, err
}

// --- the approval inbox

// IgnoreRequest asks security or an admin to ignore issues.
type IgnoreRequest struct {
	ID              int64      `json:"id"`
	FindingIDs      []int64    `json:"finding_ids"`
	Title           string     `json:"title"`
	FixGroup        string     `json:"fix_group"`
	AssetID         *int64     `json:"asset_id"`
	AssetName       string     `json:"asset_name"`
	Reason          string     `json:"reason"`
	Note            string     `json:"note"`
	Mitigation      string     `json:"mitigation"`
	Scope           string     `json:"scope"`
	Expiry          string     `json:"expiry"`
	ExpiresAt       *time.Time `json:"expires_at"`
	Status          string     `json:"status"`
	RequestedBy     *int64     `json:"requested_by_id"`
	RequestedByName string     `json:"requested_by"`
	RequestedAt     time.Time  `json:"requested_at"`
	DecidedByName   string     `json:"decided_by"`
	DecidedAt       *time.Time `json:"decided_at"`
	DecisionNote    string     `json:"decision_note"`
	Applied         int        `json:"applied"`
}

const requestCols = `r.id, r.finding_ids, r.title, r.fix_group, r.asset_id, COALESCE(a.name, ''), r.reason, r.note, r.mitigation,
	r.scope, r.expiry, r.expires_at, r.status, r.requested_by, r.requested_by_name, r.requested_at, r.decided_by_name,
	r.decided_at, r.decision_note, r.applied`

// NewIgnoreRequest is what a requester sends: the issues (finding ids, or
// a fix's open issues) and the ignore they ask for.
type NewIgnoreRequest struct {
	FindingIDs []int64
	FixGroup   string
	IgnoreSpec
}

// CreateIgnoreRequest records a request. The findings must be open in this
// workspace; the spec is validated as an ignore would be.
func (s *Store) CreateIgnoreRequest(ctx context.Context, in NewIgnoreRequest, maxDays int, actor Actor) (*IgnoreRequest, error) {
	expires, err := in.IgnoreSpec.resolve(maxDays, time.Now())
	if err != nil {
		return nil, err
	}
	var title string
	var assetID *int64
	ids := in.FindingIDs
	if in.FixGroup != "" {
		var gAsset int64
		if err := s.Pool.QueryRow(ctx, `SELECT g.asset_id, COALESCE(g.data->>'title', '') || ' on ' || a.name
			FROM fix_groups g JOIN assets a ON a.id = g.asset_id WHERE g.id = $1`, in.FixGroup).Scan(&gAsset, &title); err != nil {
			return nil, notFound(err)
		}
		assetID = &gAsset
		rows, err := s.Pool.Query(ctx, `SELECT id FROM findings WHERE fix_group = $1 AND status = 'open'
			AND state IN ('new', 'acknowledged', 'in_progress') ORDER BY id LIMIT $2`, in.FixGroup, maxRequestIssues+1)
		if err != nil {
			return nil, err
		}
		if ids, err = pgx.CollectRows(rows, pgx.RowTo[int64]); err != nil {
			return nil, err
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: no open issue to ignore", ErrInvalidAction)
	}
	if len(ids) > maxRequestIssues {
		return nil, fmt.Errorf("%w: a request can cover at most %d issues", ErrInvalidAction, maxRequestIssues)
	}
	// Only this workspace's open findings count (row-level security hides
	// the others), and the title names what they are.
	var n, fixable int
	var assets []int64
	var first string
	if err := s.Pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE `+freeFix("f")+`), COALESCE(array_agg(DISTINCT f.asset_id), '{}'),
		  COALESCE(min(f.key || ' in ' || CASE WHEN c.namespace = '' THEN c.name ELSE c.namespace || '/' || c.name END || ' on ' || a.name), '')
		FROM findings f JOIN assets a ON a.id = f.asset_id JOIN components c ON c.id = f.component_id
		WHERE f.id = ANY($1) AND f.status = 'open'`, ids).Scan(&n, &fixable, &assets, &first); err != nil {
		return nil, err
	}
	if n != len(dedupe(ids)) {
		return nil, fmt.Errorf("%w: some issues are not open or do not exist", ErrInvalidAction)
	}
	if in.Expiry == ExpiryUntilFix && fixable > 0 {
		return nil, fmt.Errorf("%w: %d of these issues already have a fixed version; choose a date", ErrInvalidAction, fixable)
	}
	if title == "" {
		if n == 1 {
			title = first
		} else {
			title = fmt.Sprintf("%d issues", n)
		}
	}
	if assetID == nil && len(assets) == 1 {
		assetID = &assets[0]
	}
	var id int64
	if err := s.Pool.QueryRow(ctx, `INSERT INTO ignore_requests (finding_ids, title, fix_group, asset_id, reason, note, mitigation,
		scope, expiry, expires_at, requested_by, requested_by_name) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
		dedupe(ids), title, in.FixGroup, assetID, in.Reason, strings.TrimSpace(in.Note), in.Mitigation, in.Scope, in.Expiry,
		expiresForRequest(in.IgnoreSpec, expires), userIDOnly(actor), actor.Name).Scan(&id); err != nil {
		return nil, err
	}
	return s.GetIgnoreRequest(ctx, id)
}

// expiresForRequest stores the date for a dated request; until-fix and
// never are computed when the request is approved.
func expiresForRequest(sp IgnoreSpec, expires *time.Time) *time.Time {
	if sp.Expiry == ExpiryDate {
		return expires
	}
	return nil
}

func dedupe(ids []int64) []int64 {
	seen := make(map[int64]bool, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func (s *Store) GetIgnoreRequest(ctx context.Context, id int64) (*IgnoreRequest, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+requestCols+` FROM ignore_requests r LEFT JOIN assets a ON a.id = r.asset_id WHERE r.id = $1`, id)
	if err != nil {
		return nil, err
	}
	r, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[IgnoreRequest])
	return r, notFound(err)
}

// IgnoreRequestFilter selects requests: by status (pending, approved,
// declined; empty for all) and, for people who may not decide, their own.
type IgnoreRequestFilter struct {
	Status      string
	RequestedBy int64
	// DecidableOn, when set, limits the list to requests whose issues are
	// all on these assets, plus the caller's own requests (RequestedBy):
	// the inbox of someone who decides through project grants only.
	DecidableOn []int64
	Page
}

func (s *Store) ListIgnoreRequests(ctx context.Context, f IgnoreRequestFilter) ([]IgnoreRequest, int64, error) {
	w := &where{}
	if f.Status != "" {
		w.add("r.status = ?", f.Status)
	}
	switch {
	case f.DecidableOn != nil:
		w.args = append(w.args, f.DecidableOn, f.RequestedBy)
		w.conds = append(w.conds, fmt.Sprintf(`(r.requested_by = $%d OR NOT EXISTS (SELECT 1 FROM unnest(r.finding_ids) x(id)
			LEFT JOIN findings f ON f.id = x.id WHERE f.asset_id IS NULL OR NOT (f.asset_id = ANY($%d))))`, len(w.args), len(w.args)-1))
	case f.RequestedBy > 0:
		w.add("r.requested_by = ?", f.RequestedBy)
	}
	var total int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM ignore_requests r`+w.sql(), w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	p := f.Page.norm()
	rows, err := s.Pool.Query(ctx, `SELECT `+requestCols+` FROM ignore_requests r LEFT JOIN assets a ON a.id = r.asset_id`+w.sql()+
		fmt.Sprintf(` ORDER BY r.status = 'pending' DESC, r.requested_at DESC, r.id DESC LIMIT %d OFFSET %d`, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[IgnoreRequest])
	return out, total, err
}

// DecideIgnoreRequest approves or declines a pending request. Approval
// ignores the request's issues that are still open and active, as the
// decider would; issues closed or ignored meanwhile are skipped.
func (s *Store) DecideIgnoreRequest(ctx context.Context, id int64, approve bool, note string, maxDays int, actor Actor) (*IgnoreRequest, error) {
	status := "declined"
	if approve {
		status = "approved"
	}
	var r *IgnoreRequest
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var cur string
		if err := tx.QueryRow(ctx, `SELECT status FROM ignore_requests WHERE id = $1 FOR UPDATE`, id).Scan(&cur); err != nil {
			return notFound(err)
		}
		if cur != "pending" {
			return fmt.Errorf("%w: the request was already %s", ErrConflict, cur)
		}
		rows, err := tx.Query(ctx, `SELECT `+requestCols+` FROM ignore_requests r LEFT JOIN assets a ON a.id = r.asset_id WHERE r.id = $1`, id)
		if err != nil {
			return err
		}
		if r, err = pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[IgnoreRequest]); err != nil {
			return err
		}
		applied := 0
		if approve {
			sp := IgnoreSpec{Reason: r.Reason, Scope: r.Scope, Expiry: r.Expiry, Until: r.ExpiresAt, Note: r.Note, Mitigation: r.Mitigation}
			expires, err := sp.resolve(maxDays, time.Now())
			if err != nil {
				return err
			}
			for _, fid := range r.FindingIDs {
				var state, status string
				var exc *int64
				err := tx.QueryRow(ctx, `SELECT state, status, exception_id FROM findings WHERE id = $1 FOR UPDATE`, fid).Scan(&state, &status, &exc)
				if errors.Is(err, pgx.ErrNoRows) {
					continue
				}
				if err != nil {
					return err
				}
				if status != "open" || (state != "new" && state != "acknowledged" && state != "in_progress") {
					continue // closed, or covered by another rule meanwhile
				}
				// The decider ignores, on the requester's behalf: the event
				// names both.
				if _, err := ignoreFinding(ctx, tx, fid, sp, expires, actor, id); err != nil {
					if errors.Is(err, ErrInvalidAction) {
						continue
					}
					return err
				}
				d, _ := json.Marshal(map[string]any{"request_id": id, "requested_by": r.RequestedByName, "reason": sp.Reason,
					"scope": sp.Scope, "expiry": sp.Expiry, "until": expires})
				if _, err := tx.Exec(ctx, `INSERT INTO finding_events (finding_id, actor_type, actor_id, actor_name, action, from_state, to_state, note, detail)
					VALUES ($1,$2,$3,$4,'ignore',$5,'risk_accepted',$6,$7)`, fid, actor.Type, userIDOnly(actor), actor.Name, state, sp.Note, d); err != nil {
					return err
				}
				applied++
			}
		}
		_, err = tx.Exec(ctx, `UPDATE ignore_requests SET status = $2, decided_by = $3, decided_by_name = $4, decided_at = now(),
			decision_note = $5, applied = $6 WHERE id = $1`, id, status, userIDOnly(actor), actor.Name, note, applied)
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.GetIgnoreRequest(ctx, id)
}

// --- check again

// Check methods: who has to report for a check to complete.
const (
	CheckAgent       = "agent"       // the agent on the host, which polls for checks
	CheckIntegration = "integration" // a server-side scan (Git repository, image)
	CheckReport      = "report"      // the next upload (stackurity scan, SBOM)
)

// Check is a request for fresh evidence about an asset, or about one fix on
// it, and its outcome once that evidence has been evaluated.
type Check struct {
	ID              int64      `json:"id"`
	AssetID         int64      `json:"asset_id"`
	AssetName       string     `json:"asset_name"`
	AssetKind       string     `json:"asset_kind"`
	FixGroup        string     `json:"fix_group"`
	FixTitle        string     `json:"fix_title"`
	Reason          string     `json:"reason"` // check, or applied ("I applied this")
	Method          string     `json:"method"`
	IntegrationID   *int64     `json:"integration_id"`
	RequestedByName string     `json:"requested_by"`
	RequestedAt     time.Time  `json:"requested_at"`
	PickedUpAt      *time.Time `json:"picked_up_at"`
	CollectionID    *int64     `json:"collection_id"`
	CompletedAt     *time.Time `json:"completed_at"`
	Outcome         string     `json:"outcome"` // '', passed, partly_fixed, still_open, expired
	OpenBefore      int        `json:"open_before"`
	Fixed           int        `json:"fixed"`
	Remaining       int        `json:"remaining"`
	NewIssues       int        `json:"new_issues"`
	// Status: waiting (no report yet), evaluating (a report arrived and is
	// being checked) or done.
	Status string `json:"status"`
	// AgentPolledAt is when an agent last asked whether to report now:
	// null for agents older than 0.7, which report on their interval.
	AgentPolledAt *time.Time `json:"agent_polled_at"`
}

const checkCols = `k.id, k.asset_id, a.name, a.kind, k.fix_group, k.fix_title, k.reason, k.method, k.integration_id, k.requested_by_name,
	k.requested_at, k.picked_up_at, k.collection_id, k.completed_at, k.outcome, k.open_before, k.fixed, k.remaining, k.new_issues,
	CASE WHEN k.completed_at IS NOT NULL THEN 'done'
	  WHEN EXISTS (SELECT 1 FROM collections c WHERE c.asset_id = COALESCE(a.merged_into, a.id) AND c.complete AND c.received_at > k.requested_at)
	  THEN 'evaluating' ELSE 'waiting' END,
	a.agent_polled_at`

const checkFrom = ` FROM checks k JOIN assets a ON a.id = k.asset_id`

// CheckRequest asks for a check of an asset or of one fix (FixGroup).
type CheckRequest struct {
	AssetID  int64
	FixGroup string
	Reason   string // check (default) or applied
}

// RequestCheck records a check, or returns the one already waiting for a
// report with the same scope. For a fix it keeps the fix's open issues, so
// the outcome says which are gone. Callers queue the server-side scan for
// method integration (IntegrationID).
func (s *Store) RequestCheck(ctx context.Context, in CheckRequest, actor Actor) (*Check, bool, error) {
	if in.Reason == "" {
		in.Reason = "check"
	}
	var id int64
	created := false
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		title := ""
		if in.FixGroup != "" {
			if err := tx.QueryRow(ctx, `SELECT asset_id, COALESCE(data->>'title', '') FROM fix_groups WHERE id = $1`, in.FixGroup).
				Scan(&in.AssetID, &title); err != nil {
				return notFound(err)
			}
		}
		var kind string
		var polled *time.Time
		var integ *int64
		if err := tx.QueryRow(ctx, `SELECT a.kind, a.agent_polled_at,
			  (SELECT i.id FROM integrations i WHERE i.asset_id = a.id AND i.enabled ORDER BY i.id LIMIT 1)
			FROM assets a WHERE a.id = $1 AND a.merged_into IS NULL FOR UPDATE`, in.AssetID).Scan(&kind, &polled, &integ); err != nil {
			return notFound(err)
		}
		// A check waiting for its report already asks for the same thing.
		err := tx.QueryRow(ctx, `SELECT k.id FROM checks k WHERE k.asset_id = $1 AND k.fix_group = $2 AND k.completed_at IS NULL
			AND NOT EXISTS (SELECT 1 FROM collections c WHERE c.asset_id = k.asset_id AND c.complete AND c.received_at > k.requested_at)
			ORDER BY k.id DESC LIMIT 1`, in.AssetID, in.FixGroup).Scan(&id)
		if err == nil {
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		method := CheckReport
		switch {
		case kind == "host" || polled != nil:
			method, integ = CheckAgent, nil
		case integ != nil:
			method = CheckIntegration
		}
		ids := []int64{}
		var before int
		if in.FixGroup != "" {
			rows, err := tx.Query(ctx, `SELECT id FROM findings WHERE fix_group = $1 AND asset_id = $2 AND status = 'open' ORDER BY id`, in.FixGroup, in.AssetID)
			if err != nil {
				return err
			}
			if ids, err = pgx.CollectRows(rows, pgx.RowTo[int64]); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT DISTINCT component_id, key, kind FROM findings WHERE id = ANY($1)) x`, ids).Scan(&before); err != nil {
				return err
			}
		} else if err := tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT DISTINCT component_id, key, kind FROM findings
			WHERE asset_id = $1 AND status = 'open') x`, in.AssetID).Scan(&before); err != nil {
			return err
		}
		created = true
		return tx.QueryRow(ctx, `INSERT INTO checks (asset_id, fix_group, fix_title, finding_ids, open_before, reason, method, integration_id,
			requested_by, requested_by_name) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
			in.AssetID, in.FixGroup, title, ids, before, in.Reason, method, integ, userIDOnly(actor), actor.Name).Scan(&id)
	})
	if err != nil {
		return nil, false, err
	}
	c, err := s.GetCheck(ctx, id)
	return c, created, err
}

func (s *Store) GetCheck(ctx context.Context, id int64) (*Check, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+checkCols+checkFrom+` WHERE k.id = $1`, id)
	if err != nil {
		return nil, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Check])
	return c, notFound(err)
}

// CheckFilter selects checks: an asset's, a fix's, the open ones.
type CheckFilter struct {
	AssetID  int64
	FixGroup string
	Open     bool
	Page
}

func (s *Store) ListChecks(ctx context.Context, f CheckFilter) ([]Check, int64, error) {
	w := &where{}
	if f.AssetID > 0 {
		w.add("k.asset_id = ?", f.AssetID)
	}
	if f.FixGroup != "" {
		w.add("k.fix_group = ?", f.FixGroup)
	}
	if f.Open {
		w.conds = append(w.conds, "k.completed_at IS NULL")
	}
	var total int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM checks k`+w.sql(), w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	p := f.Page.norm()
	rows, err := s.Pool.Query(ctx, `SELECT `+checkCols+checkFrom+w.sql()+fmt.Sprintf(` ORDER BY k.requested_at DESC, k.id DESC LIMIT %d OFFSET %d`, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Check])
	return out, total, err
}

// maxPollAssets bounds the assets one agent poll asks about (a host and
// the applications its agent reports).
const maxPollAssets = 100

// AgentCheckDue answers an agent's poll: whether any of its assets has a
// check waiting for a report. It records when the agent asked (at most
// every five minutes per asset) and that it picked the checks up. The
// poll is cheap: a lookup in a small partial index, and rarely a write.
func (s *Store) AgentCheckDue(ctx context.Context, assetIDs []int64) (bool, error) {
	if len(assetIDs) == 0 {
		return false, nil
	}
	if len(assetIDs) > maxPollAssets {
		assetIDs = assetIDs[:maxPollAssets]
	}
	var due bool
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE assets SET agent_polled_at = now() WHERE id = ANY($1)
			AND (agent_polled_at IS NULL OR agent_polled_at < now() - interval '5 minutes')`, assetIDs); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE checks k SET picked_up_at = COALESCE(k.picked_up_at, now())
			WHERE k.asset_id = ANY($1) AND k.completed_at IS NULL AND k.method <> 'integration'
			  AND NOT EXISTS (SELECT 1 FROM collections c WHERE c.asset_id = k.asset_id AND c.complete AND c.received_at > k.requested_at)`, assetIDs)
		if err != nil {
			return err
		}
		due = tag.RowsAffected() > 0
		return nil
	})
	return due, err
}

// CompleteChecks completes the checks whose report has been evaluated:
// a complete collection received after the request, and an evaluation of
// the asset that started after it arrived with none still queued. Checks
// with no report after 7 days expire. It returns how many completed.
func (s *Store) CompleteChecks(ctx context.Context) (int, error) {
	type open struct {
		id, asset   int64
		fix         string
		ids         []int64
		before      int
		requested   time.Time
		coll        *int64
		received    *time.Time
		evaluatedAt *time.Time
		pending     bool
	}
	rows, err := s.Pool.Query(ctx, `SELECT k.id, t.id, k.fix_group, k.finding_ids, k.open_before, k.requested_at, c.id, c.received_at, t.evaluated_at,
		  EXISTS (SELECT 1 FROM jobs j WHERE j.dedupe_key = 'evaluate:asset:' || t.id AND j.done_at IS NULL AND j.failed_at IS NULL)
		FROM checks k JOIN assets a ON a.id = k.asset_id JOIN assets t ON t.id = COALESCE(a.merged_into, a.id)
		LEFT JOIN LATERAL (SELECT c.id, c.received_at FROM collections c WHERE c.asset_id = t.id AND c.complete AND c.received_at > k.requested_at
		  ORDER BY c.received_at LIMIT 1) c ON true
		WHERE k.completed_at IS NULL ORDER BY k.id LIMIT 1000`)
	if err != nil {
		return 0, err
	}
	var list []open
	for rows.Next() {
		var o open
		if err := rows.Scan(&o.id, &o.asset, &o.fix, &o.ids, &o.before, &o.requested, &o.coll, &o.received, &o.evaluatedAt, &o.pending); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	done := 0
	for _, o := range list {
		ready := o.coll != nil && o.evaluatedAt != nil && !o.evaluatedAt.Before(*o.received) && !o.pending
		if !ready {
			if time.Since(o.requested) > checkExpiryDays*24*time.Hour {
				if _, err := s.Pool.Exec(ctx, `UPDATE checks SET completed_at = now(), outcome = 'expired' WHERE id = $1 AND completed_at IS NULL`, o.id); err != nil {
					return done, err
				}
				done++
			}
			continue
		}
		var fixed, remaining, fresh int
		if o.fix != "" {
			// A fix: which of its issues are still on the asset, in any
			// state and on any inventory row (an upgrade that left the
			// component vulnerable opens a new finding for the same issue).
			if err := s.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE EXISTS (SELECT 1 FROM findings p WHERE p.asset_id = $2
				  AND p.component_id = x.component_id AND p.key = x.key AND p.kind = x.kind AND p.status = 'open')),
				  count(*)
				FROM (SELECT DISTINCT component_id, key, kind FROM findings WHERE id = ANY($1)) x`, o.ids, o.asset).Scan(&remaining, &fixed); err != nil {
				return done, err
			}
			fixed -= remaining
		} else {
			// The whole asset: issues open before the request that are left,
			// and issues found since.
			if err := s.Pool.QueryRow(ctx, `SELECT
				  count(*) FILTER (WHERE EXISTS (SELECT 1 FROM findings p WHERE p.asset_id = $1 AND p.component_id = x.component_id
				    AND p.key = x.key AND p.kind = x.kind AND p.first_seen < $2)),
				  count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM findings p WHERE p.asset_id = $1 AND p.component_id = x.component_id
				    AND p.key = x.key AND p.kind = x.kind AND p.first_seen < $2))
				FROM (SELECT DISTINCT component_id, key, kind FROM findings WHERE asset_id = $1 AND status = 'open') x`,
				o.asset, o.requested).Scan(&remaining, &fresh); err != nil {
				return done, err
			}
			fixed = max(0, o.before-remaining)
		}
		outcome := CheckOutcome(fixed, remaining)
		if _, err := s.Pool.Exec(ctx, `UPDATE checks SET completed_at = now(), collection_id = $2, outcome = $3, fixed = $4, remaining = $5,
			new_issues = $6 WHERE id = $1 AND completed_at IS NULL`, o.id, o.coll, outcome, fixed, remaining, fresh); err != nil {
			return done, err
		}
		done++
	}
	return done, nil
}

// CheckOutcome: passed when nothing it was about is left, partly fixed
// when some of it went, still open when none did.
func CheckOutcome(fixed, remaining int) string {
	switch {
	case remaining == 0:
		return "passed"
	case fixed > 0:
		return "partly_fixed"
	}
	return "still_open"
}

// MarkFixApplied records that a person applied a fix: its active issues
// go to in progress, "applied, waiting for a check", with an event each.
// Nothing is resolved: only fresh evidence closes an issue. The caller
// requests the check.
func (s *Store) MarkFixApplied(ctx context.Context, fixGroup string, actor Actor) (int64, error) {
	var n int64
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM fix_groups WHERE id = $1)`, fixGroup).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		tag, err := tx.Exec(ctx, `WITH o AS (
			  SELECT id, state FROM findings WHERE fix_group = $1 AND status = 'open' AND state IN ('new', 'acknowledged', 'in_progress') FOR UPDATE),
			u AS (UPDATE findings f SET state = 'in_progress', state_reason = $5 FROM o WHERE f.id = o.id
			  RETURNING f.workspace_id, f.id, o.state AS from_state)
			INSERT INTO finding_events (workspace_id, finding_id, actor_type, actor_id, actor_name, action, from_state, to_state, note, detail)
			SELECT workspace_id, id, $2, $3, $4, 'applied', from_state, 'in_progress', $5, jsonb_build_object('fix_group', $1::text) FROM u`,
			fixGroup, actor.Type, userIDOnly(actor), actor.Name, appliedNote)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		return nil
	})
	return n, err
}

// --- regressed issues in notifications

// RegressedToAnnounce counts the active regressed findings no urgent
// message has told people about yet, grouped like CountIssues, with the
// latest regression time it covers (for MarkRegressedNotified).
func (s *Store) RegressedToAnnounce(ctx context.Context) ([]IssueCount, time.Time, error) {
	var upto *time.Time
	if err := s.Pool.QueryRow(ctx, `SELECT max(f.regressed_at) FROM findings f
		WHERE f.status = 'open' AND f.regressed_at IS NOT NULL AND f.state IN ('new', 'acknowledged')
		  AND (f.regressed_notified_at IS NULL OR f.regressed_notified_at < f.regressed_at)`).Scan(&upto); err != nil {
		return nil, time.Time{}, err
	}
	if upto == nil {
		return nil, time.Time{}, nil
	}
	rows, err := s.Pool.Query(ctx, `SELECT 0::bigint, a.id, a.name, a.environment, a.owner_team_id, f.kind, f.priority, f.sos,
		  COALESCE((f.evidence->>'known_exploited')::boolean, false), f.fix_group, '', count(*)::int
		FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		WHERE f.status = 'open' AND f.regressed_at IS NOT NULL AND f.regressed_at <= $1 AND f.state IN ('new', 'acknowledged')
		  AND (f.regressed_notified_at IS NULL OR f.regressed_notified_at < f.regressed_at)
		GROUP BY 2, 3, 4, 5, 6, 7, 8, 9, 10`, *upto)
	if err != nil {
		return nil, time.Time{}, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[IssueCount])
	return out, *upto, err
}

// MarkRegressedNotified records that the regressions up to upto have been
// announced (or that no route wanted them).
func (s *Store) MarkRegressedNotified(ctx context.Context, upto time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE findings SET regressed_notified_at = now()
		WHERE status = 'open' AND regressed_at IS NOT NULL AND regressed_at <= $1
		  AND (regressed_notified_at IS NULL OR regressed_notified_at < regressed_at)`, upto)
	return err
}
