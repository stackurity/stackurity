package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Exceptions to policy gates (docs/design/policy-gates.md, section 6;
// migration 0124): someone asks for a policy not to count against one
// asset, one component on it, or one finding or leaked key on it, with a
// reason and the date it should end; a security or admin user approves or
// declines, as for ignore requests. An approved exception always has an
// expiry, capped by the risk policy's exception_max_days; past it, the
// violation returns and the upkeep tick records the exception as ended
// (ExpireSuppressions). An approved exception can be ended early.
//
// The workflow's rules beyond one approver (a second approver, approver
// groups, expiry reminders) belong to the licensed build; the API asks
// them of a hook (internal/api/gate_exceptions.go). The store checks
// targets, dates and states only.

// Gate exception statuses. A listing reports an approved exception past
// its expiry as ended with end reason expired, whether or not the upkeep
// tick has recorded it yet.
const (
	GateExceptionPending  = "pending"
	GateExceptionApproved = "approved"
	GateExceptionDeclined = "declined"
	GateExceptionEnded    = "ended"
)

// Gate exception targets.
const (
	GateTargetAsset     = "asset"
	GateTargetComponent = "component"
	GateTargetFinding   = "finding"
)

// Why a gate exception ended.
const (
	GateEndExpired = "expired"
	GateEndRevoked = "revoked"
)

const gateExceptionNoteMax = 4000

// GateExceptionRequest is what someone asks for.
type GateExceptionRequest struct {
	PolicyID int64
	AssetID  int64
	// TargetKind: asset (every violation of the policy on the asset),
	// component (ComponentKey, a purl key on the asset) or finding
	// (FindingID or LeakID on the asset).
	TargetKind   string
	FindingID    *int64
	LeakID       *int64
	ComponentKey string
	Reason       string
	Note         string
	// ExpiresAt is the end the requester asks for: within the risk
	// policy's exception limit. Nil leaves it to the approver (the limit
	// by default).
	ExpiresAt *time.Time
}

// GateException is one exception, as the API and the dashboard show it.
type GateException struct {
	ID           int64  `json:"id"`
	PolicyID     int64  `json:"policy_id"`
	PolicyName   string `json:"policy_name"`
	RuleVersion  int    `json:"rule_version"`
	TargetKind   string `json:"target_kind"`
	AssetID      int64  `json:"asset_id"`
	AssetName    string `json:"asset_name"`
	FindingID    *int64 `json:"finding_id,omitempty"`
	LeakID       *int64 `json:"leak_id,omitempty"`
	ComponentKey string `json:"component_key,omitempty"`
	// TargetLabel says what it covers, for people: the finding's advisory
	// and component, the leak's rule, or the component.
	TargetLabel        string     `json:"target_label"`
	Reason             string     `json:"reason"`
	Note               string     `json:"note"`
	Status             string     `json:"status"`
	RequestedBy        *int64     `json:"requested_by_id"`
	RequestedByName    string     `json:"requested_by"`
	RequestedAt        time.Time  `json:"requested_at"`
	RequestedExpiresAt *time.Time `json:"requested_expires_at"`
	DecidedBy          *int64     `json:"decided_by_id"`
	DecidedByName      string     `json:"decided_by"`
	DecidedAt          *time.Time `json:"decided_at"`
	DecisionNote       string     `json:"decision_note"`
	ExpiresAt          *time.Time `json:"expires_at"`
	EndedAt            *time.Time `json:"ended_at"`
	EndedByName        string     `json:"ended_by"`
	EndReason          string     `json:"end_reason"`
	EndNote            string     `json:"end_note"`
}

// Active reports whether the exception takes violations out now.
func (x GateException) Active(now time.Time) bool {
	return x.Status == GateExceptionApproved && x.ExpiresAt != nil && x.ExpiresAt.After(now)
}

// gateExceptionCols reads a row of gate_policy_exceptions x (joined with
// gate_policies g and assets a) as a GateException, an approved exception
// past its expiry ($1, now) reported as ended.
const gateExceptionCols = `x.id, x.policy_id, COALESCE(g.name, ''), x.rule_version, x.target_kind, x.asset_id, COALESCE(a.name, ''),
	x.finding_id, x.leak_id, x.component_key, x.target_label, x.reason, x.note,
	CASE WHEN x.status = 'approved' AND x.expires_at <= $1 THEN 'ended' ELSE x.status END,
	x.requested_by, x.requested_by_name, x.requested_at, x.requested_expires_at,
	x.decided_by, x.decided_by_name, x.decided_at, x.decision_note, x.expires_at,
	CASE WHEN x.status = 'approved' AND x.expires_at <= $1 THEN x.expires_at ELSE x.ended_at END,
	CASE WHEN x.status = 'approved' AND x.expires_at <= $1 THEN 'expiry' ELSE x.ended_by_name END,
	CASE WHEN x.status = 'approved' AND x.expires_at <= $1 THEN 'expired' ELSE x.end_reason END,
	x.end_note`

const gateExceptionFrom = ` FROM gate_policy_exceptions x LEFT JOIN gate_policies g ON g.id = x.policy_id LEFT JOIN assets a ON a.id = x.asset_id`

// gateStatusSQL is the status a listing filters on (see gateExceptionCols).
const gateStatusSQL = `CASE WHEN x.status = 'approved' AND x.expires_at <= $1 THEN 'ended' ELSE x.status END`

// GateExceptionFilter narrows ListGateExceptions; zero values mean any.
type GateExceptionFilter struct {
	// Status: pending, approved (in force now), declined or ended
	// (including expired); empty for every status.
	Status   string
	PolicyID int64
	AssetID  int64
	Page
}

// GateExceptionStatuses are the statuses a listing can filter on.
var GateExceptionStatuses = []string{GateExceptionPending, GateExceptionApproved, GateExceptionDeclined, GateExceptionEnded}

// ListGateExceptions lists exceptions, pending ones by when they were
// asked (oldest first, as an inbox), others newest first.
func (s *Store) ListGateExceptions(ctx context.Context, f GateExceptionFilter) ([]GateException, int64, error) {
	p := f.Page.norm()
	where := ` WHERE ($2 = '' OR ` + gateStatusSQL + ` = $2) AND ($3::bigint = 0 OR x.policy_id = $3) AND ($4::bigint = 0 OR x.asset_id = $4)`
	now := time.Now()
	var total int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*)`+gateExceptionFrom+where, now, f.Status, f.PolicyID, f.AssetID).Scan(&total); err != nil {
		return nil, 0, err
	}
	order := ` ORDER BY x.requested_at DESC, x.id DESC`
	if f.Status == GateExceptionPending {
		order = ` ORDER BY x.requested_at, x.id`
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+gateExceptionCols+gateExceptionFrom+where+order+` LIMIT $5 OFFSET $6`,
		now, f.Status, f.PolicyID, f.AssetID, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[GateException])
	return out, total, err
}

// GetGateException returns one exception.
func (s *Store) GetGateException(ctx context.Context, id int64) (*GateException, error) {
	return getGateException(ctx, s.Pool, id)
}

func getGateException(ctx context.Context, db q, id int64) (*GateException, error) {
	rows, err := db.Query(ctx, `SELECT `+gateExceptionCols+gateExceptionFrom+` WHERE x.id = $2`, time.Now(), id)
	if err != nil {
		return nil, err
	}
	x, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[GateException])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return x, err
}

// gateExpiryLimit is the latest end an exception may have from now.
func gateExpiryLimit(maxDays int, now time.Time) time.Time {
	if maxDays <= 0 {
		maxDays = DefaultExceptionMaxDays
	}
	return now.AddDate(0, 0, maxDays)
}

func gateNote(what, note string, required bool) (string, error) {
	note = strings.TrimSpace(note)
	if required && note == "" {
		return "", fmt.Errorf("%w: %s is required", ErrInvalidAction, what)
	}
	if len(note) > gateExceptionNoteMax {
		return "", fmt.Errorf("%w: %s is limited to %d characters", ErrInvalidAction, what, gateExceptionNoteMax)
	}
	return note, nil
}

// RequestGateException records a request for an exception. The policy must
// apply to the asset now, and the target must be on the asset. A second
// request for the same thing while one is pending or in force is refused
// (ErrConflict). maxDays is the risk policy's exception_max_days.
func (s *Store) RequestGateException(ctx context.Context, in GateExceptionRequest, maxDays int, actor Actor) (*GateException, error) {
	now := time.Now()
	if !ignoreReasons[in.Reason] {
		return nil, fmt.Errorf("%w: reason must be accepted_risk, false_positive, mitigated or no_fix", ErrInvalidAction)
	}
	note, err := gateNote("a note saying why", in.Note, true)
	if err != nil {
		return nil, err
	}
	if in.ExpiresAt != nil {
		limit := gateExpiryLimit(maxDays, now)
		if !in.ExpiresAt.After(now) || in.ExpiresAt.After(limit) {
			return nil, fmt.Errorf("%w: the end date must be within the next %d days (the risk policy's limit for exceptions)",
				ErrInvalidAction, int(limit.Sub(now).Hours()/24+0.5))
		}
	}
	in.ComponentKey = strings.TrimSpace(in.ComponentKey)
	switch in.TargetKind {
	case GateTargetAsset:
		if in.FindingID != nil || in.LeakID != nil || in.ComponentKey != "" {
			return nil, fmt.Errorf("%w: an exception for the whole asset names no finding, leak or component", ErrInvalidAction)
		}
	case GateTargetComponent:
		if in.ComponentKey == "" || in.FindingID != nil || in.LeakID != nil {
			return nil, fmt.Errorf("%w: an exception for a component names its component_key only", ErrInvalidAction)
		}
		if len(in.ComponentKey) > 2048 {
			return nil, fmt.Errorf("%w: component_key is too long", ErrInvalidAction)
		}
	case GateTargetFinding:
		if (in.FindingID == nil) == (in.LeakID == nil) || in.ComponentKey != "" {
			return nil, fmt.Errorf("%w: an exception for a finding names one finding_id or leak_id", ErrInvalidAction)
		}
	default:
		return nil, fmt.Errorf("%w: target_kind must be asset, component or finding", ErrInvalidAction)
	}
	pol, err := s.GetGatePolicy(ctx, in.PolicyID)
	if err != nil {
		return nil, err
	}
	effective, err := s.EffectiveGatePolicies(ctx, in.AssetID)
	if err != nil {
		return nil, err
	}
	applies := false
	for _, p := range effective {
		applies = applies || p.ID == pol.ID
	}
	if !applies {
		return nil, fmt.Errorf("%w: this policy does not apply to this asset", ErrInvalidAction)
	}
	var label string
	switch {
	case in.FindingID != nil:
		err = s.Pool.QueryRow(ctx, `SELECT f.key || ' in ' || c.name || CASE WHEN i.version <> '' THEN ' ' || i.version ELSE '' END
			FROM findings f JOIN components c ON c.id = f.component_id JOIN inventory i ON i.id = f.inventory_id
			WHERE f.id = $1 AND f.asset_id = $2`, *in.FindingID, in.AssetID).Scan(&label)
	case in.LeakID != nil:
		err = s.Pool.QueryRow(ctx, `SELECT COALESCE(NULLIF(title, ''), rule) || ' in ' || path FROM leaks WHERE id = $1 AND asset_id = $2`,
			*in.LeakID, in.AssetID).Scan(&label)
	case in.TargetKind == GateTargetComponent:
		err = s.Pool.QueryRow(ctx, `SELECT c.name FROM inventory i JOIN components c ON c.id = i.component_id
			WHERE i.asset_id = $1 AND c.purl_key = $2 ORDER BY i.id LIMIT 1`, in.AssetID, in.ComponentKey).Scan(&label)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: what the exception names is not on this asset", ErrInvalidAction)
	}
	if err != nil {
		return nil, err
	}
	if len(label) > 500 {
		label = label[:497] + "..."
	}
	var id int64
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		// One request at a time per target: the policy's row is locked so
		// two requests for the same thing cannot both pass the check.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM gate_policies WHERE id = $1 FOR UPDATE`, pol.ID); err != nil {
			return err
		}
		var dup int64
		var dupStatus string
		err := tx.QueryRow(ctx, `SELECT id, status FROM gate_policy_exceptions
			WHERE policy_id = $1 AND asset_id = $2 AND target_kind = $3
			  AND finding_id IS NOT DISTINCT FROM $4 AND leak_id IS NOT DISTINCT FROM $5 AND component_key = $6
			  AND (status = 'pending' OR (status = 'approved' AND expires_at > $7))
			ORDER BY id LIMIT 1`, pol.ID, in.AssetID, in.TargetKind, in.FindingID, in.LeakID, in.ComponentKey, now).Scan(&dup, &dupStatus)
		if err == nil {
			word := "in force"
			if dupStatus == GateExceptionPending {
				word = "waiting for a decision"
			}
			return fmt.Errorf("%w: exception #%d for this is already %s", ErrConflict, dup, word)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		by, name := actorUser(actor)
		return tx.QueryRow(ctx, `INSERT INTO gate_policy_exceptions (policy_id, rule_version, target_kind, asset_id, finding_id, leak_id,
			component_key, target_label, reason, note, requested_by, requested_by_name, requested_expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id`,
			pol.ID, pol.RuleVersion, in.TargetKind, in.AssetID, in.FindingID, in.LeakID, in.ComponentKey, label, in.Reason, note,
			by, name, in.ExpiresAt).Scan(&id)
	})
	if err != nil {
		return nil, err
	}
	return s.GetGateException(ctx, id)
}

// lockGateException locks a pending or approved exception for a change.
func lockGateException(ctx context.Context, tx pgx.Tx, id int64) (status string, expires *time.Time, err error) {
	err = tx.QueryRow(ctx, `SELECT status, expires_at FROM gate_policy_exceptions WHERE id = $1 FOR UPDATE`, id).Scan(&status, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return status, expires, err
}

// DecideGateException approves or declines a pending request. On approval
// the exception ends at expiresAt, else at the date asked for, else at the
// risk policy's limit (maxDays), and never later than that limit. A
// decline needs a note saying why.
func (s *Store) DecideGateException(ctx context.Context, id int64, approve bool, note string, expiresAt *time.Time, maxDays int, actor Actor) (*GateException, error) {
	note, err := gateNote("a note saying why it is declined", note, !approve)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	limit := gateExpiryLimit(maxDays, now)
	if expiresAt != nil && !expiresAt.After(now) {
		return nil, fmt.Errorf("%w: the end date must be in the future", ErrInvalidAction)
	}
	var out *GateException
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		status, _, err := lockGateException(ctx, tx, id)
		if err != nil {
			return err
		}
		if status != GateExceptionPending {
			return fmt.Errorf("%w: the request was already %s", ErrConflict, status)
		}
		by, name := actorUser(actor)
		if !approve {
			if _, err := tx.Exec(ctx, `UPDATE gate_policy_exceptions SET status = 'declined', decided_by = $2, decided_by_name = $3,
				decided_at = $4, decision_note = $5 WHERE id = $1`, id, by, name, now, note); err != nil {
				return err
			}
		} else {
			var requested *time.Time
			if err := tx.QueryRow(ctx, `SELECT requested_expires_at FROM gate_policy_exceptions WHERE id = $1`, id).Scan(&requested); err != nil {
				return err
			}
			end := limit
			switch {
			case expiresAt != nil:
				end = *expiresAt
			case requested != nil && requested.After(now):
				end = *requested
			}
			if end.After(limit) {
				end = limit
			}
			if _, err := tx.Exec(ctx, `UPDATE gate_policy_exceptions SET status = 'approved', decided_by = $2, decided_by_name = $3,
				decided_at = $4, decision_note = $5, expires_at = $6 WHERE id = $1`, id, by, name, now, note, end); err != nil {
				return err
			}
		}
		out, err = getGateException(ctx, tx, id)
		return err
	})
	return out, err
}

// EndGateException ends an approved exception before its expiry: the
// violations it covered count again. The note says why.
func (s *Store) EndGateException(ctx context.Context, id int64, note string, actor Actor) (*GateException, error) {
	note, err := gateNote("the note", note, false)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var out *GateException
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		status, expires, err := lockGateException(ctx, tx, id)
		if err != nil {
			return err
		}
		switch {
		case status == GateExceptionApproved && expires != nil && !expires.After(now):
			return fmt.Errorf("%w: the exception has already expired", ErrConflict)
		case status == GateExceptionPending:
			return fmt.Errorf("%w: the request is waiting for a decision: decline it instead", ErrConflict)
		case status != GateExceptionApproved:
			return fmt.Errorf("%w: the exception is %s, not in force", ErrConflict, status)
		}
		by, name := actorUser(actor)
		if _, err := tx.Exec(ctx, `UPDATE gate_policy_exceptions SET status = 'ended', ended_at = $2, ended_by = $3, ended_by_name = $4,
			end_reason = 'revoked', end_note = $5 WHERE id = $1`, id, now, by, name, note); err != nil {
			return err
		}
		out, err = getGateException(ctx, tx, id)
		return err
	})
	return out, err
}

// endExpiredGateExceptions records approved exceptions past their expiry
// as ended (reason expired, at their expiry). Run by the upkeep tick
// (ExpireSuppressions); readers already treat them as ended.
func endExpiredGateExceptions(ctx context.Context, db q) (int64, error) {
	tag, err := db.Exec(ctx, `UPDATE gate_policy_exceptions SET status = 'ended', ended_at = expires_at, ended_by_name = 'expiry',
		end_reason = 'expired' WHERE status = 'approved' AND expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
