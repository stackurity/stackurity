package store

import (
	"context"
	"strconv"
	"time"
)

// Verified closure: the proof behind each closed finding, as one record.
// The facts come from the finding (first seen, resolved, its fix-by date),
// the inventory row it was on (the version before), resolution_detail (the
// row after, the collection that saw the change, the remediation plan; see
// ResolveRemovedFindings) and the finding's history (who said they applied
// the fix). The paid edition's evidence pack and proof export read it; the
// JSON names are the evidence pack's (stackurity-pro internal/evidence).

// Verification states of a closed finding.
const (
	// The installed version changed to one the advisories do not list, and
	// a collection saw it.
	VerifiedFixed = "verified_fixed"
	// A complete collection saw the component gone.
	VerifiedRemoved = "verified_removed"
	// Stackurity lost sight of the asset: nothing was verified.
	DisappearedUnverified = "disappeared_unverified"
	// Closed with nothing changed on the asset (advisory withdrawn or
	// changed, still affected after an upgrade, no longer evaluated).
	ClosedNotRemediation = "closed_not_remediation"
)

// Who or what fixed it (Closure.FixedBy.Type).
const (
	FixedByRemediationRun = "remediation_run"
	FixedByPullRequest    = "pull_request"
	FixedByAgentReport    = "agent_report"
	FixedByManual         = "manual"
	FixedByUnknown        = "unknown"
)

// ClosureSchemaVersion is Closure's schema version.
const ClosureSchemaVersion = 1

// Verification is the verification state for a resolution kind.
func Verification(kind string) string {
	switch kind {
	case ResolutionRemediated:
		return VerifiedFixed
	case ResolutionRemoved:
		return VerifiedRemoved
	case ResolutionDisappeared:
		return DisappearedUnverified
	}
	return ClosedNotRemediation
}

type Closure struct {
	SchemaVersion    int            `json:"schema_version"`
	FindingID        int64          `json:"finding_id"`
	AssetID          int64          `json:"asset_id"`
	AssetName        string         `json:"asset_name"`
	Kind             string         `json:"kind"`
	Key              string         `json:"key"`
	Severity         string         `json:"severity"`
	Priority         string         `json:"priority"`
	ResolutionKind   string         `json:"resolution_kind"`
	Verification     string         `json:"verification"`
	Before           ClosureBefore  `json:"before"`
	After            *ClosureAfter  `json:"after"`
	Check            *ClosureCheck  `json:"check"`
	FixedBy          ClosureFixedBy `json:"fixed_by"`
	OpenedAt         time.Time      `json:"opened_at"`
	ClosedAt         time.Time      `json:"closed_at"`
	TimeToFixSeconds int64          `json:"time_to_fix_seconds"`
	SLA              ClosureSLA     `json:"sla"`
}

type ClosureBefore struct {
	Component   string     `json:"component"`
	Version     string     `json:"version"`
	InventoryID int64      `json:"inventory_id"`
	LastSeenAt  *time.Time `json:"last_seen_at"`
}

// ClosureAfter is the row installed after the fix; nil when the component
// was removed (or the asset disappeared).
type ClosureAfter struct {
	Version     string `json:"version"`
	InventoryID *int64 `json:"inventory_id"`
}

// ClosureCheck is the collection that saw the change; nil for findings
// closed before proofs were recorded, or closed by intelligence changes.
type ClosureCheck struct {
	CollectionID int64     `json:"collection_id"`
	Source       string    `json:"source"` // the collection method: agent, lockfile, repository, scanner, registry, plugin, sbom
	ObservedAt   time.Time `json:"observed_at"`
	Complete     bool      `json:"complete"`
}

type ClosureFixedBy struct {
	Type     string     `json:"type"`
	Ref      string     `json:"ref"`
	Actor    string     `json:"actor"`
	Approver string     `json:"approver"`
	MergedAt *time.Time `json:"merged_at"`
}

// ClosureSLA compares the time to fix with the finding's fix-by date.
// PolicyDays and Met are null when the finding had no deadline, and Met
// also when the closure is not remediation.
type ClosureSLA struct {
	PolicyDays *int       `json:"policy_days"`
	DueAt      *time.Time `json:"due_at"`
	Met        *bool      `json:"met"`
}

// ClosureFilter selects closures: closed in [From, To), optionally one asset
// or one finding. Limit 0 means 1000; at most 10000.
type ClosureFilter struct {
	From, To  time.Time
	AssetID   int64
	FindingID int64
	Limit     int
}

// Closures lists closed findings with their proof, newest first, in the
// caller's workspace. slaDays is the risk policy's fix days per priority
// (risk.Policy.SLA), for policy_days.
func (s *Store) Closures(ctx context.Context, f ClosureFilter, slaDays map[string]int) ([]Closure, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 1000
	}
	limit = min(limit, 10000)
	if f.To.IsZero() {
		f.To = time.Now().Add(time.Minute)
	}
	rows, err := s.Pool.Query(ctx, `SELECT f.id, f.asset_id, a.name, f.kind, f.key, f.severity, f.priority, f.resolution_kind,
		  CASE WHEN c.namespace = '' THEN c.name ELSE c.namespace || '/' || c.name END, i.version, i.id, i.last_seen,
		  d.version, (d.detail->>'to_inventory_id')::bigint,
		  co.id, co.method, co.observed_at, COALESCE(co.complete OR co.proves_absence, false),
		  (d.detail->>'plan_id')::bigint, COALESCE(pu.approver, ''), ap.actor,
		  f.first_seen, f.resolved_at, f.fix_due
		FROM findings f JOIN assets a ON a.id = f.asset_id
		  JOIN components c ON c.id = f.component_id JOIN inventory i ON i.id = f.inventory_id
		  CROSS JOIN LATERAL (SELECT f.resolution_detail AS detail,
		    CASE WHEN f.resolution_kind = 'remediated' THEN f.resolution_detail->>'version' END AS version) d
		  LEFT JOIN collections co ON co.id = (d.detail->>'collection_id')::bigint
		  LEFT JOIN LATERAL (SELECT COALESCE(NULLIF(u.name, ''), u.email) AS approver FROM remediation_plans p
		    JOIN users u ON u.id = p.approved_by WHERE p.id = (d.detail->>'plan_id')::bigint) pu ON true
		  -- Someone said they applied the fix before it closed.
		  LEFT JOIN LATERAL (SELECT e.actor_name AS actor FROM finding_events e
		    WHERE e.finding_id = f.id AND e.action = 'applied' AND e.at <= f.resolved_at ORDER BY e.at DESC LIMIT 1) ap ON true
		WHERE f.status = 'resolved' AND f.resolved_at >= $1 AND f.resolved_at < $2
		  AND ($3::bigint = 0 OR f.asset_id = $3) AND ($4::bigint = 0 OR f.id = $4)
		ORDER BY f.resolved_at DESC, f.id LIMIT $5`, f.From, f.To, f.AssetID, f.FindingID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Closure{}
	for rows.Next() {
		var x Closure
		var afterVersion *string
		var afterInv, collID, planID *int64
		var method *string
		var observed *time.Time
		var complete bool
		var applier *string
		var resolved time.Time
		if err := rows.Scan(&x.FindingID, &x.AssetID, &x.AssetName, &x.Kind, &x.Key, &x.Severity, &x.Priority, &x.ResolutionKind,
			&x.Before.Component, &x.Before.Version, &x.Before.InventoryID, &x.Before.LastSeenAt,
			&afterVersion, &afterInv, &collID, &method, &observed, &complete,
			&planID, &x.FixedBy.Approver, &applier, &x.OpenedAt, &resolved, &x.SLA.DueAt); err != nil {
			return nil, err
		}
		x.SchemaVersion = ClosureSchemaVersion
		x.ClosedAt = resolved
		x.Verification = Verification(x.ResolutionKind)
		x.TimeToFixSeconds = int64(resolved.Sub(x.OpenedAt).Seconds())
		if afterVersion != nil {
			x.After = &ClosureAfter{Version: *afterVersion, InventoryID: afterInv}
		}
		if collID != nil && method != nil && observed != nil {
			x.Check = &ClosureCheck{CollectionID: *collID, Source: *method, ObservedAt: *observed, Complete: complete}
		}
		x.FixedBy = fixedBy(x, planID, applier, method)
		if x.SLA.DueAt != nil {
			if d, ok := slaDays[x.Priority]; ok {
				x.SLA.PolicyDays = &d
			}
			if CountsAsRemediation(x.ResolutionKind) {
				met := !resolved.After(*x.SLA.DueAt)
				x.SLA.Met = &met
			}
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// fixedBy says who or what fixed a closure: a remediation plan, a person
// who said they applied it, or the agent report that saw the new version.
// Pull requests are attributed by the paid edition.
func fixedBy(x Closure, planID *int64, applier, method *string) ClosureFixedBy {
	fb := ClosureFixedBy{Type: FixedByUnknown, Approver: x.FixedBy.Approver}
	if !CountsAsRemediation(x.ResolutionKind) {
		return fb
	}
	switch {
	case planID != nil:
		fb.Type, fb.Ref = FixedByRemediationRun, "remediation plan #"+strconv.FormatInt(*planID, 10)
	case applier != nil:
		fb.Type, fb.Actor = FixedByManual, *applier
	case method != nil && *method == "agent":
		fb.Type = FixedByAgentReport
	}
	return fb
}
