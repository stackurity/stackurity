package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Policy gates (docs/design/policy-gates.md, migration 0124): rules an
// organisation writes once and scopes like notifications. A policy is one
// rule kind with its parameters, asset filters and a mode. Violations are
// computed on read from findings and leaks (GateViolations); nothing stores
// them except the daily rollup (RollupGatePolicies).

// Gate policy kinds.
const (
	GateKnownExploited = "known_exploited"
	GateEndOfLife      = "end_of_life"
	GateFindingAge     = "finding_age"
	GateLeakedKey      = "leaked_key"
)

// GateKinds lists the rule kinds, in the order the dashboard shows them.
var GateKinds = []string{GateKnownExploited, GateEndOfLife, GateFindingAge, GateLeakedKey}

// Gate policy modes. A new policy starts in warn.
const (
	GateModeOff     = "off"
	GateModeWarn    = "warn"
	GateModeEnforce = "enforce"
)

// GateModes lists the modes from mildest to strictest.
var GateModes = []string{GateModeOff, GateModeWarn, GateModeEnforce}

// GateFilters narrow the assets a policy looks at. Empty lists match
// every asset. The environment "production" stands for the risk policy's
// production environments. Exposure is "any" or "exposed" (internet-facing
// by the risk model's effective exposure).
type GateFilters struct {
	AssetKinds   []string `json:"asset_kinds"`
	Environments []string `json:"environments"`
	Exposure     string   `json:"exposure"`
	Tags         []string `json:"tags"`
}

// GateEndOfLifeParams: a component past end of life. After (YYYY-MM-DD) also
// counts components whose end of life falls on or before that date;
// Products limits it to endoflife.date product ids.
type GateEndOfLifeParams struct {
	After    string   `json:"after,omitempty"`
	Products []string `json:"products"`
}

// GateFindingAgeParams: an open vulnerability of MinSeverity or higher older
// than MaxDays (from when the asset first had it).
type GateFindingAgeParams struct {
	MinSeverity string `json:"min_severity"`
	MaxDays     int    `json:"max_days"`
	OnlyFixable bool   `json:"only_fixable"`
}

// GateLeakedKeyParams: an open leaked key of MinSeverity or higher;
// ServedOnly counts only keys the asset serves to the network.
type GateLeakedKeyParams struct {
	MinSeverity string `json:"min_severity"`
	ServedOnly  bool   `json:"served_only"`
}

// GatePolicy is one policy gate.
type GatePolicy struct {
	ID               int64           `json:"id"`
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	Kind             string          `json:"kind"`
	Params           json.RawMessage `json:"params"`
	Filters          GateFilters     `json:"filters"`
	Mode             string          `json:"mode"`
	OwnerProjectID   *int64          `json:"owner_project_id"`
	OwnerAssetID     *int64          `json:"owner_asset_id"`
	InheritsPolicyID *int64          `json:"inherits_policy_id"`
	RuleVersion      int             `json:"rule_version"`
	CreatedBy        *int64          `json:"created_by"`
	CreatedByName    string          `json:"created_by_name"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedBy        *int64          `json:"updated_by"`
	UpdatedByName    string          `json:"updated_by_name"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// Owner is the policy's owner.
func (p GatePolicy) Owner() Owner { return Owner{ProjectID: p.OwnerProjectID, AssetID: p.OwnerAssetID} }

const gatePolicyCols = `id, name, description, kind, params, filters, mode, owner_project_id, owner_asset_id, inherits_policy_id,
	rule_version, created_by, created_by_name, created_at, updated_by, updated_by_name, updated_at`

var gateSeverities = []string{"low", "medium", "high", "critical"}

// gateSeverityRank is the SQL rank of a severity: 1 low to 4 critical, NULL
// for anything else (unknown, none), which then never reaches a minimum.
func gateSeverityRank(expr string) string {
	return `array_position(ARRAY['low','medium','high','critical'], ` + expr + `)`
}

func decodeStrict(raw json.RawMessage, v any) error {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		raw = json.RawMessage(`{}`)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("params: %v: %w", err, ErrInvalid)
	}
	return nil
}

// cleanList trims, drops empty and repeated values, and checks sizes.
func cleanList(what string, in []string, lower bool) ([]string, error) {
	out := []string{}
	if len(in) > 100 {
		return nil, fmt.Errorf("%s: at most 100 values: %w", what, ErrInvalid)
	}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if lower {
			v = strings.ToLower(v)
		}
		if v == "" {
			continue
		}
		if len(v) > 200 {
			return nil, fmt.Errorf("%s: a value is longer than 200 characters: %w", what, ErrInvalid)
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out, nil
}

// NormalizeGateParams checks a policy's parameters for its kind and returns
// them in their stored form (every field present, defaults filled).
func NormalizeGateParams(kind string, raw json.RawMessage) (json.RawMessage, error) {
	var v any
	switch kind {
	case GateKnownExploited:
		var p struct{}
		if err := decodeStrict(raw, &p); err != nil {
			return nil, err
		}
		v = p
	case GateEndOfLife:
		var p GateEndOfLifeParams
		if err := decodeStrict(raw, &p); err != nil {
			return nil, err
		}
		if p.After = strings.TrimSpace(p.After); p.After != "" {
			if _, err := time.Parse(time.DateOnly, p.After); err != nil {
				return nil, fmt.Errorf("params.after must be a date (YYYY-MM-DD): %w", ErrInvalid)
			}
		}
		var err error
		if p.Products, err = cleanList("params.products", p.Products, true); err != nil {
			return nil, err
		}
		v = p
	case GateFindingAge:
		var p GateFindingAgeParams
		if err := decodeStrict(raw, &p); err != nil {
			return nil, err
		}
		p.MinSeverity = strings.ToLower(strings.TrimSpace(p.MinSeverity))
		if !slices.Contains(gateSeverities, p.MinSeverity) {
			return nil, fmt.Errorf("params.min_severity must be low, medium, high or critical: %w", ErrInvalid)
		}
		if p.MaxDays < 1 || p.MaxDays > 3650 {
			return nil, fmt.Errorf("params.max_days must be from 1 to 3650: %w", ErrInvalid)
		}
		v = p
	case GateLeakedKey:
		var p GateLeakedKeyParams
		if err := decodeStrict(raw, &p); err != nil {
			return nil, err
		}
		p.MinSeverity = strings.ToLower(strings.TrimSpace(p.MinSeverity))
		if p.MinSeverity == "" {
			p.MinSeverity = "low"
		}
		if !slices.Contains(gateSeverities, p.MinSeverity) {
			return nil, fmt.Errorf("params.min_severity must be low, medium, high or critical: %w", ErrInvalid)
		}
		v = p
	default:
		return nil, fmt.Errorf("kind must be one of %s: %w", strings.Join(GateKinds, ", "), ErrInvalid)
	}
	out, err := json.Marshal(v)
	return out, err
}

// NormalizeGateFilters checks filters and returns them in stored form.
func NormalizeGateFilters(f GateFilters) (GateFilters, error) {
	var err error
	if f.AssetKinds, err = cleanList("filters.asset_kinds", f.AssetKinds, true); err != nil {
		return f, err
	}
	if f.Environments, err = cleanList("filters.environments", f.Environments, false); err != nil {
		return f, err
	}
	if f.Tags, err = cleanList("filters.tags", f.Tags, false); err != nil {
		return f, err
	}
	switch f.Exposure = strings.ToLower(strings.TrimSpace(f.Exposure)); f.Exposure {
	case "":
		f.Exposure = "any"
	case "any", "exposed":
	default:
		return f, fmt.Errorf("filters.exposure must be any or exposed: %w", ErrInvalid)
	}
	return f, nil
}

// normalizeGatePolicy checks every field a person sets.
func normalizeGatePolicy(p *GatePolicy) error {
	p.Name = strings.TrimSpace(p.Name)
	p.Description = strings.TrimSpace(p.Description)
	if p.Name == "" || len(p.Name) > 200 {
		return fmt.Errorf("name is required (at most 200 characters): %w", ErrInvalid)
	}
	if len(p.Description) > 2000 {
		return fmt.Errorf("description: at most 2000 characters: %w", ErrInvalid)
	}
	if p.Mode == "" {
		p.Mode = GateModeWarn
	}
	if !slices.Contains(GateModes, p.Mode) {
		return fmt.Errorf("mode must be off, warn or enforce: %w", ErrInvalid)
	}
	if p.OwnerProjectID != nil && p.OwnerAssetID != nil {
		return fmt.Errorf("a policy belongs to the organisation, one project or one asset: %w", ErrInvalid)
	}
	params, err := NormalizeGateParams(p.Kind, p.Params)
	if err != nil {
		return err
	}
	p.Params = params
	p.Filters, err = NormalizeGateFilters(p.Filters)
	return err
}

func scanGatePolicies(rows pgx.Rows) ([]GatePolicy, error) {
	return pgx.CollectRows(rows, pgx.RowToStructByPos[GatePolicy])
}

// ListGatePolicies lists every policy of the workspace (all owners).
func (s *Store) ListGatePolicies(ctx context.Context) ([]GatePolicy, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+gatePolicyCols+` FROM gate_policies ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	return scanGatePolicies(rows)
}

// ListOwnedGatePolicies lists the policies of one owner (the organisation's
// when owner is empty).
func (s *Store) ListOwnedGatePolicies(ctx context.Context, owner Owner) ([]GatePolicy, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+gatePolicyCols+` FROM gate_policies
		WHERE owner_project_id IS NOT DISTINCT FROM $1 AND owner_asset_id IS NOT DISTINCT FROM $2 ORDER BY name, id`, owner.ProjectID, owner.AssetID)
	if err != nil {
		return nil, err
	}
	return scanGatePolicies(rows)
}

// GetGatePolicy reads one policy.
func (s *Store) GetGatePolicy(ctx context.Context, id int64) (*GatePolicy, error) {
	return getGatePolicy(ctx, s.Pool, id, false)
}

func getGatePolicy(ctx context.Context, db q, id int64, lock bool) (*GatePolicy, error) {
	sql := `SELECT ` + gatePolicyCols + ` FROM gate_policies WHERE id = $1`
	if lock {
		sql += ` FOR UPDATE`
	}
	rows, err := db.Query(ctx, sql, id)
	if err != nil {
		return nil, err
	}
	p, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[GatePolicy])
	return p, notFound(err)
}

// gateAudit records a policy event in tx, so it commits with the change.
func gateAudit(ctx context.Context, tx pgx.Tx, a Actor, action string, objectID int64, detail any) error {
	d, _ := json.Marshal(detail)
	var id *int64
	if a.ID > 0 {
		id = &a.ID
	}
	_, err := tx.Exec(ctx, `INSERT INTO audit_events (actor_type, actor_id, actor_name, action, object_type, object_id, detail, remote_addr)
		VALUES ($1,$2,$3,$4,'gate_policy',$5,$6,$7)`, a.Type, id, a.Name, action, strconv.FormatInt(objectID, 10), d, a.RemoteAddr)
	return err
}

// GatePolicyAudit is the detail of a gate_policy.* audit event. The
// evidence pack derives each policy change from it: policy id, when and by
// whom (the event's own columns), the change (create, update, mode, delete,
// exclude, include, customise) and Summary, a one-line sentence.
type GatePolicyAudit struct {
	PolicyID int64       `json:"policy_id"`
	Summary  string      `json:"summary"`
	Before   *GatePolicy `json:"before,omitempty"`
	After    *GatePolicy `json:"after,omitempty"`
	// Changed lists the fields that differ between Before and After.
	Changed []string `json:"changed,omitempty"`
	// ProjectID or AssetID: where an inherited policy was turned off or on,
	// or copied.
	ProjectID *int64 `json:"project_id,omitempty"`
	AssetID   *int64 `json:"asset_id,omitempty"`
	CopyID    *int64 `json:"copy_id,omitempty"`
}

func actorUser(a Actor) (*int64, string) {
	if a.Type == "user" && a.ID > 0 {
		id := a.ID
		return &id, a.Name
	}
	return nil, a.Name
}

func ownerWords(o Owner) string {
	switch {
	case o.ProjectID != nil:
		return fmt.Sprintf("project %d", *o.ProjectID)
	case o.AssetID != nil:
		return fmt.Sprintf("asset %d", *o.AssetID)
	}
	return "the organisation"
}

// CreateGatePolicy validates and stores a new policy (its owner, and the
// policy it replaces for a copy, are taken from p) and audits it as
// gate_policy.create in the same transaction.
func (s *Store) CreateGatePolicy(ctx context.Context, p GatePolicy, a Actor) (*GatePolicy, error) {
	var out *GatePolicy
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var err error
		out, err = createGatePolicy(ctx, tx, p, a)
		return err
	})
	return out, err
}

func createGatePolicy(ctx context.Context, tx pgx.Tx, p GatePolicy, a Actor) (*GatePolicy, error) {
	if err := normalizeGatePolicy(&p); err != nil {
		return nil, err
	}
	by, name := actorUser(a)
	filters, _ := json.Marshal(p.Filters)
	rows, err := tx.Query(ctx, `INSERT INTO gate_policies (name, description, kind, params, filters, mode, owner_project_id, owner_asset_id,
			inherits_policy_id, created_by, created_by_name, updated_by, updated_by_name)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$10,$11) RETURNING `+gatePolicyCols,
		p.Name, p.Description, p.Kind, p.Params, filters, p.Mode, p.OwnerProjectID, p.OwnerAssetID, p.InheritsPolicyID, by, name)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[GatePolicy])
	switch {
	case isUniqueViolation(err):
		return nil, fmt.Errorf("a policy with that name exists: %w", ErrConflict)
	case isForeignKey(err):
		return nil, fmt.Errorf("no such project, asset or policy: %w", ErrNotFound)
	case err != nil:
		return nil, err
	}
	summary := fmt.Sprintf("Created %s policy %q (%s) for %s", p.Kind, out.Name, out.Mode, ownerWords(out.Owner()))
	return out, gateAudit(ctx, tx, a, "gate_policy.create", out.ID, GatePolicyAudit{PolicyID: out.ID, Summary: summary, After: out})
}

// gateChanged lists the fields a person can change that differ.
func gateChanged(a, b *GatePolicy) []string {
	var out []string
	if a.Name != b.Name {
		out = append(out, "name")
	}
	if a.Description != b.Description {
		out = append(out, "description")
	}
	if a.Kind != b.Kind {
		out = append(out, "kind")
	}
	if !jsonEqual(a.Params, b.Params) {
		out = append(out, "params")
	}
	fa, _ := json.Marshal(a.Filters)
	fb, _ := json.Marshal(b.Filters)
	if !jsonEqual(fa, fb) {
		out = append(out, "filters")
	}
	if a.Mode != b.Mode {
		out = append(out, "mode")
	}
	return out
}

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return bytes.Equal(a, b)
	}
	ja, _ := json.Marshal(x)
	jb, _ := json.Marshal(y)
	return bytes.Equal(ja, jb)
}

// UpdateGatePolicy replaces a policy's name, description, kind, params,
// filters and mode (its owner never changes). A change of kind, params or
// filters raises rule_version. A save that changes only the mode is
// audited as gate_policy.mode, any other change as gate_policy.update,
// with the policy before and after; a save that changes nothing is not
// audited.
//
// Step 4 of the design (docs/design/policy-gates.md, section 7) makes
// enforce a paid mode; until then the store accepts it in every edition.
func (s *Store) UpdateGatePolicy(ctx context.Context, p GatePolicy, a Actor) (*GatePolicy, error) {
	var out *GatePolicy
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		cur, err := getGatePolicy(ctx, tx, p.ID, true)
		if err != nil {
			return err
		}
		p.OwnerProjectID, p.OwnerAssetID, p.InheritsPolicyID = cur.OwnerProjectID, cur.OwnerAssetID, cur.InheritsPolicyID
		if err := normalizeGatePolicy(&p); err != nil {
			return err
		}
		changed := gateChanged(cur, &p)
		if len(changed) == 0 {
			out = cur
			return nil
		}
		bump := slices.ContainsFunc(changed, func(f string) bool { return f == "kind" || f == "params" || f == "filters" })
		by, name := actorUser(a)
		filters, _ := json.Marshal(p.Filters)
		rows, err := tx.Query(ctx, `UPDATE gate_policies SET name = $2, description = $3, kind = $4, params = $5, filters = $6, mode = $7,
				rule_version = rule_version + CASE WHEN $8 THEN 1 ELSE 0 END, updated_by = $9, updated_by_name = $10, updated_at = now()
			WHERE id = $1 RETURNING `+gatePolicyCols, p.ID, p.Name, p.Description, p.Kind, p.Params, filters, p.Mode, bump, by, name)
		if err != nil {
			return err
		}
		out, err = pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[GatePolicy])
		if isUniqueViolation(err) {
			return fmt.Errorf("a policy with that name exists: %w", ErrConflict)
		}
		if err != nil {
			return err
		}
		action, summary := "gate_policy.update", fmt.Sprintf("Changed %s of policy %q", strings.Join(changed, ", "), out.Name)
		if len(changed) == 1 && changed[0] == "mode" {
			action, summary = "gate_policy.mode", fmt.Sprintf("Policy %q mode changed from %s to %s", out.Name, cur.Mode, out.Mode)
		} else if slices.Contains(changed, "mode") {
			summary += fmt.Sprintf(" (mode %s to %s)", cur.Mode, out.Mode)
		}
		return gateAudit(ctx, tx, a, action, out.ID, GatePolicyAudit{PolicyID: out.ID, Summary: summary, Before: cur, After: out, Changed: changed})
	})
	return out, err
}

// DeleteGatePolicy deletes a policy. A project's or asset's copy of an
// inherited policy takes its turn-off with it: the inherited policy applies
// there again. Audited as gate_policy.delete with the policy as it was.
func (s *Store) DeleteGatePolicy(ctx context.Context, id int64, a Actor) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		cur, err := getGatePolicy(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if cur.InheritsPolicyID != nil {
			if _, err := tx.Exec(ctx, `DELETE FROM gate_policy_exclusions
				WHERE policy_id = $1 AND project_id IS NOT DISTINCT FROM $2 AND asset_id IS NOT DISTINCT FROM $3`,
				*cur.InheritsPolicyID, cur.OwnerProjectID, cur.OwnerAssetID); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM gate_policies WHERE id = $1`, id); err != nil {
			return err
		}
		return gateAudit(ctx, tx, a, "gate_policy.delete", id, GatePolicyAudit{PolicyID: id, Before: cur,
			Summary: fmt.Sprintf("Deleted policy %q of %s", cur.Name, ownerWords(cur.Owner()))})
	})
}

// GatePolicyExclusion is an inherited policy turned off for a project or
// an asset.
type GatePolicyExclusion struct {
	PolicyID  int64     `json:"policy_id"`
	ProjectID *int64    `json:"project_id"`
	AssetID   *int64    `json:"asset_id"`
	CreatedAt time.Time `json:"created_at"`
}

// GatePolicyExclusions lists the exclusions of an owner (a project or an
// asset), or every exclusion for an empty owner.
func (s *Store) GatePolicyExclusions(ctx context.Context, owner Owner) ([]GatePolicyExclusion, error) {
	rows, err := s.Pool.Query(ctx, `SELECT policy_id, project_id, asset_id, created_at FROM gate_policy_exclusions
		WHERE ($3 OR (project_id IS NOT DISTINCT FROM $1 AND asset_id IS NOT DISTINCT FROM $2)) ORDER BY policy_id, id`,
		owner.ProjectID, owner.AssetID, owner.Org())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[GatePolicyExclusion])
}

// SetGatePolicyExcluded turns an inherited policy off (off true) or on
// again for a project or an asset, audited as gate_policy.exclude or
// gate_policy.include when it changes anything.
func (s *Store) SetGatePolicyExcluded(ctx context.Context, policyID int64, owner Owner, off bool, a Actor) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		return setGatePolicyExcluded(ctx, tx, policyID, owner, off, a)
	})
}

func setGatePolicyExcluded(ctx context.Context, tx pgx.Tx, policyID int64, owner Owner, off bool, a Actor) error {
	if owner.Org() {
		return fmt.Errorf("a policy is turned off for a project or an asset: %w", ErrInvalid)
	}
	cur, err := getGatePolicy(ctx, tx, policyID, false)
	if err != nil {
		return err
	}
	var n int64
	action, verb := "gate_policy.include", "on"
	if off {
		action, verb = "gate_policy.exclude", "off"
		by, _ := actorUser(a)
		tag, err := tx.Exec(ctx, `INSERT INTO gate_policy_exclusions (policy_id, project_id, asset_id, created_by) VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING`, policyID, owner.ProjectID, owner.AssetID, by)
		if isForeignKey(err) {
			return fmt.Errorf("no such policy, project or asset: %w", ErrNotFound)
		}
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
	} else {
		tag, err := tx.Exec(ctx, `DELETE FROM gate_policy_exclusions WHERE policy_id = $1
			AND project_id IS NOT DISTINCT FROM $2 AND asset_id IS NOT DISTINCT FROM $3`, policyID, owner.ProjectID, owner.AssetID)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
	}
	if n == 0 {
		return nil
	}
	return gateAudit(ctx, tx, a, action, policyID, GatePolicyAudit{PolicyID: policyID, ProjectID: owner.ProjectID, AssetID: owner.AssetID,
		Summary: fmt.Sprintf("Policy %q turned %s for %s", cur.Name, verb, ownerWords(owner))})
}

// CustomiseGatePolicy replaces an inherited policy for an owner with a copy
// of it, in one transaction: the copy is saved as the owner's and the
// inherited policy is turned off there. Audited as gate_policy.create (the
// copy) and gate_policy.customise. It returns the copy.
func (s *Store) CustomiseGatePolicy(ctx context.Context, copy GatePolicy, a Actor) (*GatePolicy, error) {
	if copy.InheritsPolicyID == nil || copy.Owner().Org() {
		return nil, fmt.Errorf("a copy names the policy it replaces and its project or asset: %w", ErrInvalid)
	}
	var out *GatePolicy
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var err error
		if out, err = createGatePolicy(ctx, tx, copy, a); err != nil {
			return err
		}
		if err := setGatePolicyExcluded(ctx, tx, *copy.InheritsPolicyID, copy.Owner(), true, a); err != nil {
			return err
		}
		return gateAudit(ctx, tx, a, "gate_policy.customise", *copy.InheritsPolicyID, GatePolicyAudit{PolicyID: *copy.InheritsPolicyID,
			ProjectID: copy.OwnerProjectID, AssetID: copy.OwnerAssetID, CopyID: &out.ID,
			Summary: fmt.Sprintf("Policy %q replaced by an edited copy for %s", out.Name, ownerWords(copy.Owner()))})
	})
	return out, err
}

// gateScopeSQL selects (policy_id, asset_id) for every policy that reaches
// an asset, before filters: the organisation's policies reach every asset
// except where turned off (for the asset, or for every active project the
// asset is in); a project's reach its active assets; an asset's reach it.
// An asset's own turn-off applies to whatever it inherits.
//
// Parameters: $1 policy id (0: all), $2 asset id (0: all), $3 every mode
// (false: leave out policies that are off).
const gateScopeSQL = `
	pol AS (SELECT g.* FROM gate_policies g WHERE ($1::bigint = 0 OR g.id = $1) AND ($3::boolean OR g.mode <> 'off')),
	ap AS (SELECT pa.asset_id, pa.project_id FROM project_assets pa JOIN projects p ON p.id = pa.project_id WHERE p.archived_at IS NULL),
	reach AS (
		SELECT g.id AS policy_id, a.id AS asset_id FROM pol g CROSS JOIN assets a
		WHERE g.owner_project_id IS NULL AND g.owner_asset_id IS NULL AND ($2::bigint = 0 OR a.id = $2)
		  AND NOT (EXISTS (SELECT 1 FROM ap WHERE ap.asset_id = a.id)
		       AND NOT EXISTS (SELECT 1 FROM ap WHERE ap.asset_id = a.id AND NOT EXISTS (
		           SELECT 1 FROM gate_policy_exclusions e WHERE e.policy_id = g.id AND e.project_id = ap.project_id)))
		UNION
		SELECT g.id, ap.asset_id FROM pol g JOIN ap ON ap.project_id = g.owner_project_id WHERE ($2::bigint = 0 OR ap.asset_id = $2)
		UNION
		SELECT g.id, g.owner_asset_id FROM pol g WHERE g.owner_asset_id IS NOT NULL AND ($2::bigint = 0 OR g.owner_asset_id = $2)
	)`

// gateFilterSQL keeps the assets a policy's filters match ($4: the risk
// policy's production environments, lower case).
const gateFilterSQL = `a.merged_into IS NULL
	AND NOT EXISTS (SELECT 1 FROM gate_policy_exclusions e WHERE e.policy_id = g.id AND e.asset_id = a.id)
	AND (jsonb_array_length(COALESCE(g.filters->'asset_kinds', '[]')) = 0 OR g.filters->'asset_kinds' ? lower(a.kind))
	AND (jsonb_array_length(COALESCE(g.filters->'environments', '[]')) = 0
	     OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(g.filters->'environments') x WHERE lower(x) = lower(a.environment))
	     OR (g.filters->'environments' ? 'production' AND lower(a.environment) = ANY($4::text[])))
	AND (jsonb_array_length(COALESCE(g.filters->'tags', '[]')) = 0
	     OR a.tags && ARRAY(SELECT jsonb_array_elements_text(g.filters->'tags')))
	AND (COALESCE(g.filters->>'exposure', 'any') <> 'exposed' OR (` + effectiveExposure + `) IS TRUE)`

func (s *Store) productionEnvironments(ctx context.Context) ([]string, error) {
	p, err := s.RiskPolicy(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(p.ProductionEnvironments))
	for _, e := range p.ProductionEnvironments {
		out = append(out, strings.ToLower(e))
	}
	return out, nil
}

// EffectiveGatePolicies returns the policies that apply to an asset, after
// inheritance, turn-offs, copies and filters, including those whose mode is
// off (callers that gate skip them).
func (s *Store) EffectiveGatePolicies(ctx context.Context, assetID int64) ([]GatePolicy, error) {
	prod, err := s.productionEnvironments(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `WITH `+gateScopeSQL+`
		SELECT `+gatePolicyColsAs("g")+` FROM reach r JOIN gate_policies g ON g.id = r.policy_id JOIN assets a ON a.id = r.asset_id
		WHERE `+gateFilterSQL+` ORDER BY g.name, g.id`, int64(0), assetID, true, prod)
	if err != nil {
		return nil, err
	}
	return scanGatePolicies(rows)
}

func gatePolicyColsAs(alias string) string {
	parts := strings.Split(gatePolicyCols, ",")
	for i, p := range parts {
		parts[i] = alias + "." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

// GateViolationFilter narrows GateViolations: 0 means any.
type GateViolationFilter struct {
	PolicyID  int64
	AssetID   int64
	ProjectID int64
}

// GateViolation is one finding or leaked key that fails a policy.
type GateViolation struct {
	PolicyID   int64  `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Mode       string `json:"mode"`
	Kind       string `json:"kind"`
	AssetID    int64  `json:"asset_id"`
	AssetName  string `json:"asset_name"`
	// Reason says, in a sentence, why it fails the policy.
	Reason    string `json:"reason"`
	FindingID *int64 `json:"finding_id,omitempty"`
	LeakID    *int64 `json:"leak_id,omitempty"`
	// Component is the component's name and version ("" for a leak).
	Component string `json:"component"`
	// Key is the finding's advisory or end-of-life key, or the leak's rule.
	Key  string `json:"key"`
	Link string `json:"link"`
	// ViolationKey identifies the violation across rollups:
	// "finding:<id>" or "leak:<id>".
	ViolationKey string `json:"violation_key"`
}

// gateViolationsSQL lists violations. Parameters: $1 policy, $2 asset (0:
// all), $3 false (policies that are off never violate), $4 production
// environments, $5 now, $6 project (0: all).
//
// Findings that are suppressed (snoozed), risk-accepted or rejected as
// false positives never count, as in the CLI gate (cmd/stackurity/gate.go).
// Approved exceptions that have not expired take out what they cover.
var gateViolationsSQL = `WITH ` + gateScopeSQL + `,
	scoped AS (
		SELECT g.id AS policy_id, g.name, g.mode, g.kind, g.params, a.id AS asset_id, a.name AS asset_name
		FROM reach r JOIN pol g ON g.id = r.policy_id JOIN assets a ON a.id = r.asset_id
		WHERE ` + gateFilterSQL + `
		  AND ($6::bigint = 0 OR EXISTS (SELECT 1 FROM ap WHERE ap.asset_id = a.id AND ap.project_id = $6))
	),
	v AS (
		SELECT s.policy_id, s.name, s.mode, s.kind, s.asset_id, s.asset_name, f.id AS finding_id, NULL::bigint AS leak_id,
		  f.key, f.title, f.severity, c.name AS component, i.version, c.purl_key,
		  COALESCE(f.due_from, f.first_seen) AS since, COALESCE(f.evidence->>'eol_date', '') AS eol_date,
		  COALESCE((s.params->>'max_days')::int, 0) AS max_days, '' AS path, 0 AS line, '' AS exposure
		FROM scoped s
		JOIN findings f ON f.asset_id = s.asset_id AND f.status = 'open'
		  AND f.state NOT IN ('suppressed', 'risk_accepted') AND f.verification <> 'rejected'
		JOIN inventory i ON i.id = f.inventory_id
		JOIN components c ON c.id = f.component_id
		WHERE (s.kind = 'known_exploited' AND COALESCE((f.evidence->>'known_exploited')::boolean, false))
		   OR (s.kind = 'end_of_life' AND f.kind = 'end_of_life'
		       AND (jsonb_array_length(COALESCE(s.params->'products', '[]')) = 0 OR s.params->'products' ? (f.evidence->>'product')))
		   OR (s.kind = 'finding_age' AND f.kind = 'vulnerability'
		       AND ` + gateSeverityRank("f.severity") + ` >= ` + gateSeverityRank("s.params->>'min_severity'") + `
		       AND COALESCE(f.due_from, f.first_seen) < $5::timestamptz - make_interval(days => (s.params->>'max_days')::int)
		       AND (NOT COALESCE((s.params->>'only_fixable')::boolean, false)
		            OR (f.fixed_version <> '' AND NOT COALESCE((f.evidence->>'requires_ubuntu_pro')::boolean, false)
		                AND COALESCE(f.evidence->>'requires_subscription', '') = '')))
		UNION ALL
		SELECT s.policy_id, s.name, s.mode, s.kind, s.asset_id, s.asset_name, NULL, l.id,
		  l.rule, COALESCE(NULLIF(l.title, ''), l.rule), l.severity, '', '', '',
		  l.first_seen, '', 0, l.path, l.line, l.exposure
		FROM scoped s JOIN leaks l ON l.asset_id = s.asset_id AND l.status = 'open'
		WHERE s.kind = 'leaked_key'
		  AND ` + gateSeverityRank("l.severity") + ` >= ` + gateSeverityRank("COALESCE(s.params->>'min_severity', 'low')") + `
		  AND (NOT COALESCE((s.params->>'served_only')::boolean, false) OR l.exposure = 'served')
	)
	SELECT v.policy_id, v.name, v.mode, v.kind, v.asset_id, v.asset_name, v.finding_id, v.leak_id, v.key, v.title, v.severity,
	  v.component, v.version, v.since, v.eol_date, v.max_days, v.path, v.line, v.exposure
	FROM v
	WHERE NOT EXISTS (SELECT 1 FROM gate_policy_exceptions x
		WHERE x.policy_id = v.policy_id AND x.asset_id = v.asset_id AND x.status = 'approved' AND x.expires_at > $5::timestamptz
		  AND (x.target_kind = 'asset'
		       OR (x.target_kind = 'finding' AND (x.finding_id = v.finding_id OR x.leak_id = v.leak_id))
		       OR (x.target_kind = 'component' AND v.purl_key <> '' AND x.component_key = v.purl_key)))
	ORDER BY v.name, v.policy_id, v.asset_name, v.asset_id, v.finding_id NULLS LAST, v.leak_id`

// GateViolations computes the violations of the policies that are not off,
// now.
func (s *Store) GateViolations(ctx context.Context, f GateViolationFilter) ([]GateViolation, error) {
	return s.gateViolationsAt(ctx, f, time.Now())
}

func (s *Store) gateViolationsAt(ctx context.Context, f GateViolationFilter, now time.Time) ([]GateViolation, error) {
	prod, err := s.productionEnvironments(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, gateViolationsSQL, f.PolicyID, f.AssetID, false, prod, now, f.ProjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GateViolation{}
	for rows.Next() {
		var (
			v                              GateViolation
			title, severity, comp, version string
			since                          time.Time
			eolDate, path, exposure        string
			maxDays, line                  int
		)
		if err := rows.Scan(&v.PolicyID, &v.PolicyName, &v.Mode, &v.Kind, &v.AssetID, &v.AssetName, &v.FindingID, &v.LeakID, &v.Key,
			&title, &severity, &comp, &version, &since, &eolDate, &maxDays, &path, &line, &exposure); err != nil {
			return nil, err
		}
		if comp != "" {
			v.Component = strings.TrimSpace(comp + " " + version)
		}
		switch {
		case v.FindingID != nil:
			v.ViolationKey = "finding:" + strconv.FormatInt(*v.FindingID, 10)
			v.Link = "/findings/" + strconv.FormatInt(*v.FindingID, 10)
		case v.LeakID != nil:
			v.ViolationKey = "leak:" + strconv.FormatInt(*v.LeakID, 10)
			v.Link = fmt.Sprintf("/assets/%d?tab=leaks&leak=%d", v.AssetID, *v.LeakID)
		}
		v.Reason = gateReason(v, title, severity, since, eolDate, maxDays, path, line, exposure, now)
		out = append(out, v)
	}
	return out, rows.Err()
}

// gateReason says why a violation fails its policy, in one sentence.
func gateReason(v GateViolation, title, severity string, since time.Time, eolDate string, maxDays int, path string, line int, exposure string, now time.Time) string {
	in := ""
	if v.Component != "" {
		in = " in " + v.Component
	}
	switch v.Kind {
	case GateKnownExploited:
		return fmt.Sprintf("%s%s is known to be exploited", v.Key, in)
	case GateEndOfLife:
		if v.Component == "" {
			return title
		}
		if eolDate != "" {
			return fmt.Sprintf("%s is past its end of life (%s, support ended %s)", v.Component, v.Key, eolDate)
		}
		return fmt.Sprintf("%s is past its end of life (%s)", v.Component, v.Key)
	case GateFindingAge:
		days := int(now.Sub(since).Hours() / 24)
		return fmt.Sprintf("%s%s (%s) has been open for %d days; the limit is %d", v.Key, in, severity, days, maxDays)
	case GateLeakedKey:
		where := path
		if line > 0 {
			where = fmt.Sprintf("%s:%d", path, line)
		}
		s := fmt.Sprintf("A %s %s is written in %s", severity, title, where)
		switch exposure {
		case "served":
			s += ", which the asset serves to the network"
		case "world_readable":
			s += ", which every user on the host can read"
		}
		return s
	}
	return title
}

// RollupGatePolicies records the day's counts per policy for the workspace
// in ctx: violations and assets as now, and the violations opened and
// closed since the previous rollup (compared with gate_policy_open, which
// it then brings up to date). Run more than once a day, the counts add up
// and the day's violations are those of its last run. Policies that are
// off record zero and close what they had open.
func (s *Store) RollupGatePolicies(ctx context.Context, day time.Time) error {
	return s.rollupGatePoliciesAt(ctx, day, time.Now())
}

func (s *Store) rollupGatePoliciesAt(ctx context.Context, day, now time.Time) error {
	policies, err := s.ListGatePolicies(ctx)
	if err != nil || len(policies) == 0 {
		return err
	}
	vs, err := s.gateViolationsAt(ctx, GateViolationFilter{}, now)
	if err != nil {
		return err
	}
	keys := map[int64][]string{}
	assets := map[int64][]int64{}
	for _, v := range vs {
		keys[v.PolicyID] = append(keys[v.PolicyID], v.ViolationKey)
		assets[v.PolicyID] = append(assets[v.PolicyID], v.AssetID)
	}
	d := day.Format(time.DateOnly)
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		for _, p := range policies {
			k, a := keys[p.ID], assets[p.ID]
			if k == nil {
				k, a = []string{}, []int64{}
			}
			var opened, closed int
			// One statement per policy (a handful per organisation),
			// each set-based over that policy's violations.
			err := tx.QueryRow(ctx, `WITH cur AS (SELECT * FROM unnest($2::text[], $3::bigint[]) AS c(violation_key, asset_id)),
				gone AS (DELETE FROM gate_policy_open o WHERE o.policy_id = $1
					AND NOT EXISTS (SELECT 1 FROM cur WHERE cur.violation_key = o.violation_key) RETURNING 1),
				added AS (INSERT INTO gate_policy_open (policy_id, violation_key, asset_id, first_seen)
					SELECT DISTINCT ON (violation_key) $1, violation_key, asset_id, $4 FROM cur
					ON CONFLICT (policy_id, violation_key) DO NOTHING RETURNING 1)
				SELECT (SELECT count(*) FROM added), (SELECT count(*) FROM gone)`, p.ID, k, a, now).Scan(&opened, &closed)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO gate_policy_daily (day, policy_id, policy_name, mode, violations, assets, opened, closed, updated_at)
				VALUES ($1, $2, $3, $4, $5, (SELECT count(DISTINCT x) FROM unnest($6::bigint[]) x), $7, $8, $9)
				ON CONFLICT (workspace_id, policy_id, day) DO UPDATE SET policy_name = EXCLUDED.policy_name, mode = EXCLUDED.mode,
					violations = EXCLUDED.violations, assets = EXCLUDED.assets, opened = gate_policy_daily.opened + EXCLUDED.opened,
					closed = gate_policy_daily.closed + EXCLUDED.closed, updated_at = EXCLUDED.updated_at`,
				d, p.ID, p.Name, p.Mode, len(k), a, opened, closed, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// GatePolicyDay is one policy's counts on one day.
type GatePolicyDay struct {
	Day        time.Time `json:"day"`
	PolicyID   int64     `json:"policy_id"`
	PolicyName string    `json:"policy_name"`
	Mode       string    `json:"mode"`
	Violations int       `json:"violations"`
	Assets     int       `json:"assets"`
	Opened     int       `json:"opened"`
	Closed     int       `json:"closed"`
}

// GatePolicyDays returns the daily counts from first to last (dates,
// both included), by day then policy.
func (s *Store) GatePolicyDays(ctx context.Context, first, last time.Time) ([]GatePolicyDay, error) {
	rows, err := s.Pool.Query(ctx, `SELECT day, policy_id, policy_name, mode, violations, assets, opened, closed FROM gate_policy_daily
		WHERE day BETWEEN $1::date AND $2::date ORDER BY day, policy_id`, first.Format(time.DateOnly), last.Format(time.DateOnly))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[GatePolicyDay])
}

// GatePolicyException is one exception to a policy, as the evidence pack
// reads it.
type GatePolicyException struct {
	ID          int64  `json:"id"`
	PolicyID    int64  `json:"policy_id"`
	RuleVersion int    `json:"rule_version"`
	TargetKind  string `json:"target_kind"` // finding, asset or component
	AssetID     int64  `json:"asset_id"`
	FindingID   *int64 `json:"finding_id,omitempty"`
	LeakID      *int64 `json:"leak_id,omitempty"`
	// ComponentKey is the component's purl key, for a component target.
	ComponentKey    string     `json:"component_key,omitempty"`
	TargetLabel     string     `json:"target_label"`
	Reason          string     `json:"reason"`
	Note            string     `json:"note"`
	Status          string     `json:"status"`
	RequestedByName string     `json:"requested_by_name"`
	RequestedAt     time.Time  `json:"requested_at"`
	ApprovedByName  *string    `json:"approved_by_name"`
	ApprovedAt      *time.Time `json:"approved_at"`
	ExpiresAt       *time.Time `json:"expires_at"`
	// EndedAt and EndReason: when and why it stopped applying (expired,
	// revoked or fixed); an approved exception past its expiry is reported
	// as ended at its expiry with reason expired.
	EndedAt   *time.Time `json:"ended_at"`
	EndReason string     `json:"end_reason"`
}

// GatePolicyExceptions returns the exceptions of the workspace in ctx that
// were in force at any point from `from` to `to`: requested before `to`,
// and not ended or expired before `from`. Declined requests and requests
// still pending are included only if they were open in the window (they
// show what was asked); their ApprovedAt is nil.
func (s *Store) GatePolicyExceptions(ctx context.Context, from, to time.Time) ([]GatePolicyException, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, policy_id, rule_version, target_kind, asset_id, finding_id, leak_id, component_key, target_label,
			reason, note, status, requested_by_name, requested_at,
			CASE WHEN decided_at IS NOT NULL AND status IN ('approved', 'ended') THEN decided_by_name END,
			CASE WHEN status IN ('approved', 'ended') THEN decided_at END,
			expires_at,
			CASE WHEN ended_at IS NOT NULL THEN ended_at
			     WHEN status = 'approved' AND expires_at <= $3 THEN expires_at END,
			CASE WHEN ended_at IS NOT NULL THEN end_reason
			     WHEN status = 'approved' AND expires_at <= $3 THEN 'expired' ELSE '' END
		FROM gate_policy_exceptions
		WHERE requested_at < $2
		  AND (status <> 'declined' OR decided_at IS NULL OR decided_at >= $1)
		  AND (ended_at IS NULL OR ended_at >= $1)
		  AND (status <> 'approved' OR expires_at >= $1)
		ORDER BY requested_at, id`, from, to, time.Now())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[GatePolicyException])
}
