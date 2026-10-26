package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/risk"
)

const riskPolicyKey = "risk_policy"

// RiskPolicy returns the stored policy or the default.
func (s *Store) RiskPolicy(ctx context.Context) (risk.Policy, error) {
	var raw []byte
	err := s.Pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, riskPolicyKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return risk.DefaultPolicy(), nil
	}
	if err != nil {
		return risk.Policy{}, err
	}
	return decodeRiskPolicy(raw)
}

// decodeRiskPolicy reads a stored policy over the defaults, so a field added
// after it was saved takes its default value.
func decodeRiskPolicy(raw []byte) (risk.Policy, error) {
	p, err := risk.DecodePolicy(raw, false)
	if err != nil {
		return risk.Policy{}, fmt.Errorf("stored risk policy is invalid: %w", err)
	}
	return p.Normalize(), nil
}

// SetRiskPolicy stores a policy without an audit event (setup and tests);
// changes made by people go through ReplaceRiskPolicy.
func (s *Store) SetRiskPolicy(ctx context.Context, p risk.Policy) error {
	p = p.Normalize()
	if err := p.Validate(); err != nil {
		return err
	}
	raw, _ := json.Marshal(p)
	_, err := s.Pool.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
		ON CONFLICT (workspace_id, key) DO UPDATE SET value = EXCLUDED.value`, riskPolicyKey, raw)
	return err
}

// RiskPolicyChange is the detail of a risk_policy.update audit event: enough
// to see what changed and to rebuild either policy from the log.
type RiskPolicyChange struct {
	Before        risk.Policy `json:"before"`
	After         risk.Policy `json:"after"`
	BeforeVersion string      `json:"before_version"`
	AfterVersion  string      `json:"after_version"`
	Changed       []string    `json:"changed"` // top-level policy fields that differ
}

// ReplaceRiskPolicy validates and stores p and, in the same transaction,
// records a risk_policy.update audit event with the policy before and after,
// so every change is attributable and any version can be rebuilt.
func (s *Store) ReplaceRiskPolicy(ctx context.Context, p risk.Policy, a Actor) (RiskPolicyChange, error) {
	p = p.Normalize()
	if err := p.Validate(); err != nil {
		return RiskPolicyChange{}, err
	}
	var ch RiskPolicyChange
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		before := risk.DefaultPolicy()
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1 FOR UPDATE`, riskPolicyKey).Scan(&raw)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		default:
			if before, err = decodeRiskPolicy(raw); err != nil {
				return err
			}
		}
		ch = RiskPolicyChange{Before: before, After: p, BeforeVersion: before.Version(), AfterVersion: p.Version(),
			Changed: changedFields(before, p)}
		after, _ := json.Marshal(p)
		if _, err := tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
			ON CONFLICT (workspace_id, key) DO UPDATE SET value = EXCLUDED.value`, riskPolicyKey, after); err != nil {
			return err
		}
		d, _ := json.Marshal(ch)
		var id *int64
		if a.ID > 0 {
			id = &a.ID
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_events (actor_type, actor_id, actor_name, action, object_type, object_id, detail, remote_addr)
			VALUES ($1,$2,$3,'risk_policy.update','settings','risk_policy',$4,$5)`, a.Type, id, a.Name, d, a.RemoteAddr)
		return err
	})
	return ch, err
}

// changedFields lists the top-level JSON fields whose values differ.
func changedFields(a, b risk.Policy) []string {
	var ma, mb map[string]json.RawMessage
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	_ = json.Unmarshal(ja, &ma)
	_ = json.Unmarshal(jb, &mb)
	out := []string{}
	for k, v := range mb {
		if string(ma[k]) != string(v) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// effectiveExposure is an asset's internet exposure for risk: what an
// operator set, else what a collector observed (the exposure attribute of a
// Kubernetes workload), else, for an image, what the current workloads
// deployed as it say: exposed when any is, internal only when every one is
// internal. A workload whose exposure is unknown (Services or Ingresses
// unreadable) keeps the image unknown rather than internal. NULL means unknown.
const effectiveExposure = `COALESCE(a.internet_exposed,
		CASE a.attributes->>'exposure' WHEN 'external' THEN true WHEN 'internal' THEN false END,
		(SELECT CASE WHEN bool_or(w.attributes->>'exposure' = 'external') THEN true
		             WHEN bool_and(COALESCE(w.attributes->>'exposure', '') = 'internal') THEN false END
		 FROM asset_relations r JOIN assets w ON w.id = r.from_asset
		 WHERE r.to_asset = a.id AND r.kind = 'deployed_as' AND w.merged_into IS NULL AND w.collection_status <> 'stale'))`

// exposureSource says which of effectiveExposure's sources applies, for the
// explanation: risk.ExposureOperator, ExposureCollector, ExposureWorkloads, or
// empty when nothing recorded it.
const exposureSource = `CASE WHEN a.internet_exposed IS NOT NULL THEN 'operator'
		WHEN a.attributes->>'exposure' IN ('external', 'internal') THEN 'collector'
		WHEN EXISTS (SELECT 1 FROM asset_relations r JOIN assets w ON w.id = r.from_asset
		  WHERE r.to_asset = a.id AND r.kind = 'deployed_as' AND w.merged_into IS NULL AND w.collection_status <> 'stale') THEN 'workloads'
		WHEN a.attributes->>'exposure' IS NOT NULL THEN 'collector'
		ELSE '' END`

// riskRow is an open finding with everything the risk model looks at, as
// Prioritize and PreviewRiskPolicy read it.
type riskRow struct {
	id        int64
	in        risk.Input
	firstSeen time.Time
	title     string
	key       string
	assetID   int64
	assetName string
	priority  string // stored
}

// riskRows reads every open finding's risk inputs. Prioritize and the policy
// preview share it, so a preview scores exactly what a save would.
func riskRows(ctx context.Context, db q, now time.Time) ([]riskRow, error) {
	rows, err := db.Query(ctx, `SELECT f.id, f.kind, f.severity, f.score, COALESCE((f.evidence->>'known_exploited')::boolean, false),
		`+effectiveExposure+`, `+exposureSource+`, a.environment, a.criticality,
		f.fixed_version <> '' AND NOT COALESCE((f.evidence->>'requires_ubuntu_pro')::boolean, false)
		  AND COALESCE(f.evidence->>'requires_subscription', '') = '',
		i.scope, f.verification, f.first_seen, COALESCE((f.evidence->>'not_running_kernel')::boolean, false),
		f.priority, f.state, f.fix_due, f.title, f.key, a.id, a.name
		FROM findings f JOIN assets a ON a.id = f.asset_id JOIN inventory i ON i.id = f.inventory_id
		WHERE f.status = 'open'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []riskRow
	for rows.Next() {
		var (
			r      riskRow
			state  string
			fixDue *time.Time
		)
		if err := rows.Scan(&r.id, &r.in.Kind, &r.in.Severity, &r.in.Score, &r.in.KnownExploited, &r.in.InternetExposed, &r.in.ExposureSource,
			&r.in.Environment, &r.in.Criticality, &r.in.FixAvailable, &r.in.Scope, &r.in.Verification, &r.firstSeen, &r.in.KernelNotRunning,
			&r.priority, &state, &fixDue, &r.title, &r.key, &r.assetID, &r.assetName); err != nil {
			return nil, err
		}
		r.in.Overdue = fixDue != nil && now.After(*fixDue) && (state == "new" || state == "acknowledged" || state == "in_progress")
		out = append(out, r)
	}
	return out, rows.Err()
}

// Prioritize recomputes priority, SOS and deadlines for every open finding.
// Deadlines run from first detection; they move only when priority changes.
func (s *Store) Prioritize(ctx context.Context, p risk.Policy, now time.Time) (int, error) {
	rows, err := riskRows(ctx, s.Pool, now)
	if err != nil {
		return 0, err
	}
	type upd struct {
		id             int64
		res            risk.Result
		ackDue, fixDue time.Time
	}
	ups := make([]upd, 0, len(rows))
	version := p.Version()
	for _, r := range rows {
		res := p.Evaluate(r.in)
		ack, fix := p.Deadlines(res.Priority, r.firstSeen)
		ups = append(ups, upd{r.id, res, ack, fix})
	}
	batch := &pgx.Batch{}
	for _, u := range ups {
		factors, _ := json.Marshal(u.res.Factors)
		batch.Queue(`UPDATE findings SET priority = $2, priority_score = $3, priority_factors = $4, sos = $5, sos_rule = $8,
			ack_due = $6, fix_due = $7, priority_policy = $9,
			assignee_team_id = COALESCE(assignee_team_id, (SELECT owner_team_id FROM assets WHERE id = findings.asset_id))
			WHERE id = $1`, u.id, u.res.Priority, u.res.Score, factors, u.res.SOS, u.ackDue, u.fixDue, u.res.SOSRule, version)
	}
	if err := s.Pool.SendBatch(ctx, batch).Close(); err != nil {
		return 0, err
	}
	return len(ups), nil
}

// FindingAction is a workflow change requested by a person.
type FindingAction struct {
	Action     string     // acknowledge, start, reset, assign, suppress, accept_risk, reopen, comment
	Note       string     // reason; required for suppress and accept_risk
	Until      *time.Time // expiry for suppress / accept_risk
	Mitigation string     // optional for suppress / accept_risk
	MaxDays    int        // longest allowed expiry; 0 means DefaultExceptionMaxDays
	AssignUser *int64
	AssignTeam *int64
}

// DefaultExceptionMaxDays bounds suppression and risk acceptance when the
// policy does not say otherwise.
const DefaultExceptionMaxDays = risk.DefaultExceptionMaxDays

var ErrInvalidAction = errors.New("invalid action")

var stateFor = map[string]string{
	"acknowledge": "acknowledged", "start": "in_progress", "reset": "new",
	"suppress": "suppressed", "accept_risk": "risk_accepted", "reopen": "new",
}

// ApplyFindingAction changes a finding's workflow state and records history.
func (s *Store) ApplyFindingAction(ctx context.Context, id int64, a FindingAction, actor Actor) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var state, status string
		if err := tx.QueryRow(ctx, `SELECT state, status FROM findings WHERE id = $1 FOR UPDATE`, id).Scan(&state, &status); err != nil {
			return notFound(err)
		}
		to := state
		switch a.Action {
		case "acknowledge", "start", "reset":
			if state == "suppressed" || state == "risk_accepted" {
				return fmt.Errorf("%w: reopen the finding first", ErrInvalidAction)
			}
			to = stateFor[a.Action]
		case "suppress", "accept_risk":
			if a.Note == "" {
				return fmt.Errorf("%w: a reason is required", ErrInvalidAction)
			}
			maxDays := a.MaxDays
			if maxDays <= 0 {
				maxDays = DefaultExceptionMaxDays
			}
			if a.Until == nil || !a.Until.After(time.Now()) || a.Until.After(time.Now().AddDate(0, 0, maxDays)) {
				return fmt.Errorf("%w: an expiry within the next %d days is required", ErrInvalidAction, maxDays)
			}
			to = stateFor[a.Action]
		case "reopen":
			if state != "suppressed" && state != "risk_accepted" {
				return fmt.Errorf("%w: only suppressed or accepted findings can be reopened", ErrInvalidAction)
			}
			to = "new"
		case "assign", "comment":
		default:
			return fmt.Errorf("%w: unknown action %q", ErrInvalidAction, a.Action)
		}
		var uid *int64
		if actor.Type == "user" || (actor.Type == "token" && actor.ID > 0) {
			uid = &actor.ID
		}
		switch a.Action {
		case "acknowledge":
			if _, err := tx.Exec(ctx, `UPDATE findings SET state = $2, acknowledged_at = COALESCE(acknowledged_at, now()),
				acknowledged_by = COALESCE(acknowledged_by, $3) WHERE id = $1`, id, to, userIDOnly(actor)); err != nil {
				return err
			}
		case "start", "reset", "reopen":
			if _, err := tx.Exec(ctx, `UPDATE findings SET state = $2, suppressed_until = NULL, state_reason = '', mitigation = '' WHERE id = $1`, id, to); err != nil {
				return err
			}
		case "suppress", "accept_risk":
			if _, err := tx.Exec(ctx, `UPDATE findings SET state = $2, suppressed_until = $3, state_reason = $4, mitigation = $5 WHERE id = $1`,
				id, to, a.Until, a.Note, a.Mitigation); err != nil {
				return err
			}
		case "assign":
			if a.AssignUser == nil && a.AssignTeam == nil {
				return fmt.Errorf("%w: user_id or team_id is required", ErrInvalidAction)
			}
			if _, err := tx.Exec(ctx, `UPDATE findings SET
				assignee_user_id = CASE WHEN $2::bigint IS NULL THEN assignee_user_id WHEN $2 = 0 THEN NULL ELSE $2 END,
				assignee_team_id = CASE WHEN $3::bigint IS NULL THEN assignee_team_id WHEN $3 = 0 THEN NULL ELSE $3 END
				WHERE id = $1`, id, a.AssignUser, a.AssignTeam); err != nil {
				if isForeignKey(err) {
					return fmt.Errorf("%w: no such user or team", ErrInvalidAction)
				}
				return err
			}
		}
		detail := map[string]any{}
		if a.Until != nil {
			detail["until"] = a.Until.UTC().Format(time.RFC3339)
		}
		if a.Mitigation != "" {
			detail["mitigation"] = a.Mitigation
		}
		if a.AssignUser != nil {
			detail["user_id"] = *a.AssignUser
			var email string
			_ = tx.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, *a.AssignUser).Scan(&email)
			detail["user_email"] = email
		}
		if a.AssignTeam != nil {
			detail["team_id"] = *a.AssignTeam
			var name string
			_ = tx.QueryRow(ctx, `SELECT name FROM teams WHERE id = $1`, *a.AssignTeam).Scan(&name)
			detail["team_name"] = name
		}
		d, _ := json.Marshal(detail)
		_, err := tx.Exec(ctx, `INSERT INTO finding_events (finding_id, actor_type, actor_id, actor_name, action, from_state, to_state, note, detail)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, actor.Type, uid, actor.Name, a.Action, state, to, a.Note, d)
		return err
	})
}

func userIDOnly(a Actor) *int64 {
	if a.Type == "user" && a.ID > 0 {
		return &a.ID
	}
	return nil
}

func isForeignKey(err error) bool {
	var pe interface{ SQLState() string }
	return errors.As(err, &pe) && pe.SQLState() == "23503"
}

type FindingEvent struct {
	ID        int64           `json:"id"`
	At        time.Time       `json:"at"`
	ActorType string          `json:"actor_type"`
	ActorName string          `json:"actor_name"`
	Action    string          `json:"action"`
	FromState string          `json:"from_state"`
	ToState   string          `json:"to_state"`
	Note      string          `json:"note"`
	Detail    json.RawMessage `json:"detail"`
}

func (s *Store) FindingEvents(ctx context.Context, id int64) ([]FindingEvent, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, at, actor_type, actor_name, action, from_state, to_state, note, detail
		FROM finding_events WHERE finding_id = $1 ORDER BY at, id`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[FindingEvent])
}

// ExpireSuppressions returns findings whose suppression or risk acceptance
// has lapsed to 'new' so they are reviewed again.
func (s *Store) ExpireSuppressions(ctx context.Context) (int64, error) {
	var n int64
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE findings SET state = 'new', suppressed_until = NULL
			WHERE state IN ('suppressed', 'risk_accepted') AND suppressed_until <= now()
			RETURNING id, state_reason`)
		if err != nil {
			return err
		}
		type ex struct {
			id     int64
			reason string
		}
		var list []ex
		for rows.Next() {
			var e ex
			if err := rows.Scan(&e.id, &e.reason); err != nil {
				rows.Close()
				return err
			}
			list = append(list, e)
		}
		rows.Close()
		for _, e := range list {
			if _, err := tx.Exec(ctx, `INSERT INTO finding_events (finding_id, actor_type, actor_name, action, from_state, to_state, note)
				VALUES ($1, 'system', 'expiry', 'expired', 'suppressed', 'new', $2)`, e.id, "expired: "+e.reason); err != nil {
				return err
			}
		}
		n = int64(len(list))
		return nil
	})
	return n, err
}

// Incident is the notification unit.
type Incident struct {
	ID               int64           `json:"id"`
	Kind             string          `json:"kind"`
	Key              string          `json:"key"`
	OwnerTeamID      *int64          `json:"owner_team_id"`
	OwnerTeam        string          `json:"owner_team"`
	Title            string          `json:"title"`
	Priority         string          `json:"priority"`
	SOS              bool            `json:"sos"`
	Status           string          `json:"status"`
	State            string          `json:"state"`
	FindingCount     int             `json:"finding_count"`
	AssetCount       int             `json:"asset_count"`
	Detail           json.RawMessage `json:"detail"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
	ResolvedAt       *time.Time      `json:"resolved_at"`
	NotifiedPriority string          `json:"notified_priority"`
	NotifiedAt       *time.Time      `json:"notified_at"`
	EscalationLevel  int             `json:"escalation_level"`
	// Issues are the tracker issues (Jira) that follow this incident; only
	// ListIncidents and GetIncident fill them.
	Issues []IssueRef `json:"issues,omitempty" db:"-"`
}

const incidentCols = `i.id, i.kind, i.key, i.owner_team_id, COALESCE(t.name, ''), i.title, i.priority, i.sos, i.status, i.state,
	i.finding_count, i.asset_count, i.detail, i.created_at, i.updated_at, i.resolved_at, i.notified_priority, i.notified_at, i.escalation_level`

// CorrelateIncidents groups active findings (open and not suppressed) into
// incidents by (kind, key, owner team) and resolves incidents with nothing
// active left. It is idempotent: reprocessing never duplicates incidents.
func (s *Store) CorrelateIncidents(ctx context.Context) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		// Serialise correlation so two workers cannot race on the unique index.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(726354101)`); err != nil {
			return err
		}
		stmts := []string{
			`CREATE TEMP TABLE active_groups ON COMMIT DROP AS
			 SELECT f.kind, f.key, a.owner_team_id,
			   (array_agg(f.title ORDER BY f.priority_score DESC))[1] AS title,
			   min(f.priority) AS priority, bool_or(f.sos) AS sos,
			   CASE WHEN bool_or(f.state = 'new') THEN 'new' WHEN bool_or(f.state = 'acknowledged') THEN 'acknowledged' ELSE 'in_progress' END AS state,
			   count(*) AS finding_count, count(DISTINCT f.asset_id) AS asset_count,
			   jsonb_build_object(
			     'assets', (array_agg(DISTINCT a.name))[1:10],
			     'environments', array_agg(DISTINCT a.environment) FILTER (WHERE a.environment <> ''),
			     'components', (array_agg(DISTINCT CASE WHEN c.namespace = '' THEN c.name ELSE c.namespace || '/' || c.name END))[1:10],
			     'fixed_versions', array_agg(DISTINCT f.fixed_version) FILTER (WHERE f.fixed_version <> ''),
			     'known_exploited', bool_or(COALESCE((f.evidence->>'known_exploited')::boolean, false)),
			     'severity', (array_agg(f.severity ORDER BY f.priority_score DESC))[1],
			     'sos_rules', array_agg(DISTINCT f.priority_factors::text) FILTER (WHERE f.sos)
			   ) AS detail
			 FROM findings f JOIN assets a ON a.id = f.asset_id JOIN components c ON c.id = f.component_id
			 WHERE f.status = 'open' AND f.state IN ('new', 'acknowledged', 'in_progress') AND a.merged_into IS NULL
			 GROUP BY f.kind, f.key, a.owner_team_id`,
			// Ownership changed: move the open incident to the new owner
			// rather than resolving it and opening another (which would send
			// a false "resolved" notice).
			`UPDATE incidents i SET owner_team_id = g.owner_team_id, updated_at = now()
			 FROM active_groups g
			 WHERE i.status = 'open' AND i.kind = g.kind AND i.key = g.key
			   AND COALESCE(i.owner_team_id, 0) <> COALESCE(g.owner_team_id, 0)
			   AND NOT EXISTS (SELECT 1 FROM active_groups g2 WHERE g2.kind = i.kind AND g2.key = i.key
			     AND COALESCE(g2.owner_team_id, 0) = COALESCE(i.owner_team_id, 0))
			   AND NOT EXISTS (SELECT 1 FROM incidents i2 WHERE i2.status = 'open' AND i2.kind = g.kind AND i2.key = g.key
			     AND COALESCE(i2.owner_team_id, 0) = COALESCE(g.owner_team_id, 0))
			   AND g.owner_team_id IS NOT DISTINCT FROM (SELECT g3.owner_team_id FROM active_groups g3
			     WHERE g3.kind = i.kind AND g3.key = i.key ORDER BY g3.owner_team_id NULLS LAST LIMIT 1)`,
			`INSERT INTO incidents AS i (kind, key, owner_team_id, title, priority, sos, state, finding_count, asset_count, detail)
			 SELECT kind, key, owner_team_id, title, priority, sos, state, finding_count, asset_count, detail - 'sos_rules' FROM active_groups
			 ON CONFLICT (workspace_id, kind, key, COALESCE(owner_team_id, 0)) WHERE status = 'open' DO UPDATE SET
			   title = EXCLUDED.title, priority = EXCLUDED.priority, sos = EXCLUDED.sos, state = EXCLUDED.state,
			   finding_count = EXCLUDED.finding_count, asset_count = EXCLUDED.asset_count, detail = EXCLUDED.detail,
			   updated_at = CASE WHEN (i.priority, i.sos, i.state, i.finding_count, i.asset_count) IS DISTINCT FROM
			     (EXCLUDED.priority, EXCLUDED.sos, EXCLUDED.state, EXCLUDED.finding_count, EXCLUDED.asset_count) THEN now() ELSE i.updated_at END`,
			`UPDATE findings f SET incident_id = i.id
			 FROM assets a, incidents i
			 WHERE a.id = f.asset_id AND i.status = 'open' AND i.kind = f.kind AND i.key = f.key
			   AND COALESCE(i.owner_team_id, 0) = COALESCE(a.owner_team_id, 0)
			   AND f.status = 'open' AND f.incident_id IS DISTINCT FROM i.id`,
			`UPDATE incidents i SET status = 'resolved', resolved_at = now(), updated_at = now()
			 WHERE i.status = 'open' AND i.kind IN ('vulnerability', 'end_of_life')
			   AND NOT EXISTS (SELECT 1 FROM active_groups g WHERE g.kind = i.kind AND g.key = i.key
			     AND COALESCE(g.owner_team_id, 0) = COALESCE(i.owner_team_id, 0))`,
		}
		for _, q := range stmts {
			if _, err := tx.Exec(ctx, q); err != nil {
				return err
			}
		}
		return nil
	})
}

// SystemIncident describes a collection, feed or coverage problem.
type SystemIncident struct {
	Kind        string
	Key         string
	OwnerTeamID *int64
	Title       string
	Priority    string
	Detail      map[string]any
}

// SyncSystemIncidents opens incidents for current system problems and
// resolves those no longer present.
func (s *Store) SyncSystemIncidents(ctx context.Context, current []SystemIncident) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(726354101)`); err != nil {
			return err
		}
		keys := make([]string, 0, len(current))
		for _, c := range current {
			d, _ := json.Marshal(c.Detail)
			if _, err := tx.Exec(ctx, `INSERT INTO incidents AS i (kind, key, owner_team_id, title, priority, detail, finding_count, asset_count)
				VALUES ($1,$2,$3,$4,$5,$6,0,0)
				ON CONFLICT (workspace_id, kind, key, COALESCE(owner_team_id, 0)) WHERE status = 'open' DO UPDATE SET
				  title = EXCLUDED.title, detail = EXCLUDED.detail,
				  priority = EXCLUDED.priority, updated_at = CASE WHEN i.priority <> EXCLUDED.priority THEN now() ELSE i.updated_at END`,
				c.Kind, c.Key, c.OwnerTeamID, c.Title, c.Priority, d); err != nil {
				return err
			}
			keys = append(keys, c.Kind+"|"+c.Key)
		}
		_, err := tx.Exec(ctx, `UPDATE incidents SET status = 'resolved', resolved_at = now(), updated_at = now()
			WHERE status = 'open' AND kind IN ('feed', 'collection', 'coverage', 'platform') AND NOT (kind || '|' || key = ANY($1))`, keys)
		return err
	})
}

// DetectSystemProblems finds stale or failing feeds, stale assets, failing
// integrations and sharp drops in collected inventory (FR-08, FR-16).
func (s *Store) DetectSystemProblems(ctx context.Context) ([]SystemIncident, error) {
	var out []SystemIncident
	rows, err := s.Pool.Query(ctx, `SELECT name, kind, last_error, last_success,
		last_success IS NULL OR last_success < now() - stale_after
		FROM feeds WHERE enabled AND (last_error <> '' OR last_success IS NULL OR last_success < now() - stale_after)
		  AND (last_attempt IS NOT NULL)`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name, kind, lastErr string
		var lastOK *time.Time
		var stale bool
		if err := rows.Scan(&name, &kind, &lastErr, &lastOK, &stale); err != nil {
			rows.Close()
			return nil, err
		}
		if !stale {
			continue // a transient error with recent success is not yet an incident
		}
		pri := "P3"
		if kind == "vulnerability" {
			pri = "P2" // findings for this ecosystem are going out of date
		}
		out = append(out, SystemIncident{Kind: "feed", Key: name, Title: "Intelligence feed " + name + " is stale",
			Priority: pri, Detail: map[string]any{"last_error": lastErr, "last_success": lastOK}})
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `SELECT id, name, owner_team_id, last_seen FROM assets
		WHERE merged_into IS NULL AND collection_status = 'stale'`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var name string
		var team *int64
		var seen time.Time
		if err := rows.Scan(&id, &name, &team, &seen); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, SystemIncident{Kind: "collection", Key: fmt.Sprintf("asset:%d", id), OwnerTeamID: team,
			Title: "Asset " + name + " has stopped reporting", Priority: "P3", Detail: map[string]any{"asset_id": id, "last_seen": seen}})
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `SELECT i.id, i.name, a.owner_team_id, i.last_error, i.last_success FROM integrations i
		LEFT JOIN assets a ON a.id = i.asset_id
		WHERE i.enabled AND i.last_error <> '' AND (i.last_success IS NULL OR i.last_success < now() - 2 * i.schedule)`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var name, lastErr string
		var team *int64
		var ok *time.Time
		if err := rows.Scan(&id, &name, &team, &lastErr, &ok); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, SystemIncident{Kind: "collection", Key: fmt.Sprintf("integration:%d", id), OwnerTeamID: team,
			Title: "Integration " + name + " is failing", Priority: "P3", Detail: map[string]any{"last_error": lastErr, "last_success": ok}})
	}
	rows.Close()

	// Coverage regression: the latest complete collection found under half
	// of what the previous one did.
	rows, err = s.Pool.Query(ctx, `WITH ranked AS (
		  SELECT asset_id, collector_id, observation_count, received_at,
		    row_number() OVER (PARTITION BY asset_id, collector_id ORDER BY received_at DESC) AS rn
		  FROM collections WHERE complete)
		SELECT cur.asset_id, a.name, a.owner_team_id, cur.collector_id, prev.observation_count, cur.observation_count
		FROM ranked cur JOIN ranked prev ON prev.asset_id = cur.asset_id AND prev.collector_id = cur.collector_id AND prev.rn = 2
		JOIN assets a ON a.id = cur.asset_id
		WHERE cur.rn = 1 AND a.merged_into IS NULL AND prev.observation_count >= 10
		  AND cur.observation_count * 2 < prev.observation_count`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var name, collector string
		var team *int64
		var before, after int
		if err := rows.Scan(&id, &name, &team, &collector, &before, &after); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, SystemIncident{Kind: "coverage", Key: fmt.Sprintf("asset:%d:%s", id, collector), OwnerTeamID: team,
			Title: fmt.Sprintf("Inventory for %s dropped from %d to %d components", name, before, after), Priority: "P3",
			Detail: map[string]any{"asset_id": id, "collector": collector, "before": before, "after": after}})
	}
	rows.Close()
	return out, rows.Err()
}

type IncidentFilter struct {
	Status    string
	Kind      string
	Priority  string
	SOS       bool
	Escalated bool
	TeamID    int64
	Page
}

func (s *Store) ListIncidents(ctx context.Context, f IncidentFilter) ([]Incident, int64, error) {
	w := &where{}
	status := f.Status
	if status == "" {
		status = "open"
	}
	if status != "all" {
		w.add("i.status = ?", status)
	}
	if f.Kind != "" {
		w.add("i.kind = ?", f.Kind)
	}
	if f.Priority != "" {
		w.add("i.priority = ?", f.Priority)
	}
	if f.SOS {
		w.conds = append(w.conds, "i.sos")
	}
	if f.Escalated {
		w.conds = append(w.conds, "i.escalation_level > 0")
	}
	if f.TeamID > 0 {
		w.add("i.owner_team_id = ?", f.TeamID)
	}
	from := ` FROM incidents i LEFT JOIN teams t ON t.id = i.owner_team_id` + w.sql()
	var total int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*)`+from, w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	p := f.Page.norm()
	rows, err := s.Pool.Query(ctx, `SELECT `+incidentCols+from+fmt.Sprintf(` ORDER BY i.sos DESC, i.priority, i.updated_at DESC LIMIT %d OFFSET %d`, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Incident])
	if err != nil {
		return nil, 0, err
	}
	ids := make([]int64, len(out))
	for i := range out {
		ids[i] = out[i].ID
	}
	refs, err := s.issueRefs(ctx, ids)
	if err != nil {
		return nil, 0, err
	}
	for i := range out {
		out[i].Issues = refs[out[i].ID]
	}
	return out, total, nil
}

func (s *Store) GetIncident(ctx context.Context, id int64) (*Incident, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+incidentCols+` FROM incidents i LEFT JOIN teams t ON t.id = i.owner_team_id WHERE i.id = $1`, id)
	if err != nil {
		return nil, err
	}
	in, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Incident])
	if err != nil {
		return nil, notFound(err)
	}
	refs, err := s.issueRefs(ctx, []int64{id})
	if err != nil {
		return nil, err
	}
	in.Issues = refs[id]
	return in, nil
}

// IncidentFindingIDs returns the open findings in an incident.
func (s *Store) IncidentFindingIDs(ctx context.Context, id int64) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id FROM findings WHERE incident_id = $1 AND status = 'open' ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// MarkIncidentNotified records the highest priority announced.
func (s *Store) MarkIncidentNotified(ctx context.Context, id int64, priority string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE incidents SET notified_priority = $2, notified_at = now() WHERE id = $1`, id, priority)
	return err
}

// EscalationCandidates returns open incidents whose acknowledgement or fix
// deadline has passed, with the escalation level they should now be at:
// 1 = acknowledgement overdue, 2 = fix overdue.
func (s *Store) EscalationCandidates(ctx context.Context) (map[int64]int, error) {
	rows, err := s.Pool.Query(ctx, `SELECT i.id,
		  CASE WHEN bool_or(f.fix_due < now()) THEN 2 WHEN bool_or(f.state = 'new' AND f.ack_due < now()) THEN 1 ELSE 0 END
		FROM incidents i JOIN findings f ON f.incident_id = i.id AND f.status = 'open'
		  AND f.state IN ('new', 'acknowledged', 'in_progress')
		WHERE i.status = 'open' GROUP BY i.id, i.escalation_level
		HAVING CASE WHEN bool_or(f.fix_due < now()) THEN 2 WHEN bool_or(f.state = 'new' AND f.ack_due < now()) THEN 1 ELSE 0 END > i.escalation_level`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var id int64
		var lvl int
		if err := rows.Scan(&id, &lvl); err != nil {
			return nil, err
		}
		out[id] = lvl
	}
	return out, rows.Err()
}

func (s *Store) SetIncidentEscalation(ctx context.Context, id int64, level int) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE incidents SET escalation_level = $2 WHERE id = $1`, id, level); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE findings SET escalation_level = GREATEST(escalation_level, $2), escalated_at = now()
			WHERE incident_id = $1 AND status = 'open'`, id, level)
		return err
	})
}
