package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/tenant"
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
	// xmin is the row version read; Prioritize writes only that version.
	xmin string
	// epssCVEs are the finding's CVEs that have an EPSS score, highest
	// first, with their scores; epssStored is the CVE it used until now
	// (findings.epss_cve, nil for its key). chooseEPSS picks among them.
	epssCVEs   []string
	epssScores []float32
	epssStored *string
}

// epssFactor matches stored priority_factors that include the EPSS factor.
var epssFactor = func() string {
	b, _ := json.Marshal([]map[string]string{{"name": risk.FactorEPSS}})
	return string(b)
}()

// riskRows reads every open finding's risk inputs. Prioritize and the policy
// preview share it, so a preview scores exactly what a save would.
// assetID 0 means every asset.
func riskRows(ctx context.Context, db q, now time.Time, assetID int64) ([]riskRow, error) {
	// EPSS: every CVE of the finding that has a score, highest first (a tie
	// goes to the key, then to the lowest CVE): its key and the CVEs its
	// advisories list as aliases or upstream ids (findingCVEs). Findings
	// share a few thousand distinct keys and sources, so the CVEs are looked
	// up once for each, in a query of their own, and matched to the findings
	// here: joining them in SQL on the sources array left the plan to the
	// planner's estimates, and one plan took most of an hour on 130,000
	// findings. chooseEPSS then picks the CVE to use.
	type group struct {
		cves   []string
		scores []float32
	}
	groupKey := func(key string, sources []string) string { return key + "\x00" + strings.Join(sources, "\x00") }
	groups := map[string]group{}
	grows, err := db.Query(ctx, `SELECT d.key, d.sources,
		  array_agg(e.cve ORDER BY e.score DESC, e.cve <> d.key, e.cve), array_agg(e.score ORDER BY e.score DESC, e.cve <> d.key, e.cve)
		FROM (SELECT DISTINCT f.key, f.sources FROM findings f
		  WHERE f.status = 'open' AND f.kind = 'vulnerability' AND ($1::bigint = 0 OR f.asset_id = $1)) d
		CROSS JOIN LATERAL `+findingCVEs("d")+` JOIN epss_scores e ON e.cve = fc.cve
		GROUP BY d.key, d.sources`, assetID)
	if err != nil {
		return nil, err
	}
	for grows.Next() {
		var key string
		var sources []string
		var g group
		if err := grows.Scan(&key, &sources, &g.cves, &g.scores); err != nil {
			grows.Close()
			return nil, err
		}
		groups[groupKey(key, sources)] = g
	}
	grows.Close()
	if err := grows.Err(); err != nil {
		return nil, err
	}
	// Whether the finding already had the EPSS factor is read from its
	// stored factors, for the policy's hysteresis.
	rows, err := db.Query(ctx, `SELECT f.id, f.kind, f.severity, f.score, COALESCE((f.evidence->>'known_exploited')::boolean, false),
		`+effectiveExposure+`, `+exposureSource+`, a.environment, a.criticality,
		f.fixed_version <> '' AND NOT COALESCE((f.evidence->>'requires_ubuntu_pro')::boolean, false)
		  AND COALESCE(f.evidence->>'requires_subscription', '') = '',
		i.scope, f.verification, f.first_seen, COALESCE((f.evidence->>'not_running_kernel')::boolean, false),
		f.priority, f.state, f.fix_due, f.title, f.key, a.id, a.name,
		f.sources, f.epss_cve, COALESCE(f.priority_factors @> $2::jsonb, false), f.xmin::text
		FROM findings f JOIN assets a ON a.id = f.asset_id JOIN inventory i ON i.id = f.inventory_id
		WHERE f.status = 'open' AND ($1::bigint = 0 OR f.asset_id = $1)
		ORDER BY f.id`, assetID, epssFactor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []riskRow
	for rows.Next() {
		var (
			r       riskRow
			state   string
			fixDue  *time.Time
			sources []string
		)
		if err := rows.Scan(&r.id, &r.in.Kind, &r.in.Severity, &r.in.Score, &r.in.KnownExploited, &r.in.InternetExposed, &r.in.ExposureSource,
			&r.in.Environment, &r.in.Criticality, &r.in.FixAvailable, &r.in.Scope, &r.in.Verification, &r.firstSeen, &r.in.KernelNotRunning,
			&r.priority, &state, &fixDue, &r.title, &r.key, &r.assetID, &r.assetName, &sources, &r.epssStored, &r.in.EPSSCounted, &r.xmin); err != nil {
			return nil, err
		}
		if r.in.Kind == "vulnerability" {
			g := groups[groupKey(r.key, sources)]
			r.epssCVEs, r.epssScores = g.cves, g.scores
		}
		r.in.Overdue = fixDue != nil && now.After(*fixDue) && (state == "new" || state == "acknowledged" || state == "in_progress")
		out = append(out, r)
	}
	return out, rows.Err()
}

// PrioritizeChunk is how many findings Prioritize writes in one transaction.
// A pass that changes every finding (a new risk policy, such as the one an
// upgrade brings) then holds row locks on one chunk at a time, for well
// under a second, rather than on every open finding until the pass ends, so
// evaluations, workflow actions and the API are not kept waiting.
var PrioritizeChunk = 1000

// afterPriorityChunk, when set (tests only), runs after each chunk is
// committed; an error stops the pass there, as a crash would.
var afterPriorityChunk func(written int) error

// Prioritize recomputes priority, SOS and deadlines for every open finding.
// Deadlines run from first detection; they move only when priority changes.
func (s *Store) Prioritize(ctx context.Context, p risk.Policy, now time.Time) (int, error) {
	return s.PrioritizeAsset(ctx, p, now, 0)
}

// PrioritizeAsset is Prioritize for one asset's open findings (0: all). The
// evaluate job runs it right after matching, so a collection reported as
// evaluated also has its priorities, and a CI gate never reads the defaults
// of findings the periodic pass has not scored yet.
//
// Every open finding is read in one query (reading takes no locks), then
// scored and written in chunks of PrioritizeChunk in id order, each chunk
// one short transaction. Every finding read is written at most once, in
// exactly one chunk. If the pass stops part way (an error, a restart), the
// chunks written stay written; the next pass reads every finding again and
// leaves alone those whose stored result is already right, so it finishes
// the job without rewriting what was done.
//
// A chunk is written up to a pass's length after the read (tens of seconds
// on a large workspace), so each write applies only to the row version that
// was read, and only while the finding is open. A finding resolved since is
// left with the priority it closed with; one changed since (an evaluation,
// which rescores it itself, or a workflow action) is left as it now is, and
// the next pass scores it from what it is then. The rows are not locked
// when read: locking every open finding every minute would write to each
// of them (and the WAL) even when nothing changes.
func (s *Store) PrioritizeAsset(ctx context.Context, p risk.Policy, now time.Time, assetID int64) (int, error) {
	rows, err := riskRows(ctx, s.Pool, now, assetID)
	if err != nil {
		return 0, err
	}
	version := p.Version()
	for start := 0; start < len(rows); start += PrioritizeChunk {
		end := min(start+PrioritizeChunk, len(rows))
		if err := s.writePriorities(ctx, p, version, rows[start:end]); err != nil {
			return start, err
		}
		if afterPriorityChunk != nil {
			if err := afterPriorityChunk(end); err != nil {
				return end, err
			}
		}
	}
	return len(rows), nil
}

// writePriorities scores one chunk of findings and stores the results that
// changed, in one transaction (one batch).
func (s *Store) writePriorities(ctx context.Context, p risk.Policy, version string, rows []riskRow) error {
	// Rows come in id order and are updated in that order, the order an
	// evaluation locks findings in, so the two cannot deadlock (see
	// SyncFindings).
	batch := &pgx.Batch{}
	for _, r := range rows {
		cve := chooseEPSS(p, &r)
		res := p.Evaluate(r.in)
		ackDue, fixDue := p.Deadlines(res.Priority, r.firstSeen)
		factors, _ := json.Marshal(res.Factors)
		// Rows whose result has not changed are left alone. This runs every
		// minute over every open finding; rewriting them all bloated the
		// table and kept the findings list from using index-only scans.
		batch.Queue(`UPDATE findings SET priority = $2, priority_score = $3, priority_factors = $4, sos = $5, sos_rule = $8,
			ack_due = $6, fix_due = $7, priority_policy = $9, epss_cve = $11,
			assignee_team_id = COALESCE(assignee_team_id, (SELECT owner_team_id FROM assets WHERE id = findings.asset_id))
			WHERE id = $1 AND status = 'open' AND xmin::text = $10 AND (
			  (priority, priority_score, priority_factors, sos, sos_rule, ack_due, fix_due, priority_policy, epss_cve)
			    IS DISTINCT FROM ($2::text, $3::real, $4::jsonb, $5::boolean, $8::text, $6::timestamptz, $7::timestamptz, $9::text, $11::text)
			  OR (assignee_team_id IS NULL AND (SELECT owner_team_id FROM assets WHERE id = findings.asset_id) IS NOT NULL))`,
			r.id, res.Priority, res.Score, factors, res.SOS, ackDue, fixDue, res.SOSRule, version, r.xmin, cve)
	}
	return s.Pool.SendBatch(ctx, batch).Close()
}

// FindingAction is a workflow change requested by a person.
type FindingAction struct {
	Action     string     // acknowledge, start, reset, assign, suppress, accept_risk, ignore, reopen, comment
	Note       string     // reason; required for suppress, accept_risk and ignore
	Until      *time.Time // expiry for suppress / accept_risk / ignore with expiry date
	Mitigation string     // optional for suppress / accept_risk / ignore
	MaxDays    int        // longest allowed expiry; 0 means DefaultExceptionMaxDays
	AssignUser *int64
	AssignTeam *int64
	// UntilFix snoozes (suppress) until a free fixed version exists; Until
	// is then optional and defaults to the exception limit as a backstop.
	UntilFix bool
	// Ignore: reason, scope (asset or everywhere) and expiry (date,
	// until_fix or never). See IgnoreSpec.
	Ignore IgnoreSpec
}

// DefaultExceptionMaxDays bounds suppression and risk acceptance when the
// policy does not say otherwise.
const DefaultExceptionMaxDays = risk.DefaultExceptionMaxDays

var ErrInvalidAction = errors.New("invalid action")

var stateFor = map[string]string{
	"acknowledge": "acknowledged", "start": "in_progress", "reset": "new",
	"suppress": "suppressed", "accept_risk": "risk_accepted", "ignore": "risk_accepted", "reopen": "new",
}

// ApplyFindingAction changes a finding's workflow state and records history.
func (s *Store) ApplyFindingAction(ctx context.Context, id int64, a FindingAction, actor Actor) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if a.Action == "ignore" {
			// The rule changes other findings of the issue too: lock them
			// all in id order first.
			if err := lockIssueFindings(ctx, tx, []int64{id}); err != nil {
				return err
			}
		}
		var state, status string
		var hasFix bool
		if err := tx.QueryRow(ctx, `SELECT state, status, `+freeFix("f")+` FROM findings f WHERE id = $1 FOR UPDATE`, id).Scan(&state, &status, &hasFix); err != nil {
			return notFound(err)
		}
		to := state
		maxDays := a.MaxDays
		if maxDays <= 0 {
			maxDays = DefaultExceptionMaxDays
		}
		var ignoreUntil *time.Time
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
			if a.UntilFix {
				if a.Action != "suppress" {
					return fmt.Errorf("%w: until a fix ships is for snoozing; to accept until a fix ships, ignore with that expiry", ErrInvalidAction)
				}
				if hasFix {
					return fmt.Errorf("%w: a fixed version already exists; install it, or snooze until a date", ErrInvalidAction)
				}
				if a.Until == nil {
					backstop := time.Now().AddDate(0, 0, maxDays)
					a.Until = &backstop
				}
			}
			if a.Until == nil || !a.Until.After(time.Now()) || a.Until.After(time.Now().AddDate(0, 0, maxDays).Add(time.Minute)) {
				return fmt.Errorf("%w: an expiry within the next %d days is required", ErrInvalidAction, maxDays)
			}
			to = stateFor[a.Action]
		case "ignore":
			if status != "open" {
				return fmt.Errorf("%w: the issue is fixed", ErrInvalidAction)
			}
			a.Ignore.Note = a.Note
			a.Ignore.Mitigation = a.Mitigation
			if a.Ignore.Expiry == ExpiryDate {
				a.Ignore.Until = a.Until
			}
			var err error
			if ignoreUntil, err = a.Ignore.resolve(maxDays, time.Now()); err != nil {
				return err
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
		var ruleID int64
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
			// A finding reopened from an ignore rule keeps exception_id, so
			// that rule does not ignore it again.
			if _, err := tx.Exec(ctx, `UPDATE findings SET state = $2, state_reason = '', mitigation = '', `+unIgnore+` WHERE id = $1`, id, to); err != nil {
				return err
			}
		case "suppress", "accept_risk":
			reason := ""
			if a.Action == "accept_risk" {
				reason = ReasonAcceptedRisk
			}
			if _, err := tx.Exec(ctx, `UPDATE findings SET state = $2, suppressed_until = $3, state_reason = $4, mitigation = $5,
				until_fix = $6, ignore_reason = $7 WHERE id = $1`,
				id, to, a.Until, a.Note, a.Mitigation, a.UntilFix, reason); err != nil {
				return err
			}
		case "ignore":
			rule, err := ignoreFinding(ctx, tx, id, a.Ignore, ignoreUntil, actor, 0)
			if err != nil {
				return err
			}
			a.Until = ignoreUntil
			a.Ignore.Until = nil
			ruleID = rule
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
		if a.UntilFix {
			detail["until_fix"] = true
		}
		if a.Action == "ignore" {
			detail["reason"], detail["scope"], detail["expiry"], detail["rule_id"] = a.Ignore.Reason, a.Ignore.Scope, a.Ignore.Expiry, ruleID
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

// Behind reports whether the incident groups behind findings (BehindRule),
// whose key ("behind:wordpress:6.5") is no advisory id: its detail says so.
func (in Incident) Behind() bool {
	var det struct {
		Behind bool `json:"behind"`
	}
	return json.Unmarshal(in.Detail, &det) == nil && det.Behind
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
			   COALESCE((array_agg(f.evidence->>'group_title' ORDER BY f.priority_score DESC) FILTER (WHERE NOT (` + notBehind + `)))[1],
			     (array_agg(f.title ORDER BY f.priority_score DESC))[1]) AS title,
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
			   ) || CASE WHEN bool_or(NOT (` + notBehind + `)) THEN '{"behind": true}'::jsonb ELSE '{}'::jsonb END AS detail
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
	// Reopen is a resolved incident to open again instead of a new one
	// (an asset that went quiet again within a day of recovering).
	Reopen int64
	// Members are the assets a reporting incident lists, servers and their
	// applications; their per-asset incidents from before 0.13.10 are
	// replaced by it.
	Members []int64
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
			keys = append(keys, c.Kind+"|"+c.Key)
			// An incident reopened keeps what was announced: people are not
			// told again unless its priority rises.
			if c.Reopen > 0 {
				// detail.reopened counts the open periods after the first:
				// trackers get a new record for each (store.ReopenIssue).
				tag, err := tx.Exec(ctx, `UPDATE incidents i SET status = 'open', resolved_at = NULL, resolved_notified = false,
					title = $2, priority = $3, updated_at = now(),
					detail = $4::jsonb || jsonb_build_object('reopened', COALESCE((i.detail->>'reopened')::int, 0) + 1)
					WHERE i.id = $1 AND i.status = 'resolved' AND NOT EXISTS (SELECT 1 FROM incidents o
					  WHERE o.status = 'open' AND o.kind = i.kind AND o.key = i.key AND COALESCE(o.owner_team_id, 0) = COALESCE(i.owner_team_id, 0))`,
					c.Reopen, c.Title, c.Priority, d)
				if err != nil {
					return err
				}
				if tag.RowsAffected() == 1 {
					if err := settleLegacyReporting(ctx, tx, c, c.Reopen, false); err != nil {
						return err
					}
					continue
				}
			}
			var id int64
			var inserted bool
			if err := tx.QueryRow(ctx, `INSERT INTO incidents AS i (kind, key, owner_team_id, title, priority, detail, finding_count, asset_count)
				VALUES ($1,$2,$3,$4,$5,$6,0,0)
				ON CONFLICT (workspace_id, kind, key, COALESCE(owner_team_id, 0)) WHERE status = 'open' DO UPDATE SET
				  title = EXCLUDED.title,
				  detail = EXCLUDED.detail || jsonb_strip_nulls(jsonb_build_object('people_announced', i.detail->'people_announced',
				    'reopened', i.detail->'reopened')),
				  priority = EXCLUDED.priority, updated_at = CASE WHEN i.priority <> EXCLUDED.priority THEN now() ELSE i.updated_at END
				RETURNING i.id, xmax = 0`,
				c.Kind, c.Key, c.OwnerTeamID, c.Title, c.Priority, d).Scan(&id, &inserted); err != nil {
				return err
			}
			if err := settleLegacyReporting(ctx, tx, c, id, inserted); err != nil {
				return err
			}
		}
		// Per-asset incidents from before 0.13.10 of assets no longer
		// expected to report close saying why, with no recovery message.
		if _, err := tx.Exec(ctx, `UPDATE incidents i SET resolved_notified = true,
			  detail = i.detail || jsonb_build_object('resolution', CASE WHEN a.report_source = 'integration' THEN 'integration' ELSE 'one_off' END,
			    'asset_kind', a.kind)
			FROM assets a
			WHERE i.status = 'open' AND i.kind = 'collection' AND i.key ~ '^asset:[0-9]+$' AND a.id = substring(i.key FROM 7)::bigint
			  AND (a.report_override = 'one_off' OR a.report_source = 'integration'
			    OR a.report_source IN ('scan', 'manual') AND a.report_runs IS NOT NULL AND a.report_due_after IS NULL)`); err != nil {
			return err
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

	// Servers, repositories, images and uploads that are overdue, grouped
	// by cause (reporting_incidents.go). Assets an integration reports are
	// left to its own "Integration is failing" incident.
	if err := s.RefreshReporting(ctx, nil); err != nil {
		return nil, err
	}
	rep, err := s.reportingProblems(ctx)
	if err != nil {
		return nil, err
	}
	out = append(out, rep...)

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
	// A caller who sees only some assets filters and sorts on what the
	// incident's visible findings say (v), as narrowIncidents shows it;
	// incidents without findings (system problems) keep their own values.
	prio, sos, esc, join := "i.priority", "i.sos", "i.escalation_level", ""
	if tenant.Narrowed(ctx) {
		// Open incidents count their active findings, resolved ones every
		// finding. v is worked out in one pass over the findings on the
		// visible assets (an index-only scan of findings_asset_incident,
		// migration 0044), not by looking up each incident's findings in
		// turn, which read the heap thousands of times per request.
		pick := func(col string) string {
			return fmt.Sprintf("CASE WHEN i.status = 'open' THEN v.active_%s ELSE v.%s END", col, col)
		}
		prio = "COALESCE(" + pick("priority") + ", i.priority)"
		sos = "COALESCE(" + pick("sos") + ", i.sos)"
		esc = "COALESCE(" + pick("esc") + ", i.escalation_level)"
		only := ""
		if status == "open" {
			only = ` AND ` + activeFinding
		}
		join = ` LEFT JOIN (SELECT f.incident_id,
			  min(f.priority) FILTER (WHERE ` + activeFinding + `) AS active_priority,
			  bool_or(f.sos) FILTER (WHERE ` + activeFinding + `) AS active_sos,
			  max(f.escalation_level) FILTER (WHERE ` + activeFinding + `) AS active_esc,
			  min(f.priority) AS priority, bool_or(f.sos) AS sos, max(f.escalation_level) AS esc
			FROM findings f
			WHERE f.asset_id = ANY ((SELECT stackurity_visible_assets())::bigint[]) AND f.incident_id IS NOT NULL` + only + `
			GROUP BY f.incident_id) v ON v.incident_id = i.id`
	}
	if f.Priority != "" {
		w.add(prio+" = ?", f.Priority)
	}
	if f.SOS {
		w.conds = append(w.conds, sos)
	}
	if f.Escalated {
		w.conds = append(w.conds, esc+" > 0")
	}
	if f.TeamID > 0 {
		w.add("i.owner_team_id = ?", f.TeamID)
	}
	from := ` FROM incidents i LEFT JOIN teams t ON t.id = i.owner_team_id` + join + w.sql()
	// The page carries the total (count(*) OVER ()), so the incidents and
	// their row-level security check are read once per request, not twice.
	p := f.Page.norm()
	rows, err := s.Pool.Query(ctx, `SELECT `+incidentCols+`, count(*) OVER ()`+from+fmt.Sprintf(` ORDER BY %s DESC, %s, i.updated_at DESC LIMIT %d OFFSET %d`, sos, prio, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	type counted struct {
		Incident
		Total int64
	}
	page, err := pgx.CollectRows(rows, pgx.RowToStructByPos[counted])
	if err != nil {
		return nil, 0, err
	}
	var total int64
	out := make([]Incident, len(page))
	for i, c := range page {
		out[i], total = c.Incident, c.Total
	}
	// Past the last page there is no row to carry the total.
	if len(page) == 0 && p.Offset > 0 {
		if err := s.Pool.QueryRow(ctx, `SELECT count(*)`+from, w.args...).Scan(&total); err != nil {
			return nil, 0, err
		}
	}
	if err := s.narrowIncidents(ctx, out); err != nil {
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
	one := []Incident{*in}
	if err := s.narrowIncidents(ctx, one); err != nil {
		return nil, err
	}
	in = &one[0]
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
		JOIN assets a ON a.id = f.asset_id AND NOT `+BacklogFinding+`
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
		// Locked in id order before they change (see SyncFindings).
		_, err := tx.Exec(ctx, `WITH l AS (SELECT id FROM findings WHERE incident_id = $1 AND status = 'open' ORDER BY id FOR NO KEY UPDATE)
			UPDATE findings f SET escalation_level = GREATEST(f.escalation_level, $2), escalated_at = now()
			FROM l WHERE f.id = l.id AND f.incident_id = $1 AND f.status = 'open'`, id, level)
		return err
	})
}
