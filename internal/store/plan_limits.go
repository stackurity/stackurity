package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Plan limits (docs/asset-limits.md, "Plan limits"): how many rules of each
// kind, members and which channels an organisation may have, and whether
// its projects over the project limit are read-only. Unset on a
// self-hosted install, like the other limits; a hosted edition sets them
// from each organisation's plan. Migration 0097 enforces them with a
// trigger on each table, so every path that adds a row is held to them.

// Rule kinds a plan can limit.
const (
	LimitAlertRules = "alert_rules"
	LimitChannels   = "channels"
	LimitOwnerRules = "owner_rules"
	LimitCITrusts   = "ci_trusts"
	LimitVEXSources = "vex_sources"
	LimitAPITokens  = "api_tokens"
	LimitTeams      = "teams"
	// LimitMembers is max_members: members and pending invitations.
	LimitMembers = "members"
	// LimitSBOMImports is sbom_imports_per_month.
	LimitSBOMImports = "sbom_imports"
	// LimitChannelKind is the refusal of a kind of channel the plan does
	// not include.
	LimitChannelKind = "channel_kind"
)

// RuleLimitKinds lists the kinds of rule_limits.
var RuleLimitKinds = []string{LimitAlertRules, LimitChannels, LimitOwnerRules, LimitCITrusts, LimitVEXSources, LimitAPITokens, LimitTeams}

// ChannelKinds lists what allowed_channel_kinds may name: a channel kind,
// or slack_app / teams_app for a channel made by the Stackurity Slack or
// Teams app.
var ChannelKinds = []string{"email", "stackurity_email", "slack", "slack_app", "teams", "teams_app", "webhook", "jira", "pagerduty", "servicenow"}

// PlanLimits are an organisation's plan limits. A kind left out, and a nil
// MaxMembers or AllowedChannelKinds, is unlimited.
type PlanLimits struct {
	// Plan names the organisation's plan; NextPlan the plan a refusal
	// tells it to upgrade to ("Upgrade to Team for more").
	Plan     string `json:"plan,omitempty"`
	NextPlan string `json:"next_plan,omitempty"`
	// RuleLimits caps each kind of RuleLimitKinds.
	RuleLimits map[string]int64 `json:"rule_limits,omitempty"`
	// MaxMembers caps members plus pending invitations.
	MaxMembers *int64 `json:"max_members,omitempty"`
	// AllowedChannelKinds limits new channels to these ChannelKinds.
	AllowedChannelKinds []string `json:"allowed_channel_kinds,omitempty"`
	// OverLimitReadOnly: projects beyond the project limit (the newest
	// ones) are read-only, and assets only in them collect nothing new.
	OverLimitReadOnly bool `json:"over_limit_read_only,omitempty"`
	// CheckCooldownSeconds is how long after a Check again on an asset
	// (or one of its fixes) the next may be asked for; 0: any time.
	CheckCooldownSeconds int64 `json:"check_again_cooldown_seconds,omitempty"`
	// APIRequestsPerHour caps the organisation's API requests an hour
	// (people's and API tokens'; agents, enrollment and CI and SBOM
	// uploads from agents and CI are not counted); 0: no cap.
	APIRequestsPerHour int64 `json:"api_requests_per_hour,omitempty"`
	// SBOMImportsPerMonth caps SBOM imports a calendar month (UTC); nil:
	// no cap.
	SBOMImportsPerMonth *int64 `json:"sbom_imports_per_month,omitempty"`
	// HistoryDays is how far back resolved issues, past inventory and
	// resolved incidents are shown (data is kept; open issues and current
	// inventory are always shown); 0: everything.
	HistoryDays int64 `json:"history_days,omitempty"`
	// InactivePauseDays pauses the organisation after that many days
	// without a sign-in by any member (plan_history.go); 0: never.
	InactivePauseDays int64 `json:"inactive_pause_days,omitempty"`
}

// Empty reports whether no limit is set.
func (l PlanLimits) Empty() bool {
	return len(l.RuleLimits) == 0 && l.MaxMembers == nil && l.AllowedChannelKinds == nil && !l.OverLimitReadOnly &&
		l.Plan == "" && l.NextPlan == "" && l.CheckCooldownSeconds == 0 && l.APIRequestsPerHour == 0 && l.SBOMImportsPerMonth == nil &&
		l.HistoryDays == 0 && l.InactivePauseDays == 0
}

func (l PlanLimits) validate() error {
	for _, n := range []string{l.Plan, l.NextPlan} {
		if len(n) > 60 {
			return fmt.Errorf("plan and next_plan are limited to 60 characters: %w", ErrInvalid)
		}
	}
	for k, v := range l.RuleLimits {
		if !slices.Contains(RuleLimitKinds, k) {
			return fmt.Errorf("rule_limits: unknown kind %q (one of %s): %w", k, strings.Join(RuleLimitKinds, ", "), ErrInvalid)
		}
		if v < 0 || v > 1_000_000 {
			return fmt.Errorf("rule_limits.%s must be between 0 and 1000000: %w", k, ErrInvalid)
		}
	}
	if l.CheckCooldownSeconds < 0 || l.CheckCooldownSeconds > 7*24*3600 {
		return fmt.Errorf("check_again_cooldown_seconds must be between 0 and 604800: %w", ErrInvalid)
	}
	if l.APIRequestsPerHour < 0 || l.APIRequestsPerHour > 100_000_000 {
		return fmt.Errorf("api_requests_per_hour must be between 0 and 100000000: %w", ErrInvalid)
	}
	if l.SBOMImportsPerMonth != nil && (*l.SBOMImportsPerMonth < 0 || *l.SBOMImportsPerMonth > 100_000_000) {
		return fmt.Errorf("sbom_imports_per_month must be between 0 and 100000000: %w", ErrInvalid)
	}
	if l.HistoryDays < 0 || l.HistoryDays > 36500 {
		return fmt.Errorf("history_days must be between 0 and 36500: %w", ErrInvalid)
	}
	if l.InactivePauseDays != 0 && (l.InactivePauseDays < 20 || l.InactivePauseDays > 3650) {
		return fmt.Errorf("inactive_pause_days must be 0, or between 20 and 3650 (its warnings come 15 and 5 days before): %w", ErrInvalid)
	}
	if l.MaxMembers != nil && (*l.MaxMembers < 1 || *l.MaxMembers > 1_000_000) {
		return fmt.Errorf("max_members must be between 1 and 1000000: %w", ErrInvalid)
	}
	for _, k := range l.AllowedChannelKinds {
		if !slices.Contains(ChannelKinds, k) {
			return fmt.Errorf("allowed_channel_kinds: unknown kind %q (one of %s): %w", k, strings.Join(ChannelKinds, ", "), ErrInvalid)
		}
	}
	return nil
}

// ErrPlanLimit matches a *PlanLimitError with errors.Is.
var ErrPlanLimit = errors.New("plan limit reached")

// PlanLimitError means something new was refused because the
// organisation's plan does not allow another.
type PlanLimitError struct {
	Kind        string `json:"kind"`
	Limit       int64  `json:"limit"`
	Used        int64  `json:"used"`
	NextPlan    string `json:"next_plan"`
	ChannelKind string `json:"channel_kind,omitempty"`
}

var limitNames = map[string]string{
	LimitAlertRules: "alert rules", LimitChannels: "notification channels", LimitOwnerRules: "owner rules",
	LimitCITrusts: "CI trusts", LimitVEXSources: "VEX sources", LimitAPITokens: "API tokens", LimitTeams: "teams",
	LimitMembers: "members (pending invitations count too)", LimitSBOMImports: "SBOM imports a month",
}

func (e *PlanLimitError) Error() string {
	upgrade := "Upgrade your plan for more."
	if e.NextPlan != "" {
		upgrade = "Upgrade to " + e.NextPlan + " for more."
	}
	if e.Kind == LimitChannelKind {
		return fmt.Sprintf("your plan does not include %s channels. %s", channelKindName(e.ChannelKind), upgrade)
	}
	name := limitNames[e.Kind]
	if name == "" {
		name = e.Kind
	}
	return fmt.Sprintf("your plan allows %d %s, and this organisation has %d, so no new one can be added: "+
		"the ones you have keep working, and can be changed or deleted. %s", e.Limit, name, e.Used, upgrade)
}

func (e *PlanLimitError) Is(target error) bool { return target == ErrPlanLimit }

func channelKindName(k string) string {
	switch k {
	case "slack_app":
		return "Slack (Stackurity app)"
	case "teams_app":
		return "Microsoft Teams (Stackurity app)"
	case "stackurity_email":
		return "email sent by Stackurity"
	case "email":
		return "email through your own mail server"
	case "slack":
		return "Slack webhook"
	case "teams":
		return "Microsoft Teams webhook"
	case "jira":
		return "Jira"
	case "pagerduty":
		return "PagerDuty"
	case "servicenow":
		return "ServiceNow"
	}
	return k
}

// planLimitState is the SQLSTATE of migration 0097's refusal.
const planLimitState = "SK402"

// AsPlanLimit turns migration 0097's refusal into a *PlanLimitError.
func AsPlanLimit(err error) (*PlanLimitError, bool) {
	var pl *PlanLimitError
	if errors.As(err, &pl) {
		return pl, true
	}
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != planLimitState {
		return nil, false
	}
	pl = &PlanLimitError{}
	if json.Unmarshal([]byte(pe.Detail), pl) != nil {
		pl = &PlanLimitError{Kind: "?"}
	}
	return pl, true
}

// GetPlanLimits reads workspace ws's plan limits.
func (s *Store) GetPlanLimits(ctx context.Context, ws int64) (PlanLimits, error) {
	return planLimits(tenant.System(ctx), s.Pool, ws)
}

func planLimits(ctx context.Context, db q, ws int64) (PlanLimits, error) {
	var l PlanLimits
	err := db.QueryRow(ctx, `SELECT plan_limits FROM workspaces WHERE id = $1`, ws).Scan(&l)
	if errors.Is(err, pgx.ErrNoRows) {
		return PlanLimits{}, ErrNotFound
	}
	return l, err
}

// SetPlanLimits replaces workspace ws's plan limits; an empty PlanLimits
// removes them. For instance administration and a hosted edition's
// billing.
func (s *Store) SetPlanLimits(ctx context.Context, ws int64, l PlanLimits) error {
	if err := l.validate(); err != nil {
		return err
	}
	if l.Empty() {
		l = PlanLimits{}
	}
	tag, err := s.Pool.Exec(tenant.System(ctx), `UPDATE workspaces SET plan_limits = $2 WHERE id = $1`, ws, l)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// LimitUsage is one limit and how much of it is used.
type LimitUsage struct {
	Used  int64  `json:"used"`
	Limit *int64 `json:"limit"`
}

// PlanUsage is what the dashboard shows of the plan limits ("3 of 3
// used"). Nil in AssetUsage when the organisation has none.
type PlanUsage struct {
	Plan                string                `json:"plan"`
	NextPlan            string                `json:"next_plan"`
	Rules               map[string]LimitUsage `json:"rules"`
	Members             LimitUsage            `json:"members"`
	AllowedChannelKinds []string              `json:"allowed_channel_kinds"`
	// ReadOnlyProjects lists the projects over the project limit.
	ReadOnlyProjects []int64 `json:"read_only_projects"`
	// SBOMImports this calendar month (UTC) against the allowance.
	SBOMImports LimitUsage `json:"sbom_imports"`
	// CheckCooldownSeconds and APIRequestsPerHour are the plan's (0: none).
	CheckCooldownSeconds int64 `json:"check_again_cooldown_seconds"`
	APIRequestsPerHour   int64 `json:"api_requests_per_hour"`
	// HistoryDays and InactivePauseDays are the plan's (0: none).
	HistoryDays       int64 `json:"history_days"`
	InactivePauseDays int64 `json:"inactive_pause_days"`
}

// planUsage counts what workspace ws's plan limits apply to; nil when it
// has none.
func (s *Store) planUsage(ctx context.Context, ws int64) (*PlanUsage, error) {
	sys := tenant.System(ctx)
	l, err := planLimits(sys, s.Pool, ws)
	if err != nil || l.Empty() {
		return nil, err
	}
	u := &PlanUsage{Plan: l.Plan, NextPlan: l.NextPlan, Rules: map[string]LimitUsage{}, AllowedChannelKinds: l.AllowedChannelKinds,
		ReadOnlyProjects: []int64{}}
	var c [7]int64
	err = s.Pool.QueryRow(sys, `SELECT
		(SELECT count(*) FROM routes WHERE workspace_id = $1),
		(SELECT count(*) FROM channels WHERE workspace_id = $1),
		(SELECT count(*) FROM owner_rules WHERE workspace_id = $1),
		(SELECT count(*) FROM ci_trusts WHERE workspace_id = $1),
		(SELECT count(*) FROM vex_sources WHERE workspace_id = $1),
		(SELECT count(*) FROM api_tokens WHERE workspace_id = $1 AND user_id IS NOT NULL AND revoked_at IS NULL
		   AND (expires_at IS NULL OR expires_at > now())),
		(SELECT count(*) FROM teams WHERE workspace_id = $1)`, ws).Scan(&c[0], &c[1], &c[2], &c[3], &c[4], &c[5], &c[6])
	if err != nil {
		return nil, err
	}
	for i, k := range RuleLimitKinds {
		lu := LimitUsage{Used: c[i]}
		if v, ok := l.RuleLimits[k]; ok {
			lu.Limit = &v
		}
		u.Rules[k] = lu
	}
	err = s.Pool.QueryRow(sys, `SELECT (SELECT count(*) FROM workspace_members WHERE workspace_id = $1)
		+ (SELECT count(DISTINCT email) FROM invitations WHERE workspace_id = $1 AND accepted_at IS NULL AND revoked_at IS NULL
		     AND expires_at > now())`, ws).Scan(&u.Members.Used)
	if err != nil {
		return nil, err
	}
	u.Members.Limit = l.MaxMembers
	u.CheckCooldownSeconds, u.APIRequestsPerHour, u.SBOMImports.Limit = l.CheckCooldownSeconds, l.APIRequestsPerHour, l.SBOMImportsPerMonth
	u.HistoryDays, u.InactivePauseDays = l.HistoryDays, l.InactivePauseDays
	if err := s.Pool.QueryRow(sys, `SELECT COALESCE((SELECT used FROM plan_allowances WHERE workspace_id = $1 AND kind = 'sbom_imports'
		AND period_start = date_trunc('month', now() AT TIME ZONE 'UTC')::date), 0)`, ws).Scan(&u.SBOMImports.Used); err != nil {
		return nil, err
	}
	if u.ReadOnlyProjects, err = readOnlyProjects(sys, s.Pool, ws); err != nil {
		return nil, err
	}
	if u.ReadOnlyProjects == nil {
		u.ReadOnlyProjects = []int64{}
	}
	return u, nil
}

// readOnlyProjects lists workspace ws's active projects beyond its project
// limit when its plan makes them read-only: the oldest ones (by creation)
// stay active, up to the limit. Nil otherwise.
func readOnlyProjects(ctx context.Context, db q, ws int64) ([]int64, error) {
	rows, err := db.Query(ctx, `SELECT p.id FROM projects p JOIN workspaces w ON w.id = p.workspace_id
		WHERE w.id = $1 AND p.archived_at IS NULL AND w.project_limit IS NOT NULL
		  AND (w.plan_limits->>'over_limit_read_only')::boolean IS TRUE
		ORDER BY p.created_at, p.id OFFSET (SELECT project_limit FROM workspaces WHERE id = $1)`, ws)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// ReadOnlyProjectIDs lists the current workspace's read-only projects
// (see readOnlyProjects) as a set.
func (s *Store) ReadOnlyProjectIDs(ctx context.Context) (map[int64]bool, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil, nil
	}
	ids, err := readOnlyProjects(tenant.System(ctx), s.Pool, ws)
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	out := make(map[int64]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// ProjectReadOnlyError means nothing new is collected for an asset because
// every project it is in is over the organisation's project limit. It
// matches ErrReadOnly.
type ProjectReadOnlyError struct {
	Projects []string
	NextPlan string
}

func (e *ProjectReadOnlyError) Error() string {
	upgrade := "upgrade your plan"
	if e.NextPlan != "" {
		upgrade = "upgrade to " + e.NextPlan
	}
	return fmt.Sprintf("this asset is only in projects over your plan's project limit (%s), so nothing new is collected for it: "+
		"everything already here can still be viewed. Archive a project you no longer need, or %s", strings.Join(e.Projects, ", "), upgrade)
}

func (e *ProjectReadOnlyError) Is(target error) bool { return target == ErrReadOnly }

// checkAssetCollecting, in the transaction of an upload, returns a
// *ProjectReadOnlyError when asset is in projects and all of them are
// read-only. Assets in no project, or in one active project, collect as
// before.
func checkAssetCollecting(ctx context.Context, tx pgx.Tx, ws, asset int64) error {
	var refusal *ProjectReadOnlyError
	err := asSystem(ctx, tx, func() error {
		ro, err := readOnlyProjects(ctx, tx, ws)
		if err != nil || len(ro) == 0 {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT p.id, p.name FROM project_assets pa JOIN projects p ON p.id = pa.project_id
			WHERE pa.asset_id = $1 AND p.archived_at IS NULL ORDER BY p.name`, asset)
		if err != nil {
			return err
		}
		var names []string
		active := false
		for rows.Next() {
			var id int64
			var name string
			if err := rows.Scan(&id, &name); err != nil {
				rows.Close()
				return err
			}
			if !slices.Contains(ro, id) {
				active = true
			}
			names = append(names, name)
		}
		rows.Close()
		if err := rows.Err(); err != nil || active || len(names) == 0 {
			return err
		}
		l, err := planLimits(ctx, tx, ws)
		if err != nil {
			return err
		}
		refusal = &ProjectReadOnlyError{Projects: names, NextPlan: l.NextPlan}
		return nil
	})
	if err != nil {
		return err
	}
	if refusal != nil {
		return refusal
	}
	return nil
}

// PlanRoom returns a *PlanLimitError when the current workspace has no room
// for another rule of kind (and, for channels, channelKind, as
// allowed_channel_kinds names it), else nil. A check before a step that
// adds one later, such as Add to Slack; the trigger still decides.
func (s *Store) PlanRoom(ctx context.Context, kind, channelKind string) error {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil
	}
	u, err := s.planUsage(ctx, ws)
	if err != nil || u == nil {
		return err
	}
	if channelKind != "" && u.AllowedChannelKinds != nil && !slices.Contains(u.AllowedChannelKinds, channelKind) {
		return &PlanLimitError{Kind: LimitChannelKind, ChannelKind: channelKind, NextPlan: u.NextPlan}
	}
	if r, ok := u.Rules[kind]; ok && r.Limit != nil && r.Used >= *r.Limit {
		return &PlanLimitError{Kind: kind, Limit: *r.Limit, Used: r.Used, NextPlan: u.NextPlan}
	}
	return nil
}

// TakeSBOMImport takes one of the current workspace's SBOM imports this
// month, or returns a *PlanLimitError when none are left. Without an
// allowance it does nothing. GiveBackSBOMImport returns one whose import
// failed.
func (s *Store) TakeSBOMImport(ctx context.Context) error {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil
	}
	sys := tenant.System(ctx)
	l, err := planLimits(sys, s.Pool, ws)
	if err != nil || l.SBOMImportsPerMonth == nil {
		return err
	}
	var used int64
	err = s.Pool.QueryRow(sys, `INSERT INTO plan_allowances AS a (workspace_id, kind, period_start, used)
		VALUES ($1, 'sbom_imports', date_trunc('month', now() AT TIME ZONE 'UTC')::date, 1)
		ON CONFLICT (workspace_id, kind, period_start) DO UPDATE SET used = a.used + 1 WHERE a.used < $2
		RETURNING used`, ws, *l.SBOMImportsPerMonth).Scan(&used)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && used > *l.SBOMImportsPerMonth {
		if err == nil {
			_ = s.GiveBackSBOMImport(ctx)
		}
		return &PlanLimitError{Kind: LimitSBOMImports, Limit: *l.SBOMImportsPerMonth, Used: *l.SBOMImportsPerMonth, NextPlan: l.NextPlan}
	}
	return err
}

// GiveBackSBOMImport returns an SBOM import TakeSBOMImport took.
func (s *Store) GiveBackSBOMImport(ctx context.Context) error {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil
	}
	_, err := s.Pool.Exec(tenant.System(ctx), `UPDATE plan_allowances SET used = used - 1 WHERE workspace_id = $1 AND kind = 'sbom_imports'
		AND period_start = date_trunc('month', now() AT TIME ZONE 'UTC')::date AND used > 0`, ws)
	return err
}

// ErrCheckCooldown matches a *CheckCooldownError with errors.Is.
var ErrCheckCooldown = errors.New("check again too soon")

// CheckCooldownError means a Check again was refused because the plan
// allows one per asset every Cooldown, and the last was too recent.
type CheckCooldownError struct {
	Cooldown time.Duration
	At       time.Time // when the next may be asked for
	NextPlan string
}

func (e *CheckCooldownError) Error() string {
	upgrade := "Upgrade your plan to check more often."
	if e.NextPlan != "" {
		upgrade = "Upgrade to " + e.NextPlan + " to check more often."
	}
	wait := time.Until(e.At).Round(time.Minute)
	if wait < time.Minute {
		wait = time.Minute
	}
	return fmt.Sprintf("your plan allows Check again once every %s for each asset, so the next one can run in about %s (at %s UTC). "+
		"Scheduled checks and agent reports carry on as usual. %s", e.Cooldown, wait, e.At.UTC().Format("15:04"), upgrade)
}

func (e *CheckCooldownError) Is(target error) bool { return target == ErrCheckCooldown }

// checkCooldown, in the transaction of a Check again with asset locked,
// returns a *CheckCooldownError when the plan's cooldown has not passed
// since the last Check again on the asset.
func checkCooldown(ctx context.Context, tx pgx.Tx, ws, asset int64) error {
	var l PlanLimits
	var last *time.Time
	err := asSystem(ctx, tx, func() error {
		var err error
		if l, err = planLimits(ctx, tx, ws); err != nil || l.CheckCooldownSeconds == 0 {
			return err
		}
		return tx.QueryRow(ctx, `SELECT max(requested_at) FROM checks WHERE asset_id = $1 AND reason = 'check'`, asset).Scan(&last)
	})
	if err != nil || l.CheckCooldownSeconds == 0 || last == nil {
		return err
	}
	cd := time.Duration(l.CheckCooldownSeconds) * time.Second
	if next := last.Add(cd); time.Now().Before(next) {
		return &CheckCooldownError{Cooldown: cd, At: next, NextPlan: l.NextPlan}
	}
	return nil
}

// APIRequestsPerHour is the current workspace's API request cap an hour
// (0: none).
func (s *Store) APIRequestsPerHour(ctx context.Context, ws int64) (int64, error) {
	l, err := planLimits(tenant.System(ctx), s.Pool, ws)
	if errors.Is(err, ErrNotFound) {
		return 0, nil
	}
	return l.APIRequestsPerHour, err
}
