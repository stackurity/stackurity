package store

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Owner rules (docs/design/owner-rules.md) say who new issues are assigned
// to. A rule has a scope (the organisation, a project or an asset), an
// optional part of the stack (a layer, a package name pattern or both) and
// an owner (a person, a team or both). The most specific matching rule
// assigns an issue nobody assigned by hand.

type OwnerRule struct {
	ID          int64     `json:"id"`
	ProjectID   *int64    `json:"project_id"`
	ProjectName string    `json:"project_name,omitempty"`
	AssetID     *int64    `json:"asset_id"`
	AssetName   string    `json:"asset_name,omitempty"`
	Layer       string    `json:"layer"`
	Component   string    `json:"component"`
	UserID      *int64    `json:"user_id"`
	UserEmail   string    `json:"user_email,omitempty"`
	UserName    string    `json:"user_name,omitempty"`
	TeamID      *int64    `json:"team_id"`
	TeamName    string    `json:"team_name,omitempty"`
	Note        string    `json:"note"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	// Level is how specific the rule is, 1 (organisation default) to 6
	// (part of one asset's stack); the highest matching level wins.
	Level int `json:"level"`
	// Describe is the rule in words, as issue history shows it.
	Describe string `json:"describe"`
	// Assigned counts the open issues this rule assigned.
	Assigned int64 `json:"assigned"`

	pattern *regexp.Regexp
}

// OwnerRuleInput creates or changes a rule. At most one of ProjectID and
// AssetID; at least one of UserID and TeamID.
type OwnerRuleInput struct {
	ProjectID *int64 `json:"project_id"`
	AssetID   *int64 `json:"asset_id"`
	Layer     string `json:"layer"`
	Component string `json:"component"`
	UserID    *int64 `json:"user_id"`
	TeamID    *int64 `json:"team_id"`
	Note      string `json:"note"`
}

const ownerRuleCols = `r.id, r.project_id, COALESCE(p.name, ''), r.asset_id, COALESCE(a.name, ''), r.layer, r.component,
	r.user_id, COALESCE(u.email, ''), COALESCE(u.name, ''), r.team_id, COALESCE(t.name, ''), r.note, r.created_at, r.updated_at,
	(SELECT count(*) FROM findings f WHERE f.owner_rule_id = r.id AND f.status = 'open')`

const ownerRuleFrom = ` FROM owner_rules r LEFT JOIN projects p ON p.id = r.project_id LEFT JOIN assets a ON a.id = r.asset_id
	LEFT JOIN users u ON u.id = r.user_id LEFT JOIN teams t ON t.id = r.team_id`

func scanOwnerRules(rows pgx.Rows) ([]OwnerRule, error) {
	defer rows.Close()
	var out []OwnerRule
	for rows.Next() {
		var r OwnerRule
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.ProjectName, &r.AssetID, &r.AssetName, &r.Layer, &r.Component,
			&r.UserID, &r.UserEmail, &r.UserName, &r.TeamID, &r.TeamName, &r.Note, &r.CreatedAt, &r.UpdatedAt, &r.Assigned); err != nil {
			return nil, err
		}
		r.finish()
		out = append(out, r)
	}
	return out, rows.Err()
}

func (r *OwnerRule) finish() {
	stack := r.Layer != "" || r.Component != ""
	switch {
	case r.AssetID != nil && stack:
		r.Level = 6
	case r.AssetID != nil:
		r.Level = 5
	case r.ProjectID != nil && stack:
		r.Level = 4
	case r.ProjectID != nil:
		r.Level = 3
	case stack:
		r.Level = 2
	default:
		r.Level = 1
	}
	r.pattern = componentPattern(r.Component)
	var what []string
	if r.Layer != "" {
		what = append(what, LayerLabel(r.Layer))
	}
	if r.Component != "" {
		what = append(what, "packages "+r.Component)
	}
	where := "every asset"
	switch {
	case r.AssetName != "":
		where = r.AssetName
	case r.ProjectName != "":
		where = "project " + r.ProjectName
	}
	if len(what) == 0 {
		r.Describe = "everything on " + where
	} else {
		r.Describe = strings.Join(what, ", ") + " on " + where
	}
}

// LayerLabel names a stack layer for people, as the dashboard's Stack tab
// does (web/src/components/Stack.tsx).
func LayerLabel(layer string) string {
	if l, ok := layerLabels[layer]; ok {
		return l
	}
	return layer
}

var layerLabels = map[string]string{
	"web_server": "web server / proxy", "cms": "WordPress core", "os": "operating system", "runtime": "runtime",
	"data_store": "data store", "libraries": "application libraries", "declared": "declared in repository",
	"managed_service": "managed service", "platform": "Kubernetes platform", "other": "other",
}

// componentPattern compiles a package name pattern: case-insensitive,
// whole name, * for any characters.
func componentPattern(p string) *regexp.Regexp {
	if p == "" {
		return nil
	}
	parts := strings.Split(strings.ToLower(p), "*")
	for i := range parts {
		parts[i] = regexp.QuoteMeta(parts[i])
	}
	return regexp.MustCompile(`^` + strings.Join(parts, ".*") + `$`)
}

// OwnerRuleFilter limits ListOwnerRules. AssetID and ProjectID list the
// rules that can apply there (an asset's own, its projects' and the
// organisation's), most specific first.
type OwnerRuleFilter struct {
	AssetID   int64
	ProjectID int64
}

func (s *Store) ListOwnerRules(ctx context.Context, f OwnerRuleFilter) ([]OwnerRule, error) {
	ctx = tenant.WithoutProject(ctx)
	w := &where{}
	switch {
	case f.AssetID > 0:
		w.add(`(r.asset_id = ? OR (r.asset_id IS NULL AND (r.project_id IS NULL OR r.project_id IN
			(SELECT pa.project_id FROM project_assets pa JOIN projects pp ON pp.id = pa.project_id
			 WHERE pa.asset_id = ? AND pp.archived_at IS NULL))))`, f.AssetID)
	case f.ProjectID > 0:
		w.add(`r.asset_id IS NULL AND (r.project_id IS NULL OR r.project_id = ?)`, f.ProjectID)
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+ownerRuleCols+ownerRuleFrom+w.sql()+` ORDER BY r.id`, w.args...)
	if err != nil {
		return nil, err
	}
	rules, err := scanOwnerRules(rows)
	if err != nil {
		return nil, err
	}
	sortRules(rules)
	return rules, nil
}

// sortRules orders rules by precedence: most specific first (see best).
func sortRules(rules []OwnerRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		a, b := rules[i], rules[j]
		if a.Level != b.Level {
			return a.Level > b.Level
		}
		if sa, sb := stackScore(a), stackScore(b); sa != sb {
			return sa > sb
		}
		return a.ID < b.ID
	})
}

// stackScore: a package name and a layer beat a package name, which beats
// a layer.
func stackScore(r OwnerRule) int {
	n := 0
	if r.Component != "" {
		n += 2
	}
	if r.Layer != "" {
		n++
	}
	return n
}

func (s *Store) GetOwnerRule(ctx context.Context, id int64) (*OwnerRule, error) {
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `SELECT `+ownerRuleCols+ownerRuleFrom+` WHERE r.id = $1`, id)
	if err != nil {
		return nil, err
	}
	rules, err := scanOwnerRules(rows)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, ErrNotFound
	}
	return &rules[0], nil
}

func (in *OwnerRuleInput) check() error {
	if in.ProjectID != nil && in.AssetID != nil {
		return fmt.Errorf("name a project or an asset, not both: %w", ErrInvalid)
	}
	if in.UserID == nil && in.TeamID == nil {
		return fmt.Errorf("name a person, a team or both: %w", ErrInvalid)
	}
	if in.Layer != "" && !slices.Contains(stackLayers, in.Layer) {
		return fmt.Errorf("layer must be one of %s: %w", strings.Join(stackLayers, ", "), ErrInvalid)
	}
	in.Component = strings.TrimSpace(in.Component)
	if len(in.Component) > 200 || len(in.Note) > 500 {
		return fmt.Errorf("package name pattern is at most 200 characters, note 500: %w", ErrInvalid)
	}
	return nil
}

// SaveOwnerRule creates a rule (id 0) or replaces one. Issues not assigned
// yet are checked against the new rules on the next pass; issues a rule
// already assigned move only through ApplyOwnerRules.
func (s *Store) SaveOwnerRule(ctx context.Context, id int64, in OwnerRuleInput, by int64) (*OwnerRule, error) {
	if err := in.check(); err != nil {
		return nil, err
	}
	ctx = tenant.WithoutProject(ctx)
	if in.UserID != nil {
		var member bool
		if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM workspace_members WHERE workspace_id = stackurity_ws() AND user_id = $1)`, *in.UserID).Scan(&member); err != nil {
			return nil, err
		}
		if !member {
			return nil, fmt.Errorf("that person is not a member of this organisation: %w", ErrInvalid)
		}
	}
	var byID *int64
	if by > 0 {
		byID = &by
	}
	var err error
	if id == 0 {
		err = s.Pool.QueryRow(ctx, `INSERT INTO owner_rules (project_id, asset_id, layer, component, user_id, team_id, note, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
			in.ProjectID, in.AssetID, in.Layer, in.Component, in.UserID, in.TeamID, in.Note, byID).Scan(&id)
	} else {
		var tag interface{ RowsAffected() int64 }
		tag, err = s.Pool.Exec(ctx, `UPDATE owner_rules SET project_id = $2, asset_id = $3, layer = $4, component = $5,
			user_id = $6, team_id = $7, note = $8, updated_at = clock_timestamp() WHERE id = $1`,
			id, in.ProjectID, in.AssetID, in.Layer, in.Component, in.UserID, in.TeamID, in.Note)
		if err == nil && tag.RowsAffected() == 0 {
			return nil, ErrNotFound
		}
	}
	if isForeignKey(err) {
		return nil, fmt.Errorf("no such project, asset, person or team in this organisation: %w", ErrInvalid)
	}
	if err != nil {
		return nil, err
	}
	return s.GetOwnerRule(ctx, id)
}

// DeleteOwnerRule removes a rule. The issues it assigned keep their
// assignee until ApplyOwnerRules moves them.
func (s *Store) DeleteOwnerRule(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(tenant.WithoutProject(ctx), `DELETE FROM owner_rules WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ownerCandidate is an open issue the rules may assign, with what they
// match on.
type ownerCandidate struct {
	id       int64
	assetID  int64
	projects []int64
	layer    string
	names    []string
	userID   *int64
	teamID   *int64
	ruleID   *int64
}

// best is the rule that assigns c: the most specific one that matches
// (rules are in precedence order), or nil.
func best(rules []OwnerRule, c ownerCandidate) *OwnerRule {
	for i := range rules {
		r := &rules[i]
		if r.AssetID != nil && *r.AssetID != c.assetID {
			continue
		}
		if r.ProjectID != nil && !slices.Contains(c.projects, *r.ProjectID) {
			continue
		}
		if r.Layer != "" && r.Layer != c.layer {
			continue
		}
		if r.pattern != nil && !slices.ContainsFunc(c.names, r.pattern.MatchString) {
			continue
		}
		return r
	}
	return nil
}

// ownerCandidates reads open issues (where is a condition on f) with
// their asset's active projects and stack layer.
func ownerCandidates(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, where string, limit int, args ...any) ([]ownerCandidate, error) {
	rows, err := q.Query(ctx, `SELECT f.id, f.asset_id, a.kind, c.type, c.name, COALESCE(c.namespace, ''), f.assignee_user_id, f.assignee_team_id,
		  f.owner_rule_id, COALESCE((SELECT array_agg(pa.project_id ORDER BY pa.project_id) FROM project_assets pa
		    JOIN projects p ON p.id = pa.project_id WHERE pa.asset_id = f.asset_id AND p.archived_at IS NULL), '{}')
		FROM findings f JOIN assets a ON a.id = f.asset_id JOIN components c ON c.id = f.component_id
		WHERE f.status = 'open' AND NOT f.assignment_manual AND `+where+fmt.Sprintf(` ORDER BY f.id LIMIT %d`, limit), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ownerCandidate
	for rows.Next() {
		var c ownerCandidate
		var kind, ctype, name, ns string
		if err := rows.Scan(&c.id, &c.assetID, &kind, &ctype, &name, &ns, &c.userID, &c.teamID, &c.ruleID, &c.projects); err != nil {
			return nil, err
		}
		c.layer = findingLayer(Finding{ComponentName: name, ComponentType: ctype}, kind)
		// A pattern matches the name ("node") or the namespaced name
		// ("@types/node", "org.apache.logging.log4j/log4j-core").
		c.names = []string{strings.ToLower(name)}
		if ns != "" {
			c.names = append(c.names, strings.ToLower(ns+"/"+name))
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// rulesForPass reads every rule in precedence order and when the newest
// was written.
func (s *Store) rulesForPass(ctx context.Context) ([]OwnerRule, time.Time, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+ownerRuleCols+ownerRuleFrom)
	if err != nil {
		return nil, time.Time{}, err
	}
	rules, err := scanOwnerRules(rows)
	if err != nil {
		return nil, time.Time{}, err
	}
	sortRules(rules)
	var newest time.Time
	for _, r := range rules {
		if r.UpdatedAt.After(newest) {
			newest = r.UpdatedAt
		}
	}
	return rules, newest, nil
}

// ownerPassBatch bounds one pass; the rest wait for the next tick.
const ownerPassBatch = 2000

// AssignByOwnerRules assigns open issues nobody has assigned, by person or
// rule, to the owner the most specific matching rule names, and records
// which rule did. Issues are checked again only when a rule changes.
func (s *Store) AssignByOwnerRules(ctx context.Context) (int64, error) {
	ctx = tenant.WithoutProject(ctx)
	rules, version, err := s.rulesForPass(ctx)
	if err != nil || len(rules) == 0 {
		return 0, err
	}
	cands, err := ownerCandidates(ctx, s.Pool, `f.assignee_user_id IS NULL AND f.assignee_team_id IS NULL
		AND COALESCE(f.owner_checked_at, '-infinity'::timestamptz) < $1`, ownerPassBatch, version)
	if err != nil || len(cands) == 0 {
		return 0, err
	}
	var assigned int64
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var none []int64
		for _, c := range cands {
			r := best(rules, c)
			if r == nil {
				none = append(none, c.id)
				continue
			}
			// Only if still unassigned: a person may have assigned it since.
			ok, err := assignByRule(ctx, tx, c.id, r, version, true)
			if err != nil {
				return err
			}
			if ok {
				assigned++
			}
		}
		// Checked against these rules; looked at again when one changes.
		_, err := tx.Exec(ctx, `UPDATE findings SET owner_checked_at = $2 WHERE id = ANY($1)
			AND assignee_user_id IS NULL AND assignee_team_id IS NULL AND NOT assignment_manual`, none, version)
		return err
	})
	return assigned, err
}

// assignByRule gives finding id rule r's owner and records it in the
// issue's history. onlyUnassigned leaves an issue someone assigned since.
func assignByRule(ctx context.Context, tx pgx.Tx, id int64, r *OwnerRule, checked time.Time, onlyUnassigned bool) (bool, error) {
	cond := ` AND NOT assignment_manual`
	if onlyUnassigned {
		cond += ` AND assignee_user_id IS NULL AND assignee_team_id IS NULL`
	}
	tag, err := tx.Exec(ctx, `UPDATE findings SET assignee_user_id = $2, assignee_team_id = $3, owner_rule_id = $4,
		owner_checked_at = $5 WHERE id = $1 AND status = 'open'`+cond, id, r.UserID, r.TeamID, r.ID, checked)
	if err != nil || tag.RowsAffected() == 0 {
		return false, err
	}
	detail := map[string]any{"rule_id": r.ID, "by_rule": true}
	if r.UserID != nil {
		detail["user_id"], detail["user_email"] = *r.UserID, r.UserEmail
	}
	if r.TeamID != nil {
		detail["team_id"], detail["team_name"] = *r.TeamID, r.TeamName
	}
	d, _ := json.Marshal(detail)
	_, err = tx.Exec(ctx, `INSERT INTO finding_events (finding_id, actor_type, actor_name, action, note, detail)
		VALUES ($1, 'system', 'owner rules', 'assign', $2, $3)`, id, fmt.Sprintf("Owner rule #%d: %s", r.ID, r.Describe), d)
	return true, err
}

// unassignByRule clears an assignment a rule made when no rule matches
// the issue any more.
func unassignByRule(ctx context.Context, tx pgx.Tx, id int64, checked time.Time) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE findings SET assignee_user_id = NULL, assignee_team_id = NULL, owner_rule_id = NULL,
		owner_checked_at = $2 WHERE id = $1 AND status = 'open' AND NOT assignment_manual`, id, checked)
	if err != nil || tag.RowsAffected() == 0 {
		return false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO finding_events (finding_id, actor_type, actor_name, action, note, detail)
		VALUES ($1, 'system', 'owner rules', 'assign', 'No owner rule matches any more: unassigned', '{"by_rule": true, "user_id": 0, "team_id": 0}')`, id)
	return true, err
}

// OwnerMove is a group of open issues ApplyOwnerRules moves from one
// owner to another.
type OwnerMove struct {
	FromUser  string  `json:"from_user"`
	FromTeam  string  `json:"from_team"`
	ToUser    string  `json:"to_user"`
	ToTeam    string  `json:"to_team"`
	RuleID    int64   `json:"rule_id"`
	Rule      string  `json:"rule"`
	Count     int     `json:"count"`
	FindingID []int64 `json:"finding_ids"`
}

// OwnerPlan is what ApplyOwnerRules would do (or did).
type OwnerPlan struct {
	Moves     []OwnerMove `json:"moves"`
	Total     int         `json:"total"`
	Truncated bool        `json:"truncated"`
	Applied   bool        `json:"applied"`
}

// ownerApplyLimit bounds one apply; run it again for the rest.
const ownerApplyLimit = 20000

// ApplyOwnerRules brings every open issue a person did not assign in line
// with the current rules: unassigned ones get their owner now, ones an
// earlier rule assigned move to the owner the rules name today (or are
// unassigned when none matches). With dryRun nothing changes.
func (s *Store) ApplyOwnerRules(ctx context.Context, dryRun bool) (*OwnerPlan, error) {
	ctx = tenant.WithoutProject(ctx)
	rules, version, err := s.rulesForPass(ctx)
	if err != nil {
		return nil, err
	}
	cands, err := ownerCandidates(ctx, s.Pool, `true`, ownerApplyLimit+1)
	if err != nil {
		return nil, err
	}
	plan := &OwnerPlan{Moves: []OwnerMove{}, Applied: !dryRun}
	if len(cands) > ownerApplyLimit {
		cands, plan.Truncated = cands[:ownerApplyLimit], true
	}
	names, err := s.ownerNames(ctx)
	if err != nil {
		return nil, err
	}
	type change struct {
		c ownerCandidate
		r *OwnerRule
	}
	var changes []change
	groups := map[string]*OwnerMove{}
	var order []string
	for _, c := range cands {
		r := best(rules, c)
		switch {
		case r == nil && c.userID == nil && c.teamID == nil:
			continue // unassigned and stays so
		case r != nil && eqID(r.UserID, c.userID) && eqID(r.TeamID, c.teamID):
			continue // already with that owner
		}
		changes = append(changes, change{c, r})
		m := OwnerMove{FromUser: names.user(c.userID), FromTeam: names.team(c.teamID)}
		if r != nil {
			m.ToUser, m.ToTeam, m.RuleID, m.Rule = names.user(r.UserID), names.team(r.TeamID), r.ID, r.Describe
		}
		key := fmt.Sprintf("%s|%s|%s|%s|%d", m.FromUser, m.FromTeam, m.ToUser, m.ToTeam, m.RuleID)
		g, ok := groups[key]
		if !ok {
			g = &m
			groups[key] = g
			order = append(order, key)
		}
		g.Count++
		if len(g.FindingID) < 20 {
			g.FindingID = append(g.FindingID, c.id)
		}
	}
	for _, k := range order {
		plan.Moves = append(plan.Moves, *groups[k])
		plan.Total += groups[k].Count
	}
	sort.SliceStable(plan.Moves, func(i, j int) bool { return plan.Moves[i].Count > plan.Moves[j].Count })
	if dryRun || len(changes) == 0 {
		return plan, nil
	}
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		for _, ch := range changes {
			var err error
			if ch.r == nil {
				_, err = unassignByRule(ctx, tx, ch.c.id, version)
			} else {
				_, err = assignByRule(ctx, tx, ch.c.id, ch.r, version, false)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	return plan, err
}

func eqID(a, b *int64) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

type ownerNameMap struct{ users, teams map[int64]string }

func (n ownerNameMap) user(id *int64) string {
	if id == nil {
		return ""
	}
	if s, ok := n.users[*id]; ok {
		return s
	}
	return fmt.Sprintf("user #%d", *id)
}

func (n ownerNameMap) team(id *int64) string {
	if id == nil {
		return ""
	}
	if s, ok := n.teams[*id]; ok {
		return s
	}
	return fmt.Sprintf("team #%d", *id)
}

// ownerNames maps the workspace's people (by email) and teams (by name).
func (s *Store) ownerNames(ctx context.Context) (ownerNameMap, error) {
	n := ownerNameMap{users: map[int64]string{}, teams: map[int64]string{}}
	rows, err := s.Pool.Query(ctx, `SELECT u.id, u.email FROM users u JOIN workspace_members m ON m.user_id = u.id AND m.workspace_id = stackurity_ws()`)
	if err != nil {
		return n, err
	}
	for rows.Next() {
		var id int64
		var e string
		if err := rows.Scan(&id, &e); err != nil {
			rows.Close()
			return n, err
		}
		n.users[id] = e
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return n, err
	}
	rows, err = s.Pool.Query(ctx, `SELECT id, name FROM teams`)
	if err != nil {
		return n, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var t string
		if err := rows.Scan(&id, &t); err != nil {
			return n, err
		}
		n.teams[id] = t
	}
	return n, rows.Err()
}

// OwnerCount is how many open issues of a fix one owner has.
type OwnerCount struct {
	UserEmail string `json:"user_email"`
	TeamName  string `json:"team_name"`
	Count     int64  `json:"count"`
}

// FixGroupOwners counts the open issues of a fix (one group, or several
// comma-separated as in FindingFilter.FixGroup) by who they are assigned
// to, most first; unassigned ones have neither name.
func (s *Store) FixGroupOwners(ctx context.Context, group string) ([]OwnerCount, error) {
	rows, err := s.Pool.Query(ctx, `SELECT COALESCE(u.email, ''), COALESCE(t.name, ''), count(*)
		FROM findings f LEFT JOIN users u ON u.id = f.assignee_user_id LEFT JOIN teams t ON t.id = f.assignee_team_id
		WHERE f.fix_group = ANY($1) AND f.status = 'open'
		GROUP BY 1, 2 ORDER BY 3 DESC, 1, 2`, strings.Split(group, ","))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[OwnerCount])
}

// OwnerCoverage splits the open issues by how they got their owner, so the
// owner-rule counts can be read against the open total: by a rule, by a
// person, or not at all.
type OwnerCoverage struct {
	Open       int64 `json:"open"`
	ByRule     int64 `json:"by_rule"`
	ByHand     int64 `json:"by_hand"`
	Unassigned int64 `json:"unassigned"`
}

// SummarizeOwnerCoverage counts the open issues the caller may see.
func (s *Store) SummarizeOwnerCoverage(ctx context.Context) (*OwnerCoverage, error) {
	c := &OwnerCoverage{}
	err := s.Pool.QueryRow(ctx, `SELECT count(*),
		  count(*) FILTER (WHERE f.owner_rule_id IS NOT NULL),
		  count(*) FILTER (WHERE f.owner_rule_id IS NULL AND (f.assignee_user_id IS NOT NULL OR f.assignee_team_id IS NOT NULL)),
		  count(*) FILTER (WHERE f.owner_rule_id IS NULL AND f.assignee_user_id IS NULL AND f.assignee_team_id IS NULL)
		FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		WHERE f.status = 'open'`).Scan(&c.Open, &c.ByRule, &c.ByHand, &c.Unassigned)
	return c, err
}
