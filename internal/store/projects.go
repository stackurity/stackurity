package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Projects group a workspace's assets; people and teams can be given a role
// on chosen projects, or on one asset, instead of on the whole organisation
// (docs/design/projects.md). Row-level security narrows what members with
// project access only can see (migration 0032); this file manages projects
// and grants and answers who may do what.

// RoleNone, as a member's role, means no organisation-wide role: the
// member sees only the projects and assets they are granted.
const RoleNone auth.Role = "none"

// Project is a named group of assets.
type Project struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
	ArchivedAt  *time.Time `json:"archived_at"`
	AssetCount  int64      `json:"asset_count"`
	// Role is the caller's role in the project when they have project
	// access only; empty for organisation-wide members.
	Role auth.Role `json:"role,omitempty"`
}

// ProjectRef names a project an asset belongs to.
type ProjectRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

var projectCols = `p.id, p.name, p.description, p.created_at, p.archived_at,
	(SELECT count(*) FROM project_assets pa JOIN assets a ON a.id = pa.asset_id WHERE pa.project_id = p.id AND a.merged_into IS NULL),
	COALESCE(CASE WHEN stackurity_member() IS NULL THEN NULL ELSE (SELECT g.role FROM access_grants g
	  WHERE g.project_id = p.id AND (g.user_id = stackurity_member()
	    OR g.team_id IN (SELECT tm.team_id FROM team_members tm WHERE tm.user_id = stackurity_member()))
	  ORDER BY ` + roleRank("g.role") + ` DESC LIMIT 1) END, '')`

func roleRank(col string) string {
	return `CASE ` + col + ` WHEN 'admin' THEN 4 WHEN 'security' THEN 3 WHEN 'engineer' THEN 2 WHEN 'viewer' THEN 1 ELSE 0 END`
}

// ListProjects lists the projects the caller may see: all of them for
// organisation-wide members, their own for members with project access
// only. Archived projects are included only when asked for.
func (s *Store) ListProjects(ctx context.Context, archived bool) ([]Project, error) {
	ctx = tenant.WithoutProject(ctx)
	cond := ` WHERE p.archived_at IS NULL`
	if archived {
		cond = ``
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+projectCols+` FROM projects p`+cond+` ORDER BY p.archived_at IS NOT NULL, lower(p.name), p.id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Project])
}

func (s *Store) GetProject(ctx context.Context, id int64) (*Project, error) {
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `SELECT `+projectCols+` FROM projects p WHERE p.id = $1`, id)
	if err != nil {
		return nil, err
	}
	p, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Project])
	return p, notFound(err)
}

// ProjectVisible reports whether the caller may choose the project in the
// switcher: it exists, is not archived, and they may see it.
func (s *Store) ProjectVisible(ctx context.Context, id int64) (bool, error) {
	var ok bool
	err := s.Pool.QueryRow(tenant.WithoutProject(ctx), `SELECT EXISTS (SELECT 1 FROM projects WHERE id = $1 AND archived_at IS NULL)`, id).Scan(&ok)
	return ok, err
}

func validProjectName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return "", fmt.Errorf("a project name of 1 to 100 characters is required: %w", ErrInvalid)
	}
	return name, nil
}

// CreateProject creates a project in the context's workspace.
func (s *Store) CreateProject(ctx context.Context, name, description string) (*Project, error) {
	name, err := validProjectName(name)
	if err != nil {
		return nil, err
	}
	if len(description) > 1000 {
		return nil, fmt.Errorf("the description is limited to 1000 characters: %w", ErrInvalid)
	}
	var id int64
	err = s.Pool.QueryRow(ctx, `INSERT INTO projects (name, description) VALUES ($1, $2) RETURNING id`, name, strings.TrimSpace(description)).Scan(&id)
	if isUniqueViolation(err) {
		return nil, fmt.Errorf("a project with that name exists: %w", ErrConflict)
	}
	if err != nil {
		return nil, err
	}
	return s.GetProject(ctx, id)
}

// ProjectUpdate changes a project; nil fields are left alone.
type ProjectUpdate struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Archived    *bool   `json:"archived"`
}

func (s *Store) UpdateProject(ctx context.Context, id int64, u ProjectUpdate) error {
	if u.Name != nil {
		n, err := validProjectName(*u.Name)
		if err != nil {
			return err
		}
		u.Name = &n
	}
	if u.Description != nil {
		if len(*u.Description) > 1000 {
			return fmt.Errorf("the description is limited to 1000 characters: %w", ErrInvalid)
		}
		d := strings.TrimSpace(*u.Description)
		u.Description = &d
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE projects SET name = COALESCE($2, name), description = COALESCE($3, description),
		archived_at = CASE WHEN $4::boolean IS NULL THEN archived_at WHEN $4 THEN COALESCE(archived_at, now()) ELSE NULL END
		WHERE id = $1`, id, u.Name, u.Description, u.Archived)
	if isUniqueViolation(err) {
		return fmt.Errorf("a project with that name exists: %w", ErrConflict)
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// AddProjectAssets puts assets into a project. Assets that do not exist (or
// were merged) are skipped; it returns how many were added.
func (s *Store) AddProjectAssets(ctx context.Context, projectID int64, assetIDs []int64) (int64, error) {
	if _, err := s.GetProject(ctx, projectID); err != nil {
		return 0, err
	}
	tag, err := s.Pool.Exec(ctx, `INSERT INTO project_assets (project_id, asset_id)
		SELECT $1, a.id FROM assets a WHERE a.id = ANY($2) AND a.merged_into IS NULL
		ON CONFLICT DO NOTHING`, projectID, assetIDs)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RemoveProjectAssets takes assets out of a project.
func (s *Store) RemoveProjectAssets(ctx context.Context, projectID int64, assetIDs []int64) (int64, error) {
	if _, err := s.GetProject(ctx, projectID); err != nil {
		return 0, err
	}
	tag, err := s.Pool.Exec(ctx, `DELETE FROM project_assets WHERE project_id = $1 AND asset_id = ANY($2)`, projectID, assetIDs)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// UnfiledAssetCount counts the assets in no active project.
func (s *Store) UnfiledAssetCount(ctx context.Context) (int64, error) {
	var n int64
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM assets a WHERE a.merged_into IS NULL AND NOT EXISTS (
		SELECT 1 FROM project_assets pa JOIN projects p ON p.id = pa.project_id WHERE pa.asset_id = a.id AND p.archived_at IS NULL)`).Scan(&n)
	return n, err
}

// --- grants

// Grant gives a person or a team a role on a project or on one asset.
type Grant struct {
	ID          int64     `json:"id"`
	ProjectID   *int64    `json:"project_id"`
	ProjectName string    `json:"project_name,omitempty"`
	AssetID     *int64    `json:"asset_id"`
	AssetName   string    `json:"asset_name,omitempty"`
	UserID      *int64    `json:"user_id"`
	UserEmail   string    `json:"user_email,omitempty"`
	UserName    string    `json:"user_name,omitempty"`
	TeamID      *int64    `json:"team_id"`
	TeamName    string    `json:"team_name,omitempty"`
	Role        auth.Role `json:"role"`
	CreatedAt   time.Time `json:"created_at"`
}

const grantCols = `g.id, g.project_id, COALESCE(p.name, ''), g.asset_id, COALESCE(a.name, ''),
	g.user_id, COALESCE(u.email, ''), COALESCE(u.name, ''), g.team_id, COALESCE(t.name, ''), g.role, g.created_at`

const grantFrom = ` FROM access_grants g LEFT JOIN projects p ON p.id = g.project_id LEFT JOIN assets a ON a.id = g.asset_id
	LEFT JOIN users u ON u.id = g.user_id LEFT JOIN teams t ON t.id = g.team_id`

// GrantFilter limits ListGrants; zero values match everything.
type GrantFilter struct {
	ProjectID int64
	AssetID   int64
	UserID    int64
	TeamID    int64
}

func (s *Store) ListGrants(ctx context.Context, f GrantFilter) ([]Grant, error) {
	w := &where{}
	if f.ProjectID > 0 {
		w.add("g.project_id = ?", f.ProjectID)
	}
	if f.AssetID > 0 {
		w.add("g.asset_id = ?", f.AssetID)
	}
	if f.UserID > 0 {
		w.add("g.user_id = ?", f.UserID)
	}
	if f.TeamID > 0 {
		w.add("g.team_id = ?", f.TeamID)
	}
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `SELECT `+grantCols+grantFrom+w.sql()+
		` ORDER BY COALESCE(p.name, a.name), COALESCE(u.email, t.name), g.id`, w.args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Grant])
}

func (s *Store) GetGrant(ctx context.Context, id int64) (*Grant, error) {
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `SELECT `+grantCols+grantFrom+` WHERE g.id = $1`, id)
	if err != nil {
		return nil, err
	}
	g, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Grant])
	return g, notFound(err)
}

// GrantInput describes a grant to create or change: exactly one of
// ProjectID and AssetID, and one of UserID and TeamID.
type GrantInput struct {
	ProjectID *int64    `json:"project_id"`
	AssetID   *int64    `json:"asset_id"`
	UserID    *int64    `json:"user_id"`
	TeamID    *int64    `json:"team_id"`
	Role      auth.Role `json:"role"`
}

// SaveGrant creates the grant, or changes the role of the existing grant
// for the same person or team on the same project or asset. created
// reports which.
func (s *Store) SaveGrant(ctx context.Context, in GrantInput, by int64) (g *Grant, created bool, err error) {
	if !in.Role.ValidUser() {
		return nil, false, fmt.Errorf("role must be viewer, engineer, security or admin: %w", ErrInvalid)
	}
	if (in.ProjectID == nil) == (in.AssetID == nil) {
		return nil, false, fmt.Errorf("name either a project or an asset: %w", ErrInvalid)
	}
	if (in.UserID == nil) == (in.TeamID == nil) {
		return nil, false, fmt.Errorf("name either a person or a team: %w", ErrInvalid)
	}
	ctx = tenant.WithoutProject(ctx)
	var id int64
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `UPDATE access_grants SET role = $5
			WHERE project_id IS NOT DISTINCT FROM $1 AND asset_id IS NOT DISTINCT FROM $2
			  AND user_id IS NOT DISTINCT FROM $3 AND team_id IS NOT DISTINCT FROM $4 RETURNING id`,
			in.ProjectID, in.AssetID, in.UserID, in.TeamID, in.Role).Scan(&id)
		if err == nil {
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var byID *int64
		if by > 0 {
			byID = &by
		}
		err = tx.QueryRow(ctx, `INSERT INTO access_grants (project_id, asset_id, user_id, team_id, role, created_by)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`, in.ProjectID, in.AssetID, in.UserID, in.TeamID, in.Role, byID).Scan(&id)
		if isForeignKey(err) {
			return fmt.Errorf("no such project, asset, person or team in this organisation: %w", ErrInvalid)
		}
		created = err == nil
		return err
	})
	if err != nil {
		return nil, false, err
	}
	g, err = s.GetGrant(ctx, id)
	return g, created, err
}

func (s *Store) DeleteGrant(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(tenant.WithoutProject(ctx), `DELETE FROM access_grants WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// EnsureMember makes the user with email a member of the context's
// workspace, creating the account (with password) when needed. A new
// member gets no organisation-wide role: they see only what they are
// granted. It returns the user's id and whether the account was created.
func (s *Store) EnsureMember(ctx context.Context, email, name, password string) (int64, bool, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return 0, false, errNoWorkspace
	}
	var id int64
	var created bool
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var before, after int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&before); err != nil {
			return err
		}
		var err error
		if id, err = ensureUser(ctx, tx, email, name, password); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&after); err != nil {
			return err
		}
		created = after > before
		_, err = tx.Exec(ctx, `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, NULL)
			ON CONFLICT (workspace_id, user_id) DO NOTHING`, ws, id)
		return err
	})
	return id, created, err
}

// --- who may do what

// Access is what a user may do in a workspace.
type Access struct {
	// Member: the user belongs to the workspace (with or without an
	// organisation-wide role).
	Member bool
	// OrgRole is the organisation-wide role; empty when the user has
	// project access only.
	OrgRole auth.Role
	// ProjectRole is the highest role the user holds through project and
	// asset grants (their own or their teams'), counting active projects
	// only; empty when none.
	ProjectRole auth.Role
}

// Restricted: a member without an organisation-wide role, who sees only
// their projects' assets and asset grants.
func (a Access) Restricted() bool { return a.Member && a.OrgRole == "" }

// UserAccess returns what userID may do in workspace ws (an enabled one).
func (s *Store) UserAccess(ctx context.Context, ws, userID int64) (Access, error) {
	var a Access
	err := s.Pool.QueryRow(tenant.WithWorkspace(ctx, ws), `SELECT
		EXISTS (SELECT 1 FROM workspace_members m JOIN workspaces w ON w.id = m.workspace_id
		  WHERE m.workspace_id = $1 AND m.user_id = $2 AND w.disabled_at IS NULL),
		COALESCE((SELECT m.role FROM workspace_members m WHERE m.workspace_id = $1 AND m.user_id = $2), ''),
		COALESCE((SELECT g.role FROM access_grants g LEFT JOIN projects p ON p.id = g.project_id
		  WHERE (g.user_id = $2 OR g.team_id IN (SELECT tm.team_id FROM team_members tm WHERE tm.user_id = $2))
		    AND (g.asset_id IS NOT NULL OR p.archived_at IS NULL)
		  ORDER BY `+roleRank("g.role")+` DESC LIMIT 1), '')`, ws, userID).Scan(&a.Member, &a.OrgRole, &a.ProjectRole)
	if !a.Member {
		return Access{}, err
	}
	return a, err
}

// GrantRoleOn returns the lowest of the roles userID holds on each of the
// assets through project and asset grants: the role they may act with on
// all of them. Empty when they have no grant on one of them.
func (s *Store) GrantRoleOn(ctx context.Context, userID int64, assetIDs []int64) (auth.Role, error) {
	if len(assetIDs) == 0 {
		return "", nil
	}
	var low int
	var all bool
	err := s.Pool.QueryRow(tenant.WithoutProject(ctx), `SELECT COALESCE(min(`+roleRank("r")+`), 0), bool_and(r IS NOT NULL)
		FROM (SELECT stackurity_grant_role($1, a) AS r FROM unnest($2::bigint[]) a) x`, userID, assetIDs).Scan(&low, &all)
	if err != nil || !all {
		return "", err
	}
	return [...]auth.Role{"", auth.RoleViewer, auth.RoleEngineer, auth.RoleSecurity, auth.RoleAdmin}[low], nil
}

// FindingAssets returns the assets of the findings the caller can see.
func (s *Store) FindingAssets(ctx context.Context, findingIDs []int64) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT asset_id FROM findings WHERE id = ANY($1)`, findingIDs)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// SetDefaultProject remembers the project a member chose in the switcher
// (0: all projects).
func (s *Store) SetDefaultProject(ctx context.Context, userID, projectID int64) error {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return errNoWorkspace
	}
	var pid *int64
	if projectID > 0 {
		pid = &projectID
	}
	_, err := s.Pool.Exec(ctx, `UPDATE workspace_members SET default_project_id = $3 WHERE workspace_id = $1 AND user_id = $2`, ws, userID, pid)
	return err
}

// DefaultProject returns the project a member last chose, if they may
// still see it (0 otherwise).
func (s *Store) DefaultProject(ctx context.Context, userID int64) (int64, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return 0, nil
	}
	var id *int64
	err := s.Pool.QueryRow(ctx, `SELECT default_project_id FROM workspace_members WHERE workspace_id = $1 AND user_id = $2`, ws, userID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) || id == nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if ok, err := s.ProjectVisible(ctx, *id); err != nil || !ok {
		return 0, err
	}
	return *id, nil
}

// --- suggestions

// ProjectSuggestion proposes putting related assets together: adding
// assets to the project their neighbours are in, or a new project for a
// group of related assets in none. Nothing is changed until someone
// accepts it.
type ProjectSuggestion struct {
	Key           string       `json:"key"`
	ProjectID     int64        `json:"project_id,omitempty"`
	ProjectName   string       `json:"project_name,omitempty"`
	SuggestedName string       `json:"suggested_name,omitempty"`
	Assets        []AssetBrief `json:"assets"`
	Reason        string       `json:"reason"`
}

// AssetBrief names an asset.
type AssetBrief struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

const dismissedSuggestionsKey = "projects.dismissed_suggestions"

// groupingKinds are the relations that mean "these belong together".
var groupingKinds = []string{"runs_on", "built_from", "deployed_as"}

// ProjectSuggestions proposes groupings from what Stackurity knows about
// how assets relate (an application runs on a host, is built from a
// repository, is deployed as an image).
func (s *Store) ProjectSuggestions(ctx context.Context) ([]ProjectSuggestion, error) {
	ctx = tenant.WithoutProject(ctx)
	type edge struct{ from, to int64 }
	rows, err := s.Pool.Query(ctx, `SELECT r.from_asset, r.to_asset FROM asset_relations r
		JOIN assets a ON a.id = r.from_asset AND a.merged_into IS NULL
		JOIN assets b ON b.id = r.to_asset AND b.merged_into IS NULL
		WHERE r.kind = ANY($1) AND r.from_asset <> r.to_asset`, groupingKinds)
	if err != nil {
		return nil, err
	}
	var edges []edge
	for rows.Next() {
		var e edge
		if err := rows.Scan(&e.from, &e.to); err != nil {
			rows.Close()
			return nil, err
		}
		edges = append(edges, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(edges) == 0 {
		return []ProjectSuggestion{}, nil
	}
	assets := map[int64]AssetBrief{}
	var ids []int64
	for _, e := range edges {
		for _, id := range []int64{e.from, e.to} {
			if _, ok := assets[id]; !ok {
				assets[id] = AssetBrief{ID: id}
				ids = append(ids, id)
			}
		}
	}
	rows, err = s.Pool.Query(ctx, `SELECT id, name, kind FROM assets WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	briefs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[AssetBrief])
	if err != nil {
		return nil, err
	}
	for _, b := range briefs {
		assets[b.ID] = b
	}
	// Active projects of each related asset.
	rows, err = s.Pool.Query(ctx, `SELECT pa.asset_id, p.id, p.name FROM project_assets pa JOIN projects p ON p.id = pa.project_id
		WHERE pa.asset_id = ANY($1) AND p.archived_at IS NULL`, ids)
	if err != nil {
		return nil, err
	}
	inProject := map[int64][]ProjectRef{}
	names := map[int64]string{}
	for rows.Next() {
		var a int64
		var p ProjectRef
		if err := rows.Scan(&a, &p.ID, &p.Name); err != nil {
			rows.Close()
			return nil, err
		}
		inProject[a] = append(inProject[a], p)
		names[p.ID] = p.Name
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	dismissed, err := s.dismissedSuggestions(ctx)
	if err != nil {
		return nil, err
	}

	// 1. An asset in no project, related to assets of a project: add it.
	add := map[int64]map[int64]bool{} // project -> assets
	for _, e := range edges {
		for _, pair := range [][2]int64{{e.from, e.to}, {e.to, e.from}} {
			filed, loose := pair[0], pair[1]
			if len(inProject[loose]) > 0 {
				continue
			}
			for _, p := range inProject[filed] {
				if add[p.ID] == nil {
					add[p.ID] = map[int64]bool{}
				}
				add[p.ID][loose] = true
			}
		}
	}
	var out []ProjectSuggestion
	for pid, set := range add {
		sg := ProjectSuggestion{ProjectID: pid, ProjectName: names[pid], Assets: briefList(assets, set)}
		sg.Key = suggestionKey("add", pid, sg.Assets)
		sg.Reason = fmt.Sprintf("Related to assets in %s (runs on, built from or deployed as)", names[pid])
		if !dismissed[sg.Key] {
			out = append(out, sg)
		}
	}

	// 2. Groups of related assets that are all in no project: a new project.
	parent := map[int64]int64{}
	var find func(int64) int64
	find = func(x int64) int64 {
		if p, ok := parent[x]; ok && p != x {
			r := find(p)
			parent[x] = r
			return r
		}
		parent[x] = x
		return x
	}
	for _, e := range edges {
		if len(inProject[e.from]) > 0 || len(inProject[e.to]) > 0 {
			continue
		}
		a, b := find(e.from), find(e.to)
		if a != b {
			parent[a] = b
		}
	}
	groups := map[int64]map[int64]bool{}
	for id := range parent {
		r := find(id)
		if groups[r] == nil {
			groups[r] = map[int64]bool{}
		}
		groups[r][id] = true
	}
	for _, set := range groups {
		if len(set) < 2 {
			continue
		}
		sg := ProjectSuggestion{Assets: briefList(assets, set)}
		sg.SuggestedName = suggestedName(sg.Assets)
		sg.Key = suggestionKey("new", 0, sg.Assets)
		sg.Reason = "These assets are related and in no project"
		if !dismissed[sg.Key] {
			out = append(out, sg)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].ProjectID > 0) != (out[j].ProjectID > 0) {
			return out[i].ProjectID > 0
		}
		if out[i].ProjectName != out[j].ProjectName {
			return out[i].ProjectName < out[j].ProjectName
		}
		return out[i].Assets[0].Name < out[j].Assets[0].Name
	})
	if out == nil {
		out = []ProjectSuggestion{}
	}
	return out, nil
}

func briefList(all map[int64]AssetBrief, set map[int64]bool) []AssetBrief {
	out := make([]AssetBrief, 0, len(set))
	for id := range set {
		out = append(out, all[id])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// suggestedName prefers the application's name, then the repository's.
func suggestedName(list []AssetBrief) string {
	for _, kind := range []string{"application", "repository", "image"} {
		for _, a := range list {
			if a.Kind == kind {
				return a.Name
			}
		}
	}
	return list[0].Name
}

// suggestionKey identifies a suggestion by what it proposes, so a dismissed
// suggestion comes back only when its assets change.
func suggestionKey(kind string, project int64, list []AssetBrief) string {
	ids := make([]string, len(list))
	for i, a := range list {
		ids[i] = strconv.FormatInt(a.ID, 10)
	}
	sum := sha256.Sum256([]byte(kind + ":" + strconv.FormatInt(project, 10) + ":" + strings.Join(ids, ",")))
	return kind + "-" + hex.EncodeToString(sum[:8])
}

func (s *Store) dismissedSuggestions(ctx context.Context) (map[string]bool, error) {
	var raw []byte
	err := s.Pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, dismissedSuggestionsKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	var keys []string
	_ = json.Unmarshal(raw, &keys)
	out := map[string]bool{}
	for _, k := range keys {
		out[k] = true
	}
	return out, nil
}

// DismissSuggestion hides a suggestion until the assets it names change.
func (s *Store) DismissSuggestion(ctx context.Context, key string) error {
	if len(key) > 40 || !strings.HasPrefix(key, "add-") && !strings.HasPrefix(key, "new-") {
		return fmt.Errorf("unknown suggestion: %w", ErrInvalid)
	}
	ctx = tenant.WithoutProject(ctx)
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1 FOR UPDATE`, dismissedSuggestionsKey).Scan(&raw)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var keys []string
		_ = json.Unmarshal(raw, &keys)
		for _, k := range keys {
			if k == key {
				return nil
			}
		}
		keys = append(keys, key)
		if len(keys) > 500 {
			keys = keys[len(keys)-500:]
		}
		b, _ := json.Marshal(keys)
		_, err = tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
			ON CONFLICT (workspace_id, key) DO UPDATE SET value = EXCLUDED.value`, dismissedSuggestionsKey, b)
		return err
	})
}

// narrowIncidents recomputes what incidents say about their findings from
// the findings the caller can see, when the caller sees only some of the
// workspace's assets. An incident groups one issue across every asset, so
// its stored counts, names, priority and title can describe assets of
// other projects.
func (s *Store) narrowIncidents(ctx context.Context, list []Incident) error {
	if !tenant.Narrowed(ctx) || len(list) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(list))
	for _, in := range list {
		if isFindingKind(in.Kind) {
			ids = append(ids, in.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	// Active findings for open incidents; every finding for resolved ones.
	rows, err := s.Pool.Query(ctx, `SELECT f.incident_id,
		  count(*)::int, count(DISTINCT f.asset_id)::int,
		  (array_agg(f.title ORDER BY f.priority_score DESC))[1], min(f.priority), bool_or(f.sos), max(f.escalation_level),
		  CASE WHEN bool_or(f.state = 'new') THEN 'new' WHEN bool_or(f.state = 'acknowledged') THEN 'acknowledged' ELSE 'in_progress' END,
		  jsonb_build_object(
		    'assets', (array_agg(DISTINCT a.name))[1:10],
		    'environments', COALESCE(array_agg(DISTINCT a.environment) FILTER (WHERE a.environment <> ''), '{}'),
		    'components', (array_agg(DISTINCT CASE WHEN c.namespace = '' THEN c.name ELSE c.namespace || '/' || c.name END))[1:10],
		    'fixed_versions', COALESCE(array_agg(DISTINCT f.fixed_version) FILTER (WHERE f.fixed_version <> ''), '{}'),
		    'known_exploited', bool_or(COALESCE((f.evidence->>'known_exploited')::boolean, false)),
		    'severity', (array_agg(f.severity ORDER BY f.priority_score DESC))[1])
		FROM findings f JOIN incidents i ON i.id = f.incident_id
		JOIN assets a ON a.id = f.asset_id JOIN components c ON c.id = f.component_id
		WHERE f.incident_id = ANY($1)
		  AND (i.status <> 'open' OR (f.status = 'open' AND f.state IN ('new', 'acknowledged', 'in_progress')))
		GROUP BY f.incident_id`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	type agg struct {
		findings, assets       int
		title, priority, state string
		sos                    bool
		escalation             int
		detail                 json.RawMessage
	}
	got := map[int64]agg{}
	for rows.Next() {
		var id int64
		var a agg
		if err := rows.Scan(&id, &a.findings, &a.assets, &a.title, &a.priority, &a.sos, &a.escalation, &a.state, &a.detail); err != nil {
			return err
		}
		got[id] = a
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range list {
		in := &list[i]
		if !isFindingKind(in.Kind) {
			continue
		}
		// What was announced, and when, was about every asset.
		in.NotifiedPriority, in.NotifiedAt = "", nil
		a, ok := got[in.ID]
		if !ok {
			// Visible through a finding that is no longer active: say
			// nothing about the others.
			in.FindingCount, in.AssetCount = 0, 0
			in.Detail = json.RawMessage(`{}`)
			continue
		}
		in.FindingCount, in.AssetCount = a.findings, a.assets
		in.Title, in.Priority, in.SOS, in.Detail, in.EscalationLevel = a.title, a.priority, a.sos, a.detail, a.escalation
		if in.Status == "open" {
			in.State = a.state
		}
	}
	return nil
}

func isFindingKind(kind string) bool { return kind == "vulnerability" || kind == "end_of_life" }

// ProjectColleagues returns the members a member with project access only
// may see in pickers: themselves and the people granted (directly or
// through a team) one of their projects.
func (s *Store) ProjectColleagues(ctx context.Context, userID int64) (map[int64]bool, error) {
	rows, err := s.Pool.Query(tenant.WithMember(tenant.WithoutProject(ctx), userID), `SELECT g.user_id FROM access_grants g
		WHERE g.user_id IS NOT NULL AND g.project_id = ANY (stackurity_member_projects())
		UNION SELECT tm.user_id FROM access_grants g JOIN team_members tm ON tm.team_id = g.team_id
		WHERE g.project_id = ANY (stackurity_member_projects())`)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, err
	}
	out := map[int64]bool{userID: true}
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// ProjectPeople returns who can see projectID: the organisation's members
// with an organisation-wide role, and the people granted the project
// directly or through a team.
func (s *Store) ProjectPeople(ctx context.Context, projectID int64) (map[int64]bool, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil, fmt.Errorf("project people need a workspace: %w", ErrInvalid)
	}
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `SELECT user_id FROM workspace_members WHERE workspace_id = $1 AND role IS NOT NULL
		UNION SELECT g.user_id FROM access_grants g WHERE g.user_id IS NOT NULL AND g.project_id = $2
		UNION SELECT tm.user_id FROM access_grants g JOIN team_members tm ON tm.team_id = g.team_id WHERE g.project_id = $2`, ws, projectID)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, err
	}
	out := map[int64]bool{}
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// FixGroupAsset returns the asset of a fix group the caller can see.
func (s *Store) FixGroupAsset(ctx context.Context, id string) (int64, error) {
	var a int64
	err := s.Pool.QueryRow(ctx, `SELECT asset_id FROM fix_groups WHERE id = $1`, id).Scan(&a)
	return a, notFound(err)
}

// IgnoreRuleAsset returns the asset of an ignore rule the caller can see;
// nil for a rule that covers every asset.
func (s *Store) IgnoreRuleAsset(ctx context.Context, id int64) (*int64, error) {
	var a *int64
	err := s.Pool.QueryRow(ctx, `SELECT asset_id FROM finding_exceptions WHERE id = $1`, id).Scan(&a)
	return a, notFound(err)
}

// GrantAssets returns the assets on which userID holds at least min
// through project and asset grants (their own or their teams'), counting
// active projects only.
func (s *Store) GrantAssets(ctx context.Context, userID int64, min auth.Role) ([]int64, error) {
	rows, err := s.Pool.Query(tenant.WithoutProject(ctx), `WITH g AS (
		  SELECT g.project_id, g.asset_id FROM access_grants g LEFT JOIN projects p ON p.id = g.project_id
		  WHERE (g.user_id = $1 OR g.team_id IN (SELECT tm.team_id FROM team_members tm WHERE tm.user_id = $1))
		    AND (g.asset_id IS NOT NULL OR p.archived_at IS NULL) AND `+roleRank("g.role")+` >= `+roleRank("$2::text")+`)
		SELECT pa.asset_id FROM project_assets pa JOIN g ON g.project_id = pa.project_id
		UNION SELECT asset_id FROM g WHERE asset_id IS NOT NULL`, userID, string(min))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// ColleagueTeams returns the teams granted (any role) one of the projects
// userID is granted, directly or through a team: the teams a person who
// acts through project grants may assign issues to.
func (s *Store) ColleagueTeams(ctx context.Context, userID int64) (map[int64]bool, error) {
	rows, err := s.Pool.Query(tenant.WithMember(tenant.WithoutProject(ctx), userID), `SELECT DISTINCT g.team_id FROM access_grants g
		WHERE g.team_id IS NOT NULL AND g.project_id = ANY (stackurity_member_projects())`)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, err
	}
	out := map[int64]bool{}
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// MergeAccess is what merging assets into a target changes about access:
// the target joins the merged assets' projects, and grants on them move to
// it.
type MergeAccess struct {
	ProjectsJoined []ProjectRef `json:"projects_joined"`
	GrantsMoved    int64        `json:"grants_moved"`
}

// MergeAccessPreview says, before an identity conflict is resolved into
// target, which projects target will join and how many asset grants will
// move to it.
func (s *Store) MergeAccessPreview(ctx context.Context, conflictID, target int64) (*MergeAccess, error) {
	ctx = tenant.WithoutProject(ctx)
	var ids []int64
	if err := s.Pool.QueryRow(ctx, `SELECT asset_ids FROM identity_conflicts WHERE id = $1`, conflictID).Scan(&ids); err != nil {
		return nil, notFound(err)
	}
	var others []int64
	for _, id := range ids {
		if id != target {
			others = append(others, id)
		}
	}
	out := &MergeAccess{ProjectsJoined: []ProjectRef{}}
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT p.id, p.name FROM project_assets pa JOIN projects p ON p.id = pa.project_id
		WHERE pa.asset_id = ANY($1) AND NOT EXISTS (SELECT 1 FROM project_assets t WHERE t.project_id = pa.project_id AND t.asset_id = $2)
		ORDER BY p.name`, others, target)
	if err != nil {
		return nil, err
	}
	if out.ProjectsJoined, err = pgx.CollectRows(rows, pgx.RowToStructByPos[ProjectRef]); err != nil {
		return nil, err
	}
	err = s.Pool.QueryRow(ctx, `SELECT count(*) FROM access_grants WHERE asset_id = ANY($1)`, others).Scan(&out.GrantsMoved)
	return out, err
}
