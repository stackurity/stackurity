// Package tenant carries the workspace scope of a request or job in its
// context. The database pool reads it on every connection it hands out and
// sets the matching PostgreSQL settings, which row-level security checks
// (docs/design/workspaces.md). A context without a scope sees no tenant rows.
//
// A workspace scope can be narrowed to some of the workspace's assets
// (docs/design/projects.md): to a member who has project access only, and
// to the project an organisation-wide member chose in the switcher.
package tenant

import (
	"context"
	"strconv"
)

type kind int

const (
	none kind = iota
	workspace
	system
)

type scope struct {
	kind kind
	id   int64
	// member is the user id of a caller with no organisation-wide role:
	// they see only their projects' assets and their asset grants.
	member int64
	// project is the project the caller chose (0: all they may see).
	project int64
}

type ctxKey struct{}

// DefaultWorkspace is the workspace that existing data moved into, and the
// only one a single-organisation install has.
const DefaultWorkspace int64 = 1

// WithWorkspace scopes ctx to the whole of one workspace. It drops any
// narrowing ctx had.
func WithWorkspace(ctx context.Context, id int64) context.Context {
	return context.WithValue(ctx, ctxKey{}, scope{kind: workspace, id: id})
}

// WithMember narrows a workspace scope to what a member with project access
// only may see. It does nothing outside a workspace scope.
func WithMember(ctx context.Context, userID int64) context.Context {
	s, _ := ctx.Value(ctxKey{}).(scope)
	if s.kind != workspace || userID <= 0 {
		return ctx
	}
	s.member = userID
	return context.WithValue(ctx, ctxKey{}, s)
}

// WithProject narrows a workspace scope to one project's assets. It does
// nothing outside a workspace scope.
func WithProject(ctx context.Context, projectID int64) context.Context {
	s, _ := ctx.Value(ctxKey{}).(scope)
	if s.kind != workspace || projectID <= 0 {
		return ctx
	}
	s.project = projectID
	return context.WithValue(ctx, ctxKey{}, s)
}

// WithoutProject keeps the workspace and member of ctx but drops the chosen
// project, for work on the whole workspace (settings, pickers) while a
// project is selected. A member stays narrowed to their own access.
func WithoutProject(ctx context.Context) context.Context {
	s, _ := ctx.Value(ctxKey{}).(scope)
	if s.project == 0 {
		return ctx
	}
	s.project = 0
	return context.WithValue(ctx, ctxKey{}, s)
}

// System scopes ctx to platform work that spans workspaces: claiming jobs,
// resolving tokens and sessions, feed synchronisation and housekeeping.
// Request handlers must never use it on behalf of a caller.
func System(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, scope{kind: system})
}

// Workspace returns the workspace ctx is scoped to.
func Workspace(ctx context.Context) (int64, bool) {
	s, _ := ctx.Value(ctxKey{}).(scope)
	return s.id, s.kind == workspace
}

// Member returns the member ctx is narrowed to (0: not narrowed to one).
func Member(ctx context.Context) int64 {
	s, _ := ctx.Value(ctxKey{}).(scope)
	return s.member
}

// Project returns the project ctx is narrowed to (0: none chosen).
func Project(ctx context.Context) int64 {
	s, _ := ctx.Value(ctxKey{}).(scope)
	return s.project
}

// Narrowed reports whether ctx sees only some of its workspace's assets.
func Narrowed(ctx context.Context) bool {
	s, _ := ctx.Value(ctxKey{}).(scope)
	return s.kind == workspace && (s.member > 0 || s.project > 0)
}

// IsSystem reports whether ctx has system scope.
func IsSystem(ctx context.Context) bool {
	s, _ := ctx.Value(ctxKey{}).(scope)
	return s.kind == system
}

// Settings returns the values for the stackurity.scope and
// stackurity.workspace_id connection settings.
func Settings(ctx context.Context) (scopeName, workspaceID string) {
	scopeName, workspaceID, _, _ = AllSettings(ctx)
	return
}

// AllSettings also returns the values for stackurity.member and
// stackurity.project, empty unless the workspace scope is narrowed.
func AllSettings(ctx context.Context) (scopeName, workspaceID, member, project string) {
	s, _ := ctx.Value(ctxKey{}).(scope)
	switch s.kind {
	case workspace:
		if s.member > 0 {
			member = strconv.FormatInt(s.member, 10)
		}
		if s.project > 0 {
			project = strconv.FormatInt(s.project, 10)
		}
		return "workspace", strconv.FormatInt(s.id, 10), member, project
	case system:
		return "system", "", "", ""
	}
	return "", "", "", ""
}
