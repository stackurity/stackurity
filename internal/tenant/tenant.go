// Package tenant carries the workspace scope of a request or job in its
// context. The database pool reads it on every connection it hands out and
// sets the matching PostgreSQL settings, which row-level security checks
// (docs/design/workspaces.md). A context without a scope sees no tenant rows.
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
}

type ctxKey struct{}

// DefaultWorkspace is the workspace that existing data moved into, and the
// only one a single-organisation install has.
const DefaultWorkspace int64 = 1

// WithWorkspace scopes ctx to one workspace.
func WithWorkspace(ctx context.Context, id int64) context.Context {
	return context.WithValue(ctx, ctxKey{}, scope{workspace, id})
}

// System scopes ctx to platform work that spans workspaces: claiming jobs,
// resolving tokens and sessions, feed synchronisation and housekeeping.
// Request handlers must never use it on behalf of a caller.
func System(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, scope{system, 0})
}

// Workspace returns the workspace ctx is scoped to.
func Workspace(ctx context.Context) (int64, bool) {
	s, _ := ctx.Value(ctxKey{}).(scope)
	return s.id, s.kind == workspace
}

// IsSystem reports whether ctx has system scope.
func IsSystem(ctx context.Context) bool {
	s, _ := ctx.Value(ctxKey{}).(scope)
	return s.kind == system
}

// Settings returns the values for the stackurity.scope and
// stackurity.workspace_id connection settings.
func Settings(ctx context.Context) (scopeName, workspaceID string) {
	s, _ := ctx.Value(ctxKey{}).(scope)
	switch s.kind {
	case workspace:
		return "workspace", strconv.FormatInt(s.id, 10)
	case system:
		return "system", ""
	}
	return "", ""
}
