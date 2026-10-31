package mcp

import (
	"context"
	"errors"
	"slices"
)

// The read-only tools, for callers inside the server that are not MCP
// clients: the in-app assistant (internal/ask) offers exactly these to its
// model and runs them as the signed-in user. Tools that change something
// (write.go) are never reachable from here, whatever the caller asks for.

// ReadTool describes one read-only tool.
type ReadTool struct {
	Name        string
	Title       string
	Description string
	// InputSchema is the tool's JSON Schema. Callers must not change it:
	// it is shared with the MCP endpoint.
	InputSchema map[string]any
}

// ErrNotReadTool is returned by CallRead for a name that is not a read-only
// tool: unknown, or a tool that changes something.
var ErrNotReadTool = errors.New("no such read-only tool")

// ReadTools lists the read-only tools in their fixed order, so a list built
// from it is byte-identical from one request to the next.
func ReadTools() []ReadTool {
	out := make([]ReadTool, 0, len(readTools))
	for _, n := range readTools {
		t := tools[n]
		out = append(out, ReadTool{Name: n, Title: readTitles[n], Description: t.description, InputSchema: t.schema})
	}
	return out
}

// IsReadTool reports whether name is a read-only tool.
func IsReadTool(name string) bool { return slices.Contains(readTools, name) }

// CallRead runs the read-only tool name with args through api and returns
// its result (JSON-encodable). A name that is not a read-only tool is
// ErrNotReadTool and makes no call. Errors from the tool (a missing
// argument, the API refusing) are returned as they are.
func CallRead(ctx context.Context, api API, name string, args map[string]any) (any, error) {
	if !IsReadTool(name) {
		return nil, ErrNotReadTool
	}
	t := tools[name]
	if t.write != nil || t.run == nil {
		return nil, ErrNotReadTool
	}
	if args == nil {
		args = map[string]any{}
	}
	return t.run(ctx, api, args)
}
