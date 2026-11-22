package confcheck

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/stackurity/stackurity/internal/model"
)

// Repo runs the repository checks on the checkout at dir: GitHub Actions
// workflows (actions.go), and AI coding-agent hooks and MCP start commands
// checked into it that download and run code, and a copy of a known attack
// tool's source or images of one (attacktools.go). Paths are relative to dir.
func Repo(ctx context.Context, dir string) *model.ConfigScan {
	found, problems := Workflows(dir)
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	for _, hf := range ProjectHookFiles(dir, exists) {
		if ctx.Err() != nil {
			break
		}
		real, ok := insideDir(dir, hf.Path)
		if !ok {
			continue // missing, not a file, or a link out of the checkout (.claude -> /root/.claude)
		}
		data, truncated, err := ReadBounded(real)
		if err != nil || truncated {
			continue
		}
		display, _ := filepath.Rel(dir, hf.Path)
		display = filepath.ToSlash(display)
		cmds, err := ReadHookCommands(hf, data)
		if err != nil {
			continue
		}
		for _, c := range cmds {
			if r, ok := HookRisk(hf.Client, display, data, c, dir); ok {
				found = append(found, finding(r.Rule, model.ConfigAgentHook, hf.Client+" hook downloads and runs code", r.Severity,
					r.File, r.Line, c.Event+": "+RedactCommand(c.Command), r.Why, r.Fix))
			}
		}
	}
	for _, rel := range []string{".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json"} {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		real, ok := insideDir(dir, p)
		if !ok {
			continue
		}
		data, truncated, err := ReadBounded(real)
		if err != nil || truncated {
			continue
		}
		servers, err := MCPStartCommands(data)
		if err != nil {
			continue
		}
		for _, sv := range servers {
			if r, ok := MCPRisk(sv.Command); ok {
				found = append(found, finding(r.Rule, model.ConfigAgentHook, "MCP server start command downloads and runs code", r.Severity,
					rel, LineOf(data, sv.Name), "mcp "+sv.Name+": "+RedactCommand(sv.Command), "MCP server "+sv.Name+": "+r.Why+".", r.Fix))
			}
		}
	}
	found = append(found, repoAttackTools(dir)...)
	out := &model.ConfigScan{Found: dedupe(found), Complete: ctx.Err() == nil && len(problems) == 0}
	if len(problems) > 0 {
		out.Reason = clip(strings.Join(problems, "; "), model.MaxFieldLen)
	}
	return out
}
