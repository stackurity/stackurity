// Package confcheck finds risky settings in the files a collector reads:
// AI coding-agent hooks that download and run code (hooks.go), SSH access
// that gives root an unrestricted shell (ssh.go), and GitHub Actions
// workflows that run third-party code by a movable tag (actions.go).
//
// The rules are shared: the agent runs them on hosts (Host), the server's
// Git integrations and `stackurity scan` on repositories (Repo), and the
// standalone scanner (github.com/stackurity/scan) through pkg/engine, so a
// rule fixed here is fixed everywhere.
package confcheck

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Hooks are commands an AI coding agent or an editor runs on its own: when
// a session starts, before a tool runs, when a folder is opened. A project
// that checks one in decides what runs on every machine that opens it, so
// these files are a supply-chain surface: an attacker who can change one
// line gets code execution on every developer's machine the next time the
// agent starts (Google's GTIG reported exactly this in November 2026: a
// modified .claude/settings.json whose hook downloaded a backdoor).
//
// Every hook command is listed. Only a command that fetches code from the
// network and runs it, or hides what it runs, is a high risk: a formatter or
// a linter run as a hook is what hooks are for. On a host, a hook that runs
// a script from a Git checkout of another repository is a medium one
// (gittree.go).

// Rules for commands that run automatically.
const (
	// RuleHookRemoteExec: a hook (or a task run when a folder opens)
	// downloads code and runs it.
	RuleHookRemoteExec = "agent-hook-remote-exec"
	// RuleMCPRemoteExec: an MCP server's start command downloads code and
	// runs it.
	RuleMCPRemoteExec = "mcp-start-remote-exec"
	// RuleHookGitTree: a hook runs a script from a Git checkout of another
	// repository, so a push there changes what runs here.
	RuleHookGitTree = "agent-hook-git-checkout"
)

// MaxHookFile bounds a settings file or a script a hook runs.
const MaxHookFile = 1 << 20

// HookFile is a file that holds hooks, and how to read it.
type HookFile struct {
	Client string // Claude Code, Cursor, Gemini CLI, Windsurf, VS Code, Codex
	Path   string
	// Kind: claude, claude-plugin, cursor, gemini, windsurf, vscode-tasks, codex.
	Kind string
}

// ProjectHookFiles are the hook files a project directory can hold. A
// Claude Code plugin's hooks/hooks.json is included when dir holds a plugin
// manifest; exists is how to ask (os.Stat in a real tree).
func ProjectHookFiles(dir string, exists func(string) bool) []HookFile {
	files := []HookFile{
		{"Claude Code", filepath.Join(dir, ".claude", "settings.json"), "claude"},
		{"Claude Code", filepath.Join(dir, ".claude", "settings.local.json"), "claude"},
		{"Cursor", filepath.Join(dir, ".cursor", "hooks.json"), "cursor"},
		{"Gemini CLI", filepath.Join(dir, ".gemini", "settings.json"), "gemini"},
		{"Windsurf", filepath.Join(dir, ".windsurf", "hooks.json"), "windsurf"},
		{"VS Code", filepath.Join(dir, ".vscode", "tasks.json"), "vscode-tasks"},
	}
	// A Claude Code plugin's hooks run in every project that installs it.
	if exists != nil && exists(filepath.Join(dir, ".claude-plugin", "plugin.json")) {
		files = append(files, HookFile{"Claude Code plugin", filepath.Join(dir, "hooks", "hooks.json"), "claude-plugin"})
	}
	return files
}

// UserHookFiles are a user's own hook files under their home directory.
func UserHookFiles(home string) []HookFile {
	return []HookFile{
		{"Claude Code", filepath.Join(home, ".claude", "settings.json"), "claude"},
		{"Cursor", filepath.Join(home, ".cursor", "hooks.json"), "cursor"},
		{"Gemini CLI", filepath.Join(home, ".gemini", "settings.json"), "gemini"},
		{"Windsurf", filepath.Join(home, ".codeium", "windsurf", "hooks.json"), "windsurf"},
		{"Codex", filepath.Join(home, ".codex", "config.toml"), "codex"},
	}
}

// HookCommand is one command a file makes run automatically.
type HookCommand struct {
	Event   string // PreToolUse, statusLine, a task's label, notify
	Command string
	Noun    string // how to name it: "PreToolUse hook", "statusLine command", "task build"
}

// claudeCommandSettings are Claude Code settings, besides hooks, whose value
// is a command Claude Code runs without asking.
var claudeCommandSettings = []string{"apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper"}

// ReadHookCommands returns the commands a hook file runs automatically.
func ReadHookCommands(hf HookFile, data []byte) ([]HookCommand, error) {
	if hf.Kind == "codex" {
		var doc struct {
			Notify []string `toml:"notify"`
		}
		if _, err := toml.Decode(string(data), &doc); err != nil {
			return nil, err
		}
		if len(doc.Notify) == 0 {
			return nil, nil
		}
		return []HookCommand{{"notify", ShellJoin(doc.Notify), "notify command"}}, nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(StripJSONC(data), &doc); err != nil {
		return nil, err
	}
	if hf.Kind == "vscode-tasks" {
		return folderOpenTasks(doc["tasks"]), nil
	}
	var out []HookCommand
	var events map[string]json.RawMessage
	if json.Unmarshal(doc["hooks"], &events) == nil {
		for event, raw := range events {
			var v any
			if json.Unmarshal(raw, &v) == nil {
				for _, c := range commandsIn(v) {
					out = append(out, HookCommand{event, c, event + " hook"})
				}
			}
		}
	}
	if hf.Kind == "claude" {
		var status struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(doc["statusLine"], &status) == nil && status.Command != "" {
			out = append(out, HookCommand{"statusLine", status.Command, "statusLine command"})
		}
		for _, k := range claudeCommandSettings {
			var c string
			if json.Unmarshal(doc[k], &c) == nil && c != "" {
				out = append(out, HookCommand{k, c, k + " command"})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Event < out[j].Event })
	return out, nil
}

// commandsIn collects every "command" string under v. Claude Code, Cursor,
// Gemini CLI and Windsurf nest their hooks differently (event → matchers
// → hooks, or event → hooks); each hook names its command "command".
func commandsIn(v any) []string {
	var out []string
	switch t := v.(type) {
	case map[string]any:
		if c, ok := t["command"].(string); ok && c != "" {
			out = append(out, c)
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k != "command" {
				out = append(out, commandsIn(t[k])...)
			}
		}
	case []any:
		for _, e := range t {
			out = append(out, commandsIn(e)...)
		}
	}
	return out
}

// folderOpenTasks are VS Code tasks set to run when the folder is opened
// (runOptions.runOn: folderOpen), with each platform's command.
func folderOpenTasks(raw json.RawMessage) []HookCommand {
	type command struct {
		Command string `json:"command"`
		Args    []any  `json:"args"`
	}
	var tasks []struct {
		command
		Label      string `json:"label"`
		RunOptions struct {
			RunOn string `json:"runOn"`
		} `json:"runOptions"`
		Windows *command `json:"windows"`
		OSX     *command `json:"osx"`
		Linux   *command `json:"linux"`
	}
	if json.Unmarshal(raw, &tasks) != nil {
		return nil
	}
	var out []HookCommand
	for _, t := range tasks {
		if t.RunOptions.RunOn != "folderOpen" {
			continue
		}
		label := "folderOpen task"
		if t.Label != "" {
			label += " " + strconv.Quote(t.Label)
		}
		for _, c := range []*command{&t.command, t.Windows, t.OSX, t.Linux} {
			if c == nil || c.Command == "" {
				continue
			}
			parts := []string{c.Command}
			for _, a := range c.Args {
				switch v := a.(type) {
				case string:
					parts = append(parts, v)
				case map[string]any:
					if s, ok := v["value"].(string); ok {
						parts = append(parts, s)
					}
				}
			}
			out = append(out, HookCommand{label, strings.Join(parts, " "), "task " + strconv.Quote(t.Label) + " (run when the folder opens)"})
		}
	}
	return out
}

// ShellJoin quotes args into one command line.
func ShellJoin(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = a
		if strings.ContainsAny(a, " \t\"'") {
			q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
	}
	return strings.Join(q, " ")
}

// MCPServer is an MCP server a client starts with a local command.
type MCPServer struct {
	Name    string
	Command string // the command and its arguments, joined
}

// MCPStartCommands reads the stdio MCP servers a client configuration
// starts: "mcpServers" (Claude Code, Cursor, Gemini CLI, Windsurf), "servers"
// (VS Code), and Claude Code's per-project "projects.*.mcpServers" in
// ~/.claude.json.
func MCPStartCommands(data []byte) ([]MCPServer, error) {
	type entry struct {
		Command string `json:"command"`
		Args    []any  `json:"args"`
	}
	var doc struct {
		MCPServers map[string]entry `json:"mcpServers"`
		Servers    map[string]entry `json:"servers"`
		Projects   map[string]struct {
			MCPServers map[string]entry `json:"mcpServers"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(StripJSONC(data), &doc); err != nil {
		return nil, err
	}
	var out []MCPServer
	add := func(m map[string]entry) {
		for name, e := range m {
			if e.Command == "" {
				continue
			}
			parts := []string{e.Command}
			for _, a := range e.Args {
				if s, ok := a.(string); ok {
					parts = append(parts, s)
				}
			}
			out = append(out, MCPServer{Name: name, Command: strings.Join(parts, " ")})
		}
	}
	add(doc.MCPServers)
	add(doc.Servers)
	for _, p := range doc.Projects {
		add(p.MCPServers)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
