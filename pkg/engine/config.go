package engine

import (
	"context"
	"os"

	"github.com/stackurity/stackurity/internal/client"
	"github.com/stackurity/stackurity/internal/collect/confcheck"
	"github.com/stackurity/stackurity/internal/model"
)

// Config checks (internal/collect/confcheck): risky settings in AI
// coding-agent hooks, MCP start commands and GitHub Actions workflows. The
// standalone scanner uses these so its rules and the agent's are one.

// Config finding types.
type (
	ConfigFinding = model.ConfigFinding
	ConfigScan    = model.ConfigScan
	// HookFile is a file that holds an agent's or editor's hooks.
	HookFile = confcheck.HookFile
	// HookCommand is one command a hook file runs on its own.
	HookCommand = confcheck.HookCommand
	// HookRisk is a risky command: rule, severity, file and line, why and fix.
	HookRisk = confcheck.Risk
	// MCPServer is an MCP server a client starts with a local command.
	MCPServer = confcheck.MCPServer
)

// Config rules for agent hooks and MCP start commands.
const (
	RuleHookRemoteExec = confcheck.RuleHookRemoteExec
	RuleMCPRemoteExec  = confcheck.RuleMCPRemoteExec
	RuleHookGitTree    = confcheck.RuleHookGitTree
)

// MaxHookFile bounds a hook file or a script a hook runs.
const MaxHookFile = confcheck.MaxHookFile

// ProjectHookFiles are the hook files a project directory can hold.
func ProjectHookFiles(dir string) []HookFile {
	return confcheck.ProjectHookFiles(dir, func(p string) bool { _, err := os.Stat(p); return err == nil })
}

// UserHookFiles are a user's own hook files under their home directory.
func UserHookFiles(home string) []HookFile { return confcheck.UserHookFiles(home) }

// ReadHookCommands returns the commands a hook file runs automatically.
func ReadHookCommands(hf HookFile, data []byte) ([]HookCommand, error) {
	return confcheck.ReadHookCommands(hf, data)
}

// CheckHook grades one hook command: high when it, or a script in the
// project (root; "" for a user's own settings) that it runs, downloads code
// and runs it. display names the hook file; data is its content.
func CheckHook(client, display string, data []byte, c HookCommand, root string) (HookRisk, bool) {
	return confcheck.HookRisk(client, display, data, c, root)
}

// CheckMCPStart grades an MCP server's start command.
func CheckMCPStart(command string) (HookRisk, bool) { return confcheck.MCPRisk(command) }

// MCPStartCommands reads the stdio MCP servers a client configuration starts.
func MCPStartCommands(data []byte) ([]MCPServer, error) { return confcheck.MCPStartCommands(data) }

// RemoteExec says why a command downloads code and runs it, or "".
func RemoteExec(command string) string { return confcheck.RemoteExec(command) }

// RedactCommand masks credentials in a command and bounds its length.
func RedactCommand(c string) string { return confcheck.RedactCommand(c) }

// StripJSONC removes comments and trailing commas from JSON with comments.
func StripJSONC(b []byte) []byte { return confcheck.StripJSONC(b) }

// ReadHookFile reads at most MaxHookFile bytes of a file; truncated says
// there was more.
func ReadHookFile(p string) (data []byte, truncated bool, err error) { return confcheck.ReadBounded(p) }

// RepoConfig runs the repository config checks on the checkout at dir:
// GitHub Actions workflows and agent hooks or MCP servers checked in.
// Paths are relative to dir.
func RepoConfig(ctx context.Context, dir string) *ConfigScan { return confcheck.Repo(ctx, dir) }

// WorkflowFindings checks one GitHub Actions workflow file; rel names it.
func WorkflowFindings(rel string, data []byte) ([]ConfigFinding, error) {
	return confcheck.WorkflowFindings(rel, data)
}

// ConfigRuleDoc is a page that explains a config rule, or "".
func ConfigRuleDoc(rule string) string { return confcheck.RuleDoc(rule) }

// RepoWorkflows checks only the GitHub Actions workflows of the checkout at
// dir. problems names the files that could not be read.
func RepoWorkflows(dir string) (found []ConfigFinding, problems []string) {
	return confcheck.Workflows(dir)
}

// FeatureConfigFindings is the server feature (GET /meta) that says it
// stores a batch's config findings. Send Batch.ConfigFindings only to a
// server that lists it: older ones refuse the field.
const FeatureConfigFindings = client.FeatureConfigFindings

// ServerHas reports whether a Stackurity server lists a feature in GET /meta.
func ServerHas(ctx context.Context, server, token, toolVersion, feature string) (bool, error) {
	cl, err := client.New(server, token, toolVersion)
	if err != nil {
		return false, err
	}
	m, err := cl.Meta(ctx)
	if err != nil {
		return false, err
	}
	return m.Has(feature), nil
}
