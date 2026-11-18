// Package assistantcfg finds risky settings in AI coding assistants'
// configuration files: a Claude Code hook that downloads and runs a script
// when a session starts, an MCP server installed from a Git repository, a
// VS Code task that runs as soon as the folder is opened, a setting that
// sends the assistant's requests to another host.
//
// These files are committed with the code. Whoever can change the
// repository decides what runs on the machine of every developer who opens
// it with the assistant, with that developer's access. Attackers have used
// exactly this to install backdoors (GTIG AI Threat Tracker, November 2026:
// a modified .claude/settings.json downloaded a backdoor whenever Claude
// Code started).
//
// The files are parsed as data and nothing in them is run. Keys and
// passwords in a reported command are masked before it leaves the package.
package assistantcfg

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/stackurity/stackurity/internal/collect/leaks"
	"github.com/stackurity/stackurity/internal/model"
)

// Finding is one risky setting.
type Finding = model.AssistantFinding

// Rules: what a finding is, and its severity on its own.
const (
	RuleRemoteCode   = "remote-code"
	RuleNetwork      = "network"
	RuleMCPFromURL   = "mcp-from-url"
	RuleAPIRedirect  = "api-redirect"
	RuleMCPUnpinned  = "mcp-unpinned"
	RuleAutoApprove  = "auto-approve"
	RuleAutoTask     = "auto-task"
	critical, high   = "critical", "high"
	medium, low      = "medium", "low"
	allowMarker      = "stackurity:allow"
	maxFindingsPerFS = 50
)

var titles = map[string]string{
	RuleRemoteCode:  "Downloads and runs code",
	RuleNetwork:     "Contacts a server on the internet",
	RuleMCPFromURL:  "MCP server installed from a Git repository or URL",
	RuleAPIRedirect: "Sends the assistant's requests to another host",
	RuleMCPUnpinned: "MCP server package not pinned to a version",
	RuleAutoApprove: "Runs tools or MCP servers without asking",
	RuleAutoTask:    "Task runs when the folder is opened",
}

var severities = map[string]string{
	RuleRemoteCode: critical, RuleNetwork: medium, RuleMCPFromURL: high, RuleAPIRedirect: medium,
	RuleMCPUnpinned: low, RuleAutoApprove: low, RuleAutoTask: low,
}

// Title is a rule's title, for a finding shown without one.
func Title(rule string) string { return titles[rule] }

// format is how a file is laid out.
type format int

const (
	claudeSettings format = iota // .claude/settings.json: hooks, statusLine, helpers, env, permissions
	mcpConfig                    // {"mcpServers": {...}}: .mcp.json, .cursor/mcp.json, .gemini/settings.json
	vscodeMCP                    // .vscode/mcp.json: {"servers": {...}}
	vscodeTasks                  // .vscode/tasks.json: tasks that run on folderOpen
	cursorHooks                  // .cursor/hooks.json: {"hooks": {"event": [{"command": ...}]}}
)

// known are the files read, by their last two path elements (or the name
// alone for a file at any level), and the assistant that reads them.
var known = []struct {
	suffix string
	tool   string
	format format
}{
	{".claude/settings.json", "claude-code", claudeSettings},
	{".claude/settings.local.json", "claude-code", claudeSettings},
	{".mcp.json", "mcp", mcpConfig},
	{".cursor/mcp.json", "cursor", mcpConfig},
	{".cursor/hooks.json", "cursor", cursorHooks},
	{".gemini/settings.json", "gemini-cli", mcpConfig},
	{".amazonq/mcp.json", "amazon-q", mcpConfig},
	{".roo/mcp.json", "roo-code", mcpConfig},
	{".vscode/mcp.json", "vscode", vscodeMCP},
	{".vscode/tasks.json", "vscode", vscodeTasks},
}

// Known reports whether rel (forward slashes) is a file the package reads,
// and which assistant reads it.
func Known(rel string) (tool string, ok bool) {
	_, tool, ok = kind(rel)
	return tool, ok
}

func kind(rel string) (format, string, bool) {
	rel = "/" + strings.TrimPrefix(rel, "/")
	for _, k := range known {
		if strings.HasSuffix(rel, "/"+k.suffix) {
			return k.format, k.tool, true
		}
	}
	return 0, "", false
}

// Scan reports the risky settings in one file's contents. name is the
// file's path (forward slashes), recorded as given; a name the package
// does not read gives nothing. A file that is not valid JSON (with
// comments, as VS Code allows) is an error: it was not checked.
func Scan(name string, data []byte) ([]Finding, error) {
	f, tool, ok := kind(name)
	if !ok {
		return nil, nil
	}
	clean := stripJSONC(data)
	if len(bytes.TrimSpace(clean)) == 0 {
		return nil, nil
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(clean))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", name, err)
	}
	s := &scanner{name: name, tool: tool, data: data, clean: clean, seen: map[string]bool{}}
	switch f {
	case claudeSettings:
		s.claude(doc)
	case mcpConfig:
		s.servers("mcpServers", obj(doc["mcpServers"]))
	case vscodeMCP:
		s.servers("servers", obj(doc["servers"]))
	case vscodeTasks:
		s.tasks(doc)
	case cursorHooks:
		s.hooks("hooks", obj(doc["hooks"]), false)
	}
	return s.out, nil
}

type scanner struct {
	name, tool  string
	data, clean []byte
	out         []Finding
	seen        map[string]bool
}

func (s *scanner) add(rule, setting, command, locate string) {
	if len(s.out) >= maxFindingsPerFS {
		return
	}
	command = Mask(command)
	sum := sha256.Sum256([]byte(rule + "\x00" + setting + "\x00" + command))
	fp := hex.EncodeToString(sum[:16])
	if s.seen[fp] {
		return
	}
	line := s.line(locate)
	if line > 0 && allowed(s.data, line) {
		return
	}
	s.seen[fp] = true
	s.out = append(s.out, Finding{Rule: rule, Title: titles[rule], Severity: severities[rule], Path: s.name, Line: line,
		Tool: s.tool, Setting: setting, Command: command, Fingerprint: fp})
}

// claude reads Claude Code's settings: hooks run on their own at the
// events they name; statusLine on every prompt; the helpers whenever
// credentials are needed.
func (s *scanner) claude(doc map[string]any) {
	s.hooks("hooks", obj(doc["hooks"]), true)
	if sl := obj(doc["statusLine"]); sl != nil {
		if c := str(sl["command"]); c != "" {
			s.command("statusLine", c)
		}
	}
	for _, k := range []string{"apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper"} {
		if c := str(doc[k]); c != "" {
			s.command(k, c)
		}
	}
	env := obj(doc["env"])
	for _, k := range sortedKeys(env) {
		if v := str(env[k]); v != "" && redirectEnv[k] != "" {
			if host, ok := foreignHost(v, redirectEnv[k]); ok {
				s.add(RuleAPIRedirect, "env."+k, host, quote(v))
			}
		}
	}
	if b, _ := doc["enableAllProjectMcpServers"].(bool); b {
		s.add(RuleAutoApprove, "enableAllProjectMcpServers", "true", `"enableAllProjectMcpServers"`)
	}
	if p := obj(doc["permissions"]); p != nil && str(p["defaultMode"]) == "bypassPermissions" {
		s.add(RuleAutoApprove, "permissions.defaultMode", "bypassPermissions", `"bypassPermissions"`)
	}
	s.servers("mcpServers", obj(doc["mcpServers"]))
}

// hooks reads {"Event": [...]} where each entry is a command, or (Claude
// Code) a matcher with its own list of hooks.
func (s *scanner) hooks(prefix string, hooks map[string]any, nested bool) {
	for _, event := range sortedKeys(hooks) {
		for _, entry := range arr(hooks[event]) {
			e := obj(entry)
			if e == nil {
				continue
			}
			list := []any{e}
			if nested && e["hooks"] != nil {
				list = arr(e["hooks"])
			}
			for _, h := range list {
				if c := str(obj(h)["command"]); c != "" {
					s.command(prefix+"."+event, c)
				}
			}
		}
	}
}

// command classifies a command that runs on its own. Nothing is reported
// for a command that neither downloads nor runs downloaded code: a hook
// that formats the code is what hooks are for.
func (s *scanner) command(setting, command string) bool {
	if rule := classify(command); rule != "" {
		s.add(rule, setting, command, quote(command))
		return true
	}
	return false
}

// servers reads MCP server definitions. A server with a url is reached
// over the network and runs nothing locally; one with a command runs it
// whenever the client starts the server.
func (s *scanner) servers(prefix string, servers map[string]any) {
	for _, name := range sortedKeys(servers) {
		srv := obj(servers[name])
		c := str(srv["command"])
		if c == "" {
			continue
		}
		args := []string{c}
		for _, a := range arr(srv["args"]) {
			if v := str(a); v != "" {
				args = append(args, v)
			}
		}
		line := strings.Join(args, " ")
		setting := prefix + "." + name
		locate := quote(name)
		if rule := classify(line); rule == RuleRemoteCode {
			s.add(rule, setting, line, locate)
			continue
		}
		switch src := packageSource(args); src {
		case srcURL:
			s.add(RuleMCPFromURL, setting, line, locate)
		case srcUnpinned:
			s.add(RuleMCPUnpinned, setting, line, locate)
		}
	}
}

// tasks reads VS Code tasks. Only a task that runs when the folder is
// opened (runOptions.runOn folderOpen) runs without anyone choosing to.
func (s *scanner) tasks(doc map[string]any) {
	for i, t := range arr(doc["tasks"]) {
		task := obj(t)
		if task == nil || str(obj(task["runOptions"])["runOn"]) != "folderOpen" {
			continue
		}
		label := str(task["label"])
		if label == "" {
			label = fmt.Sprint(i)
		}
		setting := "tasks." + label
		variants := []map[string]any{task}
		for _, osName := range []string{"windows", "linux", "osx"} {
			if v := obj(task[osName]); v != nil {
				variants = append(variants, v)
			}
		}
		reported := false
		for _, v := range variants {
			c := str(v["command"])
			if c == "" {
				continue
			}
			for _, a := range arr(v["args"]) {
				if as := str(a); as != "" {
					c += " " + as
				} else if ao := obj(a); ao != nil && str(ao["value"]) != "" {
					c += " " + str(ao["value"])
				}
			}
			if s.command(setting, c) {
				reported = true
			}
		}
		if !reported {
			c := str(task["command"])
			s.add(RuleAutoTask, setting, c, quote("folderOpen"))
		}
	}
}

// line is the line of the first occurrence of locate (JSON text), or 0.
func (s *scanner) line(locate string) int {
	if locate == "" {
		return 0
	}
	i := bytes.Index(s.clean, []byte(locate))
	if i < 0 {
		return 0
	}
	return 1 + bytes.Count(s.clean[:i], []byte{'\n'})
}

func allowed(data []byte, line int) bool {
	lines := bytes.SplitN(data, []byte{'\n'}, line+1)
	return line <= len(lines) && bytes.Contains(lines[line-1], []byte(allowMarker))
}

// quote is s as JSON writes it, to find it in the file.
func quote(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSpace(b.String())
}

// Commands that fetch something over the network.
var fetchRE = regexp.MustCompile(`(?i)(?:^|[\s;&|(` + "`" + `'"])(?:curl|wget|fetch|aria2c|iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer|bitsadmin)(?:\.exe)?(?:$|[\s;&|)'"])` +
	`|downloadstring|downloadfile|downloaddata|certutil(?:\.exe)?\s+[^|;&]*-urlcache|net\.webclient|/dev/tcp/`)

// What runs downloaded code: a pipe into an interpreter, a command
// substitution or process substitution of a fetch, PowerShell's
// Invoke-Expression, an encoded PowerShell command, a decoded payload run
// by a shell, or a downloaded file made executable or run.
var (
	pipeShellRE = regexp.MustCompile(`(?i)\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:/usr/bin/env\s+|/bin/|/usr/bin/)?(?:sh|bash|zsh|dash|ksh|fish|python[0-9.]*|perl|ruby|node|php|pwsh|powershell|iex|invoke-expression|source)(?:\.exe)?(?:$|[\s;&|)'"-])`)
	substRE     = regexp.MustCompile(`(?i)(?:\$\(|<\(|` + "`" + `)\s*(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b`)
	iexRE       = regexp.MustCompile(`(?i)\b(?:iex|invoke-expression)\b\s*[\(\$]|(?:downloadstring|downloaddata)\s*\(.*\|\s*iex\b|\biex\s*\(?\s*\(?\s*(?:new-object|iwr|irm|invoke-)`)
	encodedRE   = regexp.MustCompile(`(?i)\b(?:pwsh|powershell)(?:\.exe)?\b.*\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}`)
	decodeRE    = regexp.MustCompile(`(?i)(?:base64\s+(?:-d|--decode|-D)|openssl\s+(?:base64|enc)\s+[^|]*-d|xxd\s+-r)[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python[0-9.]*|perl|node)\b`)
	runAfterRE  = regexp.MustCompile(`(?i)(?:&&|;|\|\|)\s*(?:chmod\s+(?:[0-7]*[1357][0-7]*|[ugoa]*\+[rw]*x)|(?:sudo\s+)?(?:sh|bash|zsh|python[0-9.]*|node|perl)\s+\S|\./|\.\s+/|source\s+\S|start-process|msiexec|rundll32|regsvr32)`)
	mshtaRE     = regexp.MustCompile(`(?i)\b(?:mshta|regsvr32\s+/s\s+/n\s+/u\s+/i:)\s*https?://`)
)

// classify says what a command does that matters: run downloaded code
// (remote-code), reach the network (network), or nothing worth reporting.
func classify(command string) string {
	c := strings.Join(strings.Fields(command), " ")
	fetch := fetchRE.MatchString(c)
	switch {
	case substRE.MatchString(c), encodedRE.MatchString(c), decodeRE.MatchString(c), iexRE.MatchString(c), mshtaRE.MatchString(c):
		return RuleRemoteCode
	case fetch && (pipeShellRE.MatchString(c) || runAfterRE.MatchString(c)):
		return RuleRemoteCode
	case fetch:
		return RuleNetwork
	}
	return ""
}

// Where an MCP server's code comes from.
const (
	srcNone     = iota // a local program or path
	srcURL             // a Git repository, a URL or a tarball on the network
	srcUnpinned        // a registry package with no version, so whatever is newest
)

// launchers run a package fetched at start-up.
var launchers = map[string]bool{"npx": true, "bunx": true, "uvx": true, "pnpx": true}
var launcherSub = map[string]string{"pnpm": "dlx", "yarn": "dlx", "pipx": "run", "npm": "exec", "bun": "x", "uv": "tool run", "deno": "run"}

// packageSource says where the package an MCP server's command runs
// comes from.
func packageSource(args []string) int {
	if len(args) == 0 {
		return srcNone
	}
	prog := strings.TrimSuffix(path.Base(strings.ReplaceAll(args[0], `\`, "/")), ".cmd")
	prog = strings.TrimSuffix(prog, ".exe")
	rest := args[1:]
	switch {
	case launchers[prog]:
	case launcherSub[prog] != "":
		sub := strings.Fields(launcherSub[prog])
		if len(rest) < len(sub) || strings.Join(rest[:len(sub)], " ") != launcherSub[prog] {
			return srcNone
		}
		rest = rest[len(sub):]
	default:
		return srcNone
	}
	pkg := ""
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if a == "--" {
			if i+1 < len(rest) && pkg == "" {
				pkg = rest[i+1]
			}
			break
		}
		if a == "-p" || a == "--package" || a == "--from" || a == "--spec" {
			if i+1 < len(rest) {
				pkg = rest[i+1]
			}
			break
		}
		if v, ok := strings.CutPrefix(a, "--package="); ok {
			pkg = v
			break
		}
		if v, ok := strings.CutPrefix(a, "--from="); ok {
			pkg = v
			break
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		pkg = a
		break
	}
	if pkg == "" {
		return srcNone
	}
	low := strings.ToLower(pkg)
	for _, p := range []string{"http://", "https://", "git+", "git:", "github:", "gitlab:", "bitbucket:", "gist:", "ssh://", "jsr:http", "npm:http"} {
		if strings.HasPrefix(low, p) {
			return srcURL
		}
	}
	if strings.Contains(low, "://") {
		return srcURL
	}
	if strings.HasPrefix(pkg, ".") || strings.HasPrefix(pkg, "/") || strings.HasPrefix(pkg, "~") || strings.Contains(pkg, `\`) {
		return srcNone // a local path
	}
	if prog == "deno" {
		return srcNone // deno run of a local file; a URL is caught above
	}
	// npm reads user/repo as a GitHub repository.
	if (launchers[prog] && prog != "uvx") || prog == "pnpm" || prog == "yarn" || prog == "npm" || prog == "bun" {
		name := pkg
		if strings.HasPrefix(name, "@") {
			if i := strings.Index(name, "/"); i > 0 {
				name = name[i+1:]
			} else {
				return srcNone
			}
		} else if strings.Contains(name, "/") {
			return srcURL
		}
		at := strings.LastIndex(name, "@")
		if at <= 0 {
			return srcUnpinned
		}
		if v := name[at+1:]; v == "" || v == "latest" || v == "next" || strings.ContainsAny(v, "^~*xX><") {
			return srcUnpinned
		}
		return srcNone
	}
	// Python: pkg==1.2.3 or pkg@1.2.3 (uvx) is pinned.
	if strings.Contains(pkg, "==") || (strings.Contains(pkg, "@") && !strings.HasSuffix(pkg, "@latest")) {
		return srcNone
	}
	return srcUnpinned
}

// redirectEnv are settings that send an assistant's requests, with its API
// key, to a host; the value is the provider's own host suffix.
var redirectEnv = map[string]string{
	"ANTHROPIC_BASE_URL":         "anthropic.com",
	"ANTHROPIC_BEDROCK_BASE_URL": "amazonaws.com",
	"ANTHROPIC_VERTEX_BASE_URL":  "googleapis.com",
	"OPENAI_BASE_URL":            "openai.com",
	"OPENAI_API_BASE":            "openai.com",
	"HTTPS_PROXY":                "-",
	"HTTP_PROXY":                 "-",
}

// foreignHost reports the host a URL setting sends requests to when it is
// not the provider's own. A proxy setting ("-") always is.
func foreignHost(v, own string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || u.Host == "" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if own != "-" && (host == own || strings.HasSuffix(host, "."+own)) {
		return "", false
	}
	return host, true
}

// Masking: keys with their own format (the leaks rules), a URL's password,
// and values after a credential's name.
var (
	userinfoRE = regexp.MustCompile(`(://[^/:@\s'"]+:)[^@\s/'"]+@`)
	bearerRE   = regexp.MustCompile(`(?i)((?:authorization|x-api-key|api-key|private-token)\s*[:=]\s*(?:bearer\s+|token\s+|basic\s+)?)[^\s'"]+`)
	paramRE    = regexp.MustCompile(`(?i)((?:[a-z0-9_-]*(?:token|secret|passw(?:or)?d|api[_-]?key|access[_-]?key|auth))\s*[=:]\s*)[^\s&'";]+`)
	bareRE     = regexp.MustCompile(`(?i)(\b(?:bearer|token)\s+)[A-Za-z0-9._~+/=-]{16,}`)
)

// Mask returns command with keys and passwords replaced by ****, cut to
// model.MaxAssistantCommand bytes and on one line.
func Mask(command string) string {
	var values []string
	leaks.ScanValues("command.env", []byte(command), func(_ leaks.Leak, v string) { values = append(values, v) })
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	for _, v := range values {
		command = strings.ReplaceAll(command, v, "****")
	}
	command = userinfoRE.ReplaceAllString(command, "${1}****@")
	command = bearerRE.ReplaceAllString(command, "${1}****")
	command = paramRE.ReplaceAllStringFunc(command, func(m string) string {
		sub := paramRE.FindStringSubmatch(m)
		if strings.HasPrefix(m[len(sub[1]):], "$") || m[len(sub[1]):] == "****" {
			return m // a variable, not the value
		}
		return sub[1] + "****"
	})
	command = bareRE.ReplaceAllString(command, "${1}****")
	command = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, command)
	command = strings.TrimSpace(command)
	if len(command) > model.MaxAssistantCommand {
		cut := model.MaxAssistantCommand - len("…")
		for cut > 0 && !utf8.RuneStart(command[cut]) {
			cut--
		}
		command = command[:cut] + "…"
	}
	return command
}

// stripJSONC blanks comments, then trailing commas, outside strings,
// keeping every newline so line numbers stay right. Plain JSON is
// unchanged.
func stripJSONC(data []byte) []byte {
	out := bytes.Clone(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
	walk(out, func(i int) int {
		switch {
		case out[i] == '/' && i+1 < len(out) && out[i+1] == '/':
			for ; i < len(out) && out[i] != '\n'; i++ {
				out[i] = ' '
			}
			return i
		case out[i] == '/' && i+1 < len(out) && out[i+1] == '*':
			out[i], out[i+1] = ' ', ' '
			for i += 2; i < len(out); i++ {
				if out[i] == '*' && i+1 < len(out) && out[i+1] == '/' {
					out[i], out[i+1] = ' ', ' '
					return i + 1
				}
				if out[i] != '\n' {
					out[i] = ' '
				}
			}
			return i
		}
		return i
	})
	walk(out, func(i int) int {
		if out[i] == ',' {
			j := i + 1
			for j < len(out) && (out[j] == ' ' || out[j] == '\t' || out[j] == '\n' || out[j] == '\r') {
				j++
			}
			if j < len(out) && (out[j] == '}' || out[j] == ']') {
				out[i] = ' '
			}
		}
		return i
	})
	return out
}

// walk calls f at each byte outside a JSON string; f returns the index it
// read up to.
func walk(b []byte, f func(i int) int) {
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			continue
		}
		i = f(i)
	}
}

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func arr(v any) []any          { a, _ := v.([]any); return a }
func str(v any) string         { s, _ := v.(string); return s }

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
