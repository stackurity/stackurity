package confcheck

import (
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/stackurity/stackurity/internal/model"
)

// maxProjectDirs bounds the directories under one home that are read as
// projects (each holds a few small files at most).
const maxProjectDirs = 200

// maxClaudeJSON bounds ~/.claude.json, which also keeps a history.
const maxClaudeJSON = 8 << 20

// hookScan collects the findings of one host's agent hook files.
type hookScan struct {
	h    *hostFS
	out  []model.ConfigFinding
	seen map[string]bool // files read
}

// hostHooks reads the AI agent hook and MCP files of each account's home,
// of the projects directly under it, and of the given application
// directories.
func (h *hostFS) hostHooks(accounts []account, appDirs []string) []model.ConfigFinding {
	s := &hookScan{h: h, seen: map[string]bool{}}
	for _, a := range accounts {
		for _, hf := range UserHookFiles(a.Home) {
			s.file(hf, a.Home, "")
		}
		for _, p := range []string{path.Join(a.Home, ".claude.json"), path.Join(a.Home, ".cursor", "mcp.json"),
			path.Join(a.Home, ".gemini", "settings.json"), path.Join(a.Home, ".codeium", "windsurf", "mcp_config.json")} {
			s.mcp(p)
		}
		// Projects kept in the home directory: /root/infra, /home/deploy/app.
		// A home directory that is itself a project has its .claude/ read
		// above; its settings.local.json and other clients' files here.
		s.project(a.Home, a.Home)
		entries := h.readDir(a.Home)
		n := 0
		for _, e := range entries {
			if n >= maxProjectDirs {
				h.problem(a.Home, "has more than 200 directories; the first were checked")
				break
			}
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			n++
			s.project(path.Join(a.Home, e.Name()), a.Home)
		}
	}
	for _, d := range appDirs {
		s.project(path.Clean("/"+d), "")
	}
	return s.out
}

// project reads one project directory's hook and MCP files.
func (s *hookScan) project(dir, home string) {
	for _, hf := range ProjectHookFiles(dir, s.h.exists) {
		s.file(hf, home, dir)
	}
	for _, p := range []string{path.Join(dir, ".mcp.json"), path.Join(dir, ".cursor", "mcp.json"), path.Join(dir, ".vscode", "mcp.json")} {
		s.mcp(p)
	}
}

// file reads one hook file and adds a finding for each risky command.
// proj is the project directory it belongs to, "" for a user's own file.
func (s *hookScan) file(hf HookFile, home, proj string) {
	p := filepath.ToSlash(hf.Path)
	if s.seen[p] {
		return
	}
	s.seen[p] = true
	data, err := s.h.read(p, MaxHookFile)
	if err != nil || data == nil {
		return
	}
	hf.Path = p
	cmds, err := ReadHookCommands(hf, data)
	if err != nil {
		return // not valid JSON: the agent does not run it either
	}
	for _, c := range cmds {
		subject := c.Event + ": " + RedactCommand(c.Command)
		if r, ok := s.risk(hf, data, c, home, proj); ok {
			title := hf.Client + " hook downloads and runs code"
			if r.Rule == RuleHookGitTree {
				title = hf.Client + " hook runs a script from another repository's checkout"
			}
			s.out = append(s.out, finding(r.Rule, model.ConfigAgentHook, title, r.Severity, r.File, r.Line, subject, r.Why, r.Fix))
		}
	}
}

// risk grades one hook command on a host: what HookRisk reports, then
// scripts the command runs by an absolute or home path, then scripts that
// sit in a Git checkout of another repository.
func (s *hookScan) risk(hf HookFile, data []byte, c HookCommand, home, proj string) (Risk, bool) {
	consequence := hf.Client + " runs it without asking, so whoever controls that address runs code on this server."
	if r, ok := HookRisk(hf.Client, hf.Path, data, c, s.h.fullOrEmpty(proj)); ok {
		if r.File != hf.Path {
			r.File = path.Join(proj, r.File) // a project script, named from the host's root
		}
		return r, true
	}
	scripts := s.h.scriptsOf(c.Command, home, proj)
	for _, sp := range scripts {
		if !s.h.isScript(sp) {
			continue
		}
		real, err := s.h.resolve(sp)
		if err != nil {
			continue
		}
		if line, why := ScriptRemoteExec(real); why != "" {
			return Risk{Severity: "high", Rule: RuleHookRemoteExec, File: sp, Line: line,
				Why: c.Noun + " in " + hf.Path + " runs " + sp + ", which " + why + ". " + consequence,
				Fix: "Remove it, or pin and review what it downloads."}, true
		}
	}
	own := s.h.gitTree(hf.Path)
	for _, sp := range scripts {
		tree := s.h.gitTree(sp)
		if tree == "" || tree == own {
			continue // not in a checkout, or in the project's own repository
		}
		remotes := s.h.gitRemotes(tree)
		if len(remotes) == 0 {
			continue // a local repository: nobody else can push to it
		}
		return Risk{Severity: "medium", Rule: RuleHookGitTree, File: hf.Path, Line: LineOf(data, c.Command),
			Why: c.Noun + " runs " + sp + ", which is in a Git checkout of " + remotes[0] + " (" + tree + "): whoever can push to that " +
				"repository changes what " + hf.Client + " runs on this server the next time the checkout is updated.",
			Fix: "Copy the script out of the checkout to a root-owned path (for example /usr/local/lib/agent-hooks/) and review " +
				"changes before copying them, or pin the checkout to a reviewed commit."}, true
	}
	return Risk{}, false
}

// fullOrEmpty is where project directory p is on this machine, resolved
// (and inside a mounted root), or "" for none.
func (h *hostFS) fullOrEmpty(p string) string {
	if p == "" {
		return ""
	}
	real, err := h.resolve(p)
	if err != nil {
		return ""
	}
	return real
}

// readDir lists a host directory; nothing when it is not a directory
// (opening a FIFO would block) or leads out of a mounted root.
func (h *hostFS) readDir(p string) []os.DirEntry {
	real, err := h.resolve(p)
	if err != nil {
		return nil
	}
	if st, err := os.Lstat(real); err != nil || !st.IsDir() {
		return nil
	}
	entries, _ := os.ReadDir(real)
	return entries
}

// scriptsOf returns the host files a command runs that exist: absolute
// paths, paths under the home directory (~/x, $HOME/x) and, in a project,
// paths relative to it or named through its variable
// ($CLAUDE_PROJECT_DIR/x).
func (h *hostFS) scriptsOf(command, home, proj string) []string {
	seen := map[string]bool{}
	var out []string
	for _, tok := range commandTokens(command) {
		p := ""
		switch {
		case strings.HasPrefix(tok, "~/") && home != "":
			p = path.Join(home, tok[2:])
		case strings.HasPrefix(tok, "$HOME/") && home != "":
			p = path.Join(home, tok[len("$HOME/"):])
		case strings.HasPrefix(tok, "${HOME}/") && home != "":
			p = path.Join(home, tok[len("${HOME}/"):])
		case strings.HasPrefix(tok, "/"):
			p = path.Clean(tok)
		default:
			for _, v := range projectVars {
				if rest, ok := strings.CutPrefix(tok, v+"/"); ok && proj != "" {
					p = path.Join(proj, rest)
				}
			}
			if p == "" && proj != "" && !strings.Contains(tok, "$") && scriptExt[strings.ToLower(path.Ext(tok))] {
				p = path.Join(proj, tok)
			}
		}
		if p == "" || seen[p] || strings.HasPrefix(p, "/dev/") || strings.HasPrefix(p, "/proc/") {
			continue
		}
		if _, ok := h.regular(p); !ok {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// isScript reports whether a host file is read for downloads: a known
// script extension, or a file that starts with #!.
func (h *hostFS) isScript(p string) bool {
	if scriptExt[strings.ToLower(path.Ext(p))] {
		return true
	}
	f, err := h.open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, 2)
	n, _ := f.Read(b)
	return n == 2 && string(b) == "#!"
}

// mcp reads one MCP client configuration and adds a finding for each
// server whose start command downloads and runs code.
func (s *hookScan) mcp(p string) {
	if s.seen["mcp:"+p] {
		return
	}
	s.seen["mcp:"+p] = true
	limit := int64(MaxHookFile)
	if path.Base(p) == ".claude.json" {
		limit = maxClaudeJSON
	}
	data, err := s.h.read(p, limit)
	if err != nil || data == nil {
		return
	}
	servers, err := MCPStartCommands(data)
	if err != nil {
		return
	}
	for _, sv := range servers {
		if r, ok := MCPRisk(sv.Command); ok {
			why := "MCP server " + sv.Name + ": " + r.Why + "."
			s.out = append(s.out, finding(r.Rule, model.ConfigAgentHook, "MCP server start command downloads and runs code", r.Severity,
				p, LineOf(data, sv.Name), "mcp "+sv.Name+": "+RedactCommand(sv.Command), why, r.Fix))
		}
	}
}
