package confcheck

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// What a command that runs remote code looks like. Each expression is run
// on one line of the command, lower-cased.
var (
	// A program that fetches from the network.
	fetchRE = `(?:\bcurl\b|\bwget\b|\biwr\b|\birm\b|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|downloaddata|net\.webclient|start-bitstransfer|certutil\b[^|;&]*-urlcache|bitsadmin\b[^|;&]*/transfer)`
	// What runs the text piped to it: a shell, or a script interpreter
	// reading its program from standard input ("| python3 -", not
	// "| python3 -m json.tool", which only reads data).
	interpRE = `(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\S+=\S*\s+)*)?(?:/usr/bin/|/bin/|/usr/local/bin/)?(?:(?:sh|bash|zsh|dash|ksh|fish|iex|invoke-expression|pwsh|powershell(?:\.exe)?|cmd(?:\.exe)?)\b|(?:python[0-9.]*|perl|ruby|node|php)(?:\s+-[a-z]?)*\s*(?:$|[;&|)]))`

	// curl … | sh, iwr … | iex
	pipeToShell = regexp.MustCompile(fetchRE + `.*\|\s*` + interpRE)
	// bash -c "$(curl …)", sh <(curl …), eval "$(wget -qO- …)", source <(curl …), python -c "$(curl …)"
	runSubstitution = regexp.MustCompile(`(?:\b(?:sh|bash|zsh|dash|ksh|eval|source|python[0-9.]*|perl|ruby|node|php)\b|(?:^|[;&|(]\s*)\.)\s+(?:-\S+\s+)*["']?(?:\$\(|<\(|` + "`" + `)\s*(?:sudo\s+)?` + fetchRE)
	// iex (iwr …), Invoke-Expression (New-Object Net.WebClient).DownloadString(…)
	psInvoke = regexp.MustCompile(`(?:\biex\b|invoke-expression)`)
	// python -c "…urlopen(…)…exec(…)", node -e "…fetch(…)…eval(…)"
	scriptFetch = regexp.MustCompile(`(?:urlopen|urlretrieve|requests\.get|httpx\.get|\bfetch\(|https?\.get\(|http\.request\()`)
	scriptExec  = regexp.MustCompile(`(?:\bexec\(|\beval\(|new function\(|child_process|subprocess|os\.system)`)
	// base64 -d …, [Convert]::FromBase64String(…), b64decode(…), atob(…)
	decodeRE = regexp.MustCompile(`(?:base64\s+(?:-\S+\s+)*(?:-d\b|-D\b|--decode\b)|\bb64decode\(|frombase64string|\batob\(|\bopenssl\s+(?:enc\s+)?(?:-\S+\s+)*-d\b[^|;&]*-base64|xxd\s+-r)`)
	execRE   = regexp.MustCompile(`(?:\|\s*` + interpRE + `|\beval\b|\bexec\(|\biex\b|invoke-expression)`)
	// pwsh -EncodedCommand <base64>
	psEncoded = regexp.MustCompile(`(?:pwsh|powershell)(?:\.exe)?\b.*\s-e(?:nc(?:odedcommand)?|c)?\s+[a-z0-9+/=]{16,}`)
	// curl -o /tmp/x …; chmod +x /tmp/x; /tmp/x
	fetchToFile = regexp.MustCompile(fetchRE + `[^|;&]*(?:\s-[a-z]*o(?:\s+|=)?[^\s-]|\s--output[\s=]|\s>\s*\S|-outfile\b|downloadfile)`)
	makeExec    = regexp.MustCompile(`(?:\bchmod\s+(?:-\S+\s+)*(?:[ugoa]*\+[rw]*x|0?[0-7]?[1357][0-7]{2}|0?[0-7]{2}[1357])\b|start-process\b|(?:&&|;)\s*(?:/tmp/|/var/tmp/|/dev/shm/|\$tmpdir|%temp%))`)
	fetchAny    = regexp.MustCompile(fetchRE)

	urlHost = regexp.MustCompile(`(?i)\bhttps?://([^/\s"'$` + "`" + `)|;&\\]+)`)
)

// RemoteExec reports why a command fetches code from the network and runs
// it, or "" when it does not. Each line is checked on its own, with
// backslash-continued lines joined.
func RemoteExec(command string) string {
	for _, line := range commandLines(command) {
		l := strings.ToLower(line)
		if why := remoteExecLine(l); why != "" {
			return why + from(line)
		}
	}
	return ""
}

func remoteExecLine(l string) string {
	switch {
	case pipeToShell.MatchString(l):
		return "downloads code and pipes it to a shell"
	case runSubstitution.MatchString(l):
		return "downloads code and runs it"
	case psInvoke.MatchString(l) && fetchAny.MatchString(l):
		return "downloads a PowerShell script and runs it (Invoke-Expression)"
	case psEncoded.MatchString(l):
		return "runs an encoded PowerShell command, hiding what it does"
	case decodeRE.MatchString(l) && execRE.MatchString(l):
		return "decodes hidden (base64) content and runs it"
	case scriptFetch.MatchString(l) && scriptExec.MatchString(l):
		return "downloads code from a script and runs it"
	case fetchToFile.MatchString(l) && makeExec.MatchString(l[fetchToFile.FindStringIndex(l)[0]:]):
		return "downloads a program and makes it executable or runs it"
	}
	return ""
}

func from(line string) string {
	if m := urlHost.FindStringSubmatch(line); m != nil {
		return " from " + stripUserinfo(m[1])
	}
	return ""
}

// stripUserinfo drops user:password@ from a URL's host part.
func stripUserinfo(h string) string {
	if i := strings.LastIndexByte(h, '@'); i >= 0 {
		return h[i+1:]
	}
	return h
}

// commandLines splits a command or a script into logical lines.
func commandLines(s string) []string {
	var out []string
	var cur strings.Builder
	for _, ln := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.HasSuffix(ln, "\\") {
			cur.WriteString(strings.TrimSuffix(ln, "\\") + " ")
			continue
		}
		cur.WriteString(ln)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// scriptExt are files a hook command may run that are read for the same
// patterns: an attacker can keep the settings file tidy and put the
// download in the script it calls.
var scriptExt = map[string]bool{".sh": true, ".bash": true, ".zsh": true, ".ps1": true, ".py": true, ".js": true, ".mjs": true, ".cjs": true, ".rb": true, ".pl": true, ".cmd": true, ".bat": true}

// projectVars are how hook commands name the project directory.
var projectVars = []string{"${CLAUDE_PROJECT_DIR}", "$CLAUDE_PROJECT_DIR", "${CLAUDE_PLUGIN_ROOT}", "$CLAUDE_PLUGIN_ROOT", "${workspaceFolder}", "$GEMINI_PROJECT_DIR", "${GEMINI_PROJECT_DIR}"}

// commandTokens splits a command into words with quotes and shell
// punctuation around them removed.
func commandTokens(command string) []string {
	var out []string
	for _, tok := range strings.Fields(command) {
		tok = strings.Trim(strings.NewReplacer(`"`, "", `'`, "").Replace(tok), ";&|()")
		if tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

// ScriptsIn returns the project files a command runs, relative to root,
// that exist and stay inside it.
func ScriptsIn(command, root string) []string {
	if root == "" {
		return nil
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, tok := range commandTokens(command) {
		for _, v := range projectVars {
			if strings.HasPrefix(tok, v+"/") {
				tok = "." + strings.TrimPrefix(tok, v)
			}
		}
		if !scriptExt[strings.ToLower(filepath.Ext(tok))] || filepath.IsAbs(tok) || strings.HasPrefix(tok, "~") || strings.Contains(tok, "$") {
			continue
		}
		rel := filepath.Clean(filepath.FromSlash(tok))
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || seen[rel] {
			continue
		}
		real, err := filepath.EvalSymlinks(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		if r, err := filepath.Rel(realRoot, real); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			continue // a link out of the project
		}
		seen[rel] = true
		out = append(out, filepath.ToSlash(rel))
	}
	return out
}

// ReadBounded reads at most MaxHookFile bytes of p; truncated says there
// was more.
func ReadBounded(p string) (data []byte, truncated bool, err error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && !st.Mode().IsRegular() {
		return nil, false, os.ErrInvalid // a FIFO or a device would block or never end
	}
	data, err = io.ReadAll(io.LimitReader(f, MaxHookFile+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > MaxHookFile {
		return data[:MaxHookFile], true, nil
	}
	return data, false, nil
}

// LineOf is the line of the file on which command is written, or 0.
func LineOf(data []byte, command string) int {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(command)
	quoted := bytes.TrimSuffix(b.Bytes(), []byte("\n"))
	needles := [][]byte{quoted[1 : len(quoted)-1], []byte(command)}
	if first := strings.SplitN(command, "\n", 2)[0]; len(first) >= 12 {
		needles = append(needles, []byte(first))
	}
	for _, n := range needles {
		if len(n) == 0 {
			continue
		}
		if i := bytes.Index(data, n); i >= 0 {
			return 1 + bytes.Count(data[:i], []byte{'\n'})
		}
	}
	return 0
}

// ScriptRemoteExec reads a script a hook runs and returns the first line
// that fetches code and runs it, with why.
func ScriptRemoteExec(p string) (int, string) {
	script, truncated, err := ReadBounded(p)
	if err != nil || truncated {
		return 0, ""
	}
	sc := bufio.NewScanner(bytes.NewReader(script))
	sc.Buffer(make([]byte, 64<<10), MaxHookFile)
	n, start := 0, 0
	var joined strings.Builder
	for sc.Scan() {
		n++
		ln := sc.Text()
		if joined.Len() == 0 {
			start = n
		}
		if strings.HasSuffix(ln, "\\") {
			joined.WriteString(strings.TrimSuffix(ln, "\\") + " ")
			continue
		}
		joined.WriteString(ln)
		full := joined.String()
		joined.Reset()
		if strings.HasPrefix(strings.TrimSpace(full), "#") {
			continue
		}
		if why := remoteExecLine(strings.ToLower(full)); why != "" {
			return start, why + from(full)
		}
	}
	return 0, ""
}

// RedactCommand masks values that look like credentials in a listed
// command (a token in a URL or a header) and bounds its length.
func RedactCommand(c string) string {
	c = credInURL.ReplaceAllString(c, "${1}***@")
	c = authHeader.ReplaceAllString(c, "${1}***")
	if len(c) > 300 {
		c = c[:300] + "…"
	}
	return c
}

var (
	credInURL  = regexp.MustCompile(`(https?://|ssh://|git\+ssh://)[^/\s:@]+:[^/\s@]+@`)
	authHeader = regexp.MustCompile(`(?i)((?:authorization|x-api-key|api-key|private-token)\s*:\s*(?:bearer\s+|token\s+)?)\S+`)
)

// StripJSONC removes // and /* */ comments and trailing commas (VS Code's
// settings are JSON with comments).
func StripJSONC(b []byte) []byte {
	return stripJSONC(stripJSONC(b, true), false)
}

// stripJSONC removes comments (comments true) or trailing commas.
func stripJSONC(b []byte, comments bool) []byte {
	var out bytes.Buffer
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out.WriteByte(c)
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
		switch {
		case c == '"':
			inStr = true
			out.WriteByte(c)
		case comments && c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out.WriteByte('\n')
		case comments && c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
		case !comments && c == ',':
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\n' || b[j] == '\r' || b[j] == '\t') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue
			}
			out.WriteByte(c)
		default:
			out.WriteByte(c)
		}
	}
	return out.Bytes()
}
