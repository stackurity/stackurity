package confcheck

import (
	"bytes"
	"debug/buildinfo"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/stackurity/stackurity/internal/model"
)

// Attack tools: offensive frameworks that attackers run from servers they
// rent or have taken over. Unlike a vulnerability there is nothing to
// patch; finding one on a monitored server, image or repository means
// either someone is attacking from it (a compromise) or someone installed
// it without the security team knowing. Every match is high.
//
// Only strong signals are used, so a finding needs no second look to be
// worth one: the Go module a binary was built from (recorded by the Go
// toolchain, read as data, never run), a repository's go.mod, and the
// names of container images reported to carry a backdoor. A file that is
// merely named like the tool is not enough.

// Attack tool rules.
const (
	// RuleAttackToolArtex: ARTEX (or a renamed fork such as ScopeWeaver),
	// the AI-driven penetration testing framework the FBI warned about on
	// 13 Nov 2026 (FLASH 261113), found as a binary, an image or a copy
	// of its source.
	RuleAttackToolArtex = "attack-tool-artex"
	// RuleAttackToolArtexBackdoor: one of the prebuilt ARTEX images
	// reported to carry a backdoored login handler that runs any command
	// sent to it before checking the password.
	RuleAttackToolArtexBackdoor = "attack-tool-artex-backdoored-image"
	// RuleAttackToolArtexName: a Go module or container image only named
	// like ARTEX (github.com/someone/artex, an image "acme/artex"). Forks
	// rename the module, so this is reported, but at medium: "artex" is
	// also an ordinary name, and a name alone proves nothing.
	RuleAttackToolArtexName = "attack-tool-artex-name"
	// RuleAttackToolCyberStrikeAI: CyberStrikeAI, an AI-driven offensive
	// security platform with web shell management and a built-in C2,
	// found as a binary or a copy of its source. Unit 42 reported on 24
	// Nov 2026 that attackers ran it on a command-and-control server.
	RuleAttackToolCyberStrikeAI = "attack-tool-cyberstrikeai"
	// RuleAttackToolCyberStrikeAIName: a Go module or container image only
	// named like CyberStrikeAI.
	RuleAttackToolCyberStrikeAIName = "attack-tool-cyberstrikeai-name"
)

// AttackToolsDoc is the how-to every attack tool finding links to.
const AttackToolsDoc = "https://stackurity.ai/docs/config-checks#attack-tools"

// attackTool is one tool and how to recognise it.
type attackTool struct {
	name     string
	rule     string
	nameRule string
	// backdoorRule is the rule for an image in backdoored.
	backdoorRule string
	// modules are Go module paths, lower case, that only the tool and its
	// forks use; names are last path elements that identify it on their
	// own (a module "artex" or "example.com/x/scopeweaver").
	modules []string
	names   []string
	// backdoored are image repositories (lower case, without registry or
	// tag) reported to ship a backdoored build; images are other
	// repository names (last path element) that are the tool.
	backdoored []string
	images     []string
	about      string
}

var attackTools = []attackTool{{
	name:         "ARTEX",
	rule:         RuleAttackToolArtex,
	nameRule:     RuleAttackToolArtexName,
	backdoorRule: RuleAttackToolArtexBackdoor,
	// Autumn-27/ARTEX is the original (taken down 8 Oct 2026); the others
	// are public forks, ScopeWeaver a renamed one.
	modules:    []string{"github.com/autumn-27/artex", "github.com/ruoji6/artex", "github.com/jaykwok/artex", "github.com/cskwork/scopeweaver"},
	names:      []string{"artex", "scopeweaver"},
	backdoored: []string{"tomicdd/artex", "congdonglinux/artex"},
	images:     []string{"artex", "scopeweaver"},
	about: "ARTEX is an AI-driven attack framework (published as a penetration testing tool) that criminals and " +
		"state-backed groups use to break into organisations; the FBI warned about it on 13 Nov 2026.",
}, {
	name:     "CyberStrikeAI",
	rule:     RuleAttackToolCyberStrikeAI,
	nameRule: RuleAttackToolCyberStrikeAIName,
	// Its go.mod declares the bare module "cyberstrike-ai" (main package
	// cyberstrike-ai/cmd/server), which forks keep.
	modules: []string{"cyberstrike-ai"},
	names:   []string{"cyberstrike-ai", "cyberstrikeai"},
	images:  []string{"cyberstrike-ai", "cyberstrikeai"},
	about: "CyberStrikeAI is an AI-driven offensive security platform (published as a penetration testing tool) with web " +
		"shell management and a built-in command-and-control server; Unit 42 reported on 24 Nov 2026 that attackers " +
		"ran it on the server that steered AI agents breaking into Linux web servers.",
}}

// toolForModule returns the attack tool a Go main module or main package
// path belongs to. strong is false for a match by name only.
func toolForModule(paths ...string) (t attackTool, matched string, strong, ok bool) {
	for _, p := range paths {
		lp := strings.ToLower(strings.TrimSpace(p))
		if lp == "" {
			continue
		}
		for _, t := range attackTools {
			for _, m := range t.modules {
				if lp == m || strings.HasPrefix(lp, m+"/") {
					return t, p, true, true
				}
			}
			// The module's own last element (github.com/x/artex, or a
			// bare "artex" module), not a package deeper in another
			// project: github.com/acme/tools/artex is not it.
			for _, n := range t.names {
				if lp == n || path.Base(lp) == n && strings.Count(lp, "/") <= 2 {
					return t, p, false, true
				}
			}
		}
	}
	return attackTool{}, "", false, false
}

// nameOnly is the finding for a module or image only named like the tool.
func nameOnly(t attackTool, where string, line int, subject, what string) model.ConfigFinding {
	return finding(t.nameRule, model.ConfigAttackTool, "Named like the "+t.name+" attack tool", "medium", where, line, subject,
		t.about+" "+what+" Only the name matches, which other projects can share, so check what it is.",
		"Look at where it came from. If it is "+t.name+" and nobody on your team installed it, treat this machine as "+
			"compromised; if it is something else, dismiss this finding with a note.")
}

// GoBinaryAttackTool grades one Go executable's build record: a finding
// when its main module is a known attack tool. where is how the binary is
// named in the finding (its path on the host or in the image).
func GoBinaryAttackTool(where, mainPackage, mainModule string) (model.ConfigFinding, bool) {
	t, mod, strong, ok := toolForModule(mainModule, mainPackage)
	if !ok {
		return model.ConfigFinding{}, false
	}
	if !strong {
		return nameOnly(t, where, 0, "Go module "+mod, "This executable was built from a Go module named "+mod+"."), true
	}
	return finding(t.rule, model.ConfigAttackTool, t.name+" attack tool found", "high", where, 0,
		"Go module "+mod,
		t.about+" This executable was built from "+mod+" (its Go build record says so): someone can run it here.",
		"Find out who installed it and why. If nobody on your team did, treat this machine as compromised: isolate it, "+
			"rotate the credentials it holds and rebuild it. If it is your own test tool, dismiss this finding with a note."), true
}

// ImageAttackTools grades a container image by its references (repository
// and tags as Docker shows them): builds reported to be backdoored (ARTEX's),
// and images named after a tool.
func ImageAttackTools(refs ...string) []model.ConfigFinding {
	var out, named []model.ConfigFinding
	seen := map[string]bool{}
	for _, ref := range refs {
		repo := imageRepo(ref)
		if repo == "" || seen[repo] {
			continue
		}
		seen[repo] = true
		for _, t := range attackTools {
			if contains(t.backdoored, repo) {
				out = append(out, finding(t.backdoorRule, model.ConfigAttackTool,
					t.name+" image with a reported backdoor", "high", ref, 0, "image "+repo,
					t.about+" The prebuilt image "+repo+" was reported (BadByte, Nov 2026) to carry a backdoored login "+
						"handler that runs any command sent to it before checking the password; Docker Hub removed it on 5 Nov, "+
						"but copies already pulled stay backdoored. Anyone who can reach its console can run commands here.",
					"Stop and remove every container from this image, delete the image, and check the host for changes made "+
						"since it was pulled: new accounts, SSH keys, cron jobs and services."))
				continue
			}
			if contains(t.images, path.Base(repo)) && len(named) == 0 {
				named = append(named, nameOnly(t, ref, 0, "image "+repo, "This container image is named "+repo+"."))
			}
		}
	}
	// The refs are one image's: a reported backdoored build says all there
	// is to say; another tag of it named like the tool adds nothing.
	if len(out) == 0 {
		out = named
	}
	return out
}

// imageRepo is an image reference's repository, lower case, without the
// registry, tag or digest: docker.io/tomicdd/artex:latest -> tomicdd/artex,
// "artex" -> "artex".
func imageRepo(ref string) string {
	ref = strings.ToLower(strings.TrimSpace(ref))
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndexByte(ref, ':'); i > strings.LastIndexByte(ref, '/') {
		ref = ref[:i]
	}
	parts := strings.Split(ref, "/")
	if len(parts) > 1 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		parts = parts[1:]
	}
	if len(parts) == 2 && parts[0] == "library" {
		parts = parts[1:]
	}
	return strings.Join(parts, "/")
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// goModModule is the module path a go.mod declares.
func goModModule(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "module"); ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t') {
			return strings.Trim(strings.TrimSpace(rest), `"`+"`")
		}
	}
	return ""
}

// sourceAttackTool grades a checkout by its go.mod: a copy of an attack
// tool's source. display is how the file is named in the finding.
func sourceAttackTool(display string, goMod []byte) (model.ConfigFinding, bool) {
	mod := goModModule(goMod)
	t, _, strong, ok := toolForModule(mod)
	if !ok {
		return model.ConfigFinding{}, false
	}
	if !strong {
		return nameOnly(t, display, LineOf(goMod, mod), "module "+mod, "This go.mod declares a module named "+mod+"."), true
	}
	return finding(t.rule, model.ConfigAttackTool, t.name+" source code found", "high", display, LineOf(goMod, mod),
		"module "+mod, t.about+" This is a copy of its source ("+mod+"): it can be built and run from here.",
		"Find out who copied it and why. Remove it unless your security team uses it for authorised testing; "+
			"then dismiss this finding with a note."), true
}

// repoAttackTools reads a checkout's go.mod and the image references in
// its Dockerfile and Compose files.
func repoAttackTools(dir string) []model.ConfigFinding {
	var out []model.ConfigFinding
	read := func(rel string) []byte {
		real, ok := insideDir(dir, path.Join(dir, rel))
		if !ok {
			return nil
		}
		data, truncated, err := ReadBounded(real)
		if err != nil || truncated {
			return nil
		}
		return data
	}
	if data := read("go.mod"); data != nil {
		if f, ok := sourceAttackTool("go.mod", data); ok {
			out = append(out, f)
		}
	}
	for _, rel := range []string{"Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} {
		data := read(rel)
		if data == nil {
			continue
		}
		for _, ref := range imageRefs(data, rel == "Dockerfile") {
			for _, f := range ImageAttackTools(ref) {
				// Named by the file that pulls it, not the image.
				g := finding(f.Rule, f.Category, f.Title, f.Severity, rel, LineOf(data, ref), f.Subject, f.Why,
					"Remove "+ref+" from "+rel+". "+f.Fix)
				out = append(out, g)
			}
		}
	}
	return out
}

// heredocStart is a Dockerfile heredoc (RUN <<EOF, <<-"EOF", <<'EOF').
var heredocStart = regexp.MustCompile(`<<-?["']?([A-Za-z_][A-Za-z0-9_]*)["']?`)

// imageRefs are the images a Dockerfile (FROM) or Compose file (image:)
// names.
func imageRefs(data []byte, dockerfile bool) []string {
	var out []string
	heredoc := ""
	for _, line := range strings.Split(string(data), "\n") {
		if heredoc != "" { // inside a RUN <<EOF body: not instructions
			if strings.TrimSpace(line) == heredoc {
				heredoc = ""
			}
			continue
		}
		if m := heredocStart.FindStringSubmatch(line); dockerfile && m != nil {
			heredoc = m[1]
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		indented := line[0] == ' ' || line[0] == '\t'
		switch strings.ToLower(f[0]) {
		case "from":
			if indented { // a continuation or a script line, not an instruction
				continue
			}
			ref := f[1]
			if strings.HasPrefix(ref, "--") && len(f) > 2 { // FROM --platform=x image
				ref = f[2]
			}
			out = append(out, ref)
		case "image:", "-image:":
			out = append(out, strings.Trim(f[1], `"'`))
		}
	}
	return out
}

// hostAttackToolPlaces are where a tool's binary or source is looked for
// on a host, with how many directory levels below each are listed. Each
// login account's home is added at depth 1, plus its go/bin and
// .local/bin, and the applications' directories at depth 1. Directories
// whose names start with "." are not entered (other than those named).
// place is a directory to look in and how many levels below it.
type place struct {
	dir   string
	depth int
}

var hostAttackToolPlaces = []place{
	{"/app", 1}, {"/opt", 2}, {"/srv", 1}, {"/usr/local/bin", 0}, {"/usr/local/sbin", 0}, {"/root", 1},
	// Where an intruder drops a tool.
	{"/tmp", 1}, {"/var/tmp", 1}, {"/dev/shm", 1},
}

// Bounds of one host's walk: executables opened for their build
// information, their size, and the bytes read from them in total.
const (
	maxAttackToolExec     = 1000
	maxAttackToolExecSize = 512 << 20
	maxAttackToolBytes    = 256 << 20
)

// attackTools looks for known attack tools on the host: Go executables
// built from one (opened for their build record only, never run) and
// checkouts of one's source. A walk cut short by its bounds is noted as a
// problem, so the scan is not complete and nothing found before is taken as
// gone.
func (h *hostFS) attackTools(accounts []account, appDirs []string) []model.ConfigFinding {
	var out []model.ConfigFinding
	places := append([]place{}, hostAttackToolPlaces...)
	for _, a := range accounts {
		places = append(places, place{a.Home, 1}, place{path.Join(a.Home, "go", "bin"), 0},
			place{path.Join(a.Home, ".local", "bin"), 0})
	}
	for _, d := range appDirs {
		places = append(places, place{path.Clean("/" + d), 1})
	}
	seen := map[string]bool{}
	opened, budget := 0, int64(maxAttackToolBytes)
	capped := false
	var look func(dir string, depth int)
	look = func(dir string, depth int) {
		if seen[dir] {
			return
		}
		seen[dir] = true
		if data, err := h.read(path.Join(dir, "go.mod"), MaxHookFile); err == nil && data != nil {
			if f, ok := sourceAttackTool(path.Join(dir, "go.mod"), data); ok {
				out = append(out, f)
			}
		}
		entries := h.readDir(dir)
		if len(entries) > maxProjectDirs*10 {
			h.problem(dir, "has more than 2000 entries; attack tools were looked for in the first")
			entries = entries[:maxProjectDirs*10]
		}
		for _, e := range entries {
			p := path.Join(dir, e.Name())
			if e.IsDir() {
				if depth > 0 && !strings.HasPrefix(e.Name(), ".") {
					look(p, depth-1)
				}
				continue
			}
			if !e.Type().IsRegular() {
				continue
			}
			st, err := e.Info()
			if err != nil || st.Mode().Perm()&0o111 == 0 || st.Size() < 4 || st.Size() > maxAttackToolExecSize {
				continue
			}
			if opened >= maxAttackToolExec || budget <= 0 {
				if !capped {
					capped = true
					h.problem(dir, "was not fully checked for attack tools (executable limit reached)")
				}
				continue
			}
			opened++
			if f, ok := h.goBinaryAttackTool(p, &budget); ok {
				out = append(out, f)
			}
		}
	}
	for _, pl := range places {
		look(pl.dir, pl.depth)
	}
	return out
}

// budgetAt is a file as buildinfo reads it, counting the bytes read
// against the walk's budget.
type budgetAt struct {
	f      io.ReaderAt
	budget *int64
}

func (b budgetAt) ReadAt(p []byte, off int64) (int, error) {
	if *b.budget <= 0 {
		return 0, errBudget
	}
	if int64(len(p)) > *b.budget {
		p = p[:*b.budget]
	}
	n, err := b.f.ReadAt(p, off)
	*b.budget -= int64(n)
	return n, err
}

var errBudget = errors.New("attack tool read budget used up")

// machO reports a Mach-O executable's magic number (a Mac running the CLI).
func machO(head []byte) bool {
	switch string(head) {
	case "\xfe\xed\xfa\xce", "\xfe\xed\xfa\xcf", "\xce\xfa\xed\xfe", "\xcf\xfa\xed\xfe", "\xca\xfe\xba\xbe":
		return true
	}
	return false
}

// goBinaryAttackTool reads one host executable's Go build record. A
// malformed file cannot stop the agent: a panic in the reader is
// recovered and the file skipped.
func (h *hostFS) goBinaryAttackTool(p string, budget *int64) (f model.ConfigFinding, ok bool) {
	defer func() {
		if recover() != nil {
			f, ok = model.ConfigFinding{}, false
		}
	}()
	file, err := h.open(p)
	if err != nil {
		return model.ConfigFinding{}, false
	}
	defer file.Close()
	r := budgetAt{f: file, budget: budget}
	head := make([]byte, 4)
	if _, err := r.ReadAt(head, 0); err != nil || !bytes.Equal(head, []byte("\x7fELF")) && !machO(head) {
		return model.ConfigFinding{}, false
	}
	bi, err := buildinfo.Read(r)
	if err != nil {
		return model.ConfigFinding{}, false
	}
	return GoBinaryAttackTool(p, bi.Path, bi.Main.Path)
}
