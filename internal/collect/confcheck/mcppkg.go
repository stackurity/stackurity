package confcheck

import (
	"context"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/model"
)

// MCPPackage is the registry package an MCP server's start command runs:
// `npx -y @scope/server@1.4.2` is npm @scope/server 1.4.2. Version is ""
// when the command does not pin one, so the package runs at whatever
// version the registry serves that day.
type MCPPackage struct {
	Ecosystem string // npm or pypi
	Name      string
	Version   string
}

// exactVersion is a pinned version: 1.4.2, 0.6.1rc1, 2.0.0-beta.3. A
// range, a tag such as "latest" or "next", or a wildcard is not one.
var exactVersion = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){0,3}([-+.]?[0-9A-Za-z][0-9A-Za-z.+-]*)?$`)

var pypiNameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// pypiSep normalises a PyPI name per PEP 503.
var pypiSep = regexp.MustCompile(`[-_.]+`)

var npmNameRE = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$`)

// MCPStartPackage reads the package an MCP start command runs from npm
// (npx, bunx, pnpm dlx, yarn dlx) or PyPI (uvx, uv tool run, pipx run).
// A local path, an address, a git source or any other launcher is not a
// registry package: ok is false.
func MCPStartPackage(command string) (MCPPackage, bool) {
	f := strings.Fields(command)
	if len(f) == 0 {
		return MCPPackage{}, false
	}
	launcher := strings.ToLower(strings.TrimSuffix(path.Base(strings.ReplaceAll(f[0], `\`, "/")), ".cmd"))
	launcher = strings.TrimSuffix(launcher, ".exe")
	args := f[1:]
	switch launcher {
	case "npx", "bunx":
		return npmStart(args)
	case "pnpm", "yarn", "bun":
		if len(args) > 0 && (args[0] == "dlx" || (launcher == "bun" && args[0] == "x")) {
			return npmStart(args[1:])
		}
	case "uvx":
		return pypiStart(args, "--from")
	case "uv":
		if len(args) > 1 && args[0] == "tool" && args[1] == "run" {
			return pypiStart(args[2:], "--from")
		}
	case "pipx":
		if len(args) > 0 && args[0] == "run" {
			return pypiStart(args[1:], "--spec")
		}
	}
	return MCPPackage{}, false
}

// npmStart reads `[flags] pkg[@version]`, or the --package/-p value.
func npmStart(args []string) (MCPPackage, bool) {
	spec := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--package" || a == "-p" {
			if i+1 < len(args) {
				spec = args[i+1]
			}
			break
		}
		if v, ok := strings.CutPrefix(a, "--package="); ok {
			spec = v
			break
		}
		if strings.HasPrefix(a, "-") {
			continue // -y, --yes, -q, --quiet, --prefer-online
		}
		spec = a
		break
	}
	if spec == "" {
		return MCPPackage{}, false
	}
	name, version := spec, ""
	// The version follows the last "@" that is not the scope's.
	if i := strings.LastIndex(spec, "@"); i > 0 {
		name, version = spec[:i], spec[i+1:]
	}
	name = strings.ToLower(name)
	if !npmNameRE.MatchString(name) {
		return MCPPackage{}, false // ./server, /opt/x, git+https://…, file:…, a URL
	}
	return MCPPackage{Ecosystem: "npm", Name: name, Version: pinned(version)}, true
}

// pypiStart reads `[flags] pkg[==version]`, or the value of fromFlag.
func pypiStart(args []string, fromFlag string) (MCPPackage, bool) {
	spec := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == fromFlag {
			if i+1 < len(args) {
				spec = args[i+1]
			}
			break
		}
		if v, ok := strings.CutPrefix(a, fromFlag+"="); ok {
			spec = v
			break
		}
		if strings.HasPrefix(a, "-") {
			switch a {
			case "--with", "-w", "--python", "-p", "--index", "--index-url", "--extra-index-url", "--pip-args":
				i++ // these take a value
			}
			continue
		}
		spec = a
		break
	}
	name, version := spec, ""
	if n, v, ok := strings.Cut(spec, "=="); ok {
		name, version = n, v
	} else if n, v, ok := strings.Cut(spec, "@"); ok {
		name, version = n, v // uvx pkg@1.2.3
	}
	if i := strings.IndexByte(name, '['); i >= 0 {
		name = name[:i] // extras: pkg[cli]
	}
	if !pypiNameRE.MatchString(name) {
		return MCPPackage{}, false
	}
	return MCPPackage{Ecosystem: "pypi", Name: strings.ToLower(pypiSep.ReplaceAllString(name, "-")), Version: pinned(version)}, true
}

// pinned returns v when it is an exact version, else "" (unpinned).
func pinned(v string) string {
	if v == "" || !exactVersion.MatchString(v) {
		return ""
	}
	return strings.TrimPrefix(v, "v")
}

// Purl is the package URL, with the version when it is pinned.
func (p MCPPackage) Purl() string {
	ns, name := "", p.Name
	if p.Ecosystem == "npm" && strings.HasPrefix(name, "@") {
		if scope, rest, ok := strings.Cut(name, "/"); ok {
			ns, name = scope, rest
		}
	}
	return packageurl.NewPackageURL(p.Ecosystem, ns, name, p.Version, nil, "").ToString()
}

// mcpConfigFiles are the MCP client configurations a repository can hold.
var mcpConfigFiles = []string{".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json"}

// RepoMCPPackages lists the registry packages that the MCP servers
// configured in the checkout at dir start, as components of the
// repository, so the hourly checks match them against advisories and
// malicious-package records. A server whose command pins no version is
// listed with no version (confidence unknown), never as checked clean.
// Coverage says which configuration files were read.
func RepoMCPPackages(ctx context.Context, dir string) ([]model.Observation, model.CoverageItem) {
	cov := model.CoverageItem{Scope: "mcp:servers", Status: "checked"}
	var obs []model.Observation
	seen := map[string]bool{}
	var unread []string
	for _, rel := range mcpConfigFiles {
		if ctx.Err() != nil {
			return obs, model.CoverageItem{Scope: cov.Scope, Status: "partial", Reason: "stopped before every MCP configuration was read"}
		}
		p := filepath.Join(dir, filepath.FromSlash(rel))
		real, ok := insideDir(dir, p)
		if !ok {
			continue // absent, or a link out of the checkout
		}
		data, truncated, err := ReadBounded(real)
		if err != nil || truncated {
			unread = append(unread, rel)
			continue
		}
		servers, err := MCPStartCommands(data)
		if err != nil {
			unread = append(unread, rel)
			continue
		}
		for _, sv := range servers {
			pkg, ok := MCPStartPackage(sv.Command)
			if !ok {
				continue
			}
			key := rel + "\x00" + pkg.Purl()
			if seen[key] {
				continue
			}
			seen[key] = true
			o := model.Observation{
				Purl: pkg.Purl(), Version: pkg.Version, Location: rel, Scope: "runtime",
				Confidence: model.ConfidenceInferred,
				Evidence:   map[string]string{"source": "mcp-config", "mcp_server": clip(sv.Name, model.MaxShortField)},
			}
			if pkg.Version == "" {
				o.Confidence = model.ConfidenceUnknown
				o.Evidence["version"] = "not pinned: runs the version the registry serves when the client starts"
			}
			obs = append(obs, o)
		}
	}
	if len(unread) > 0 {
		cov.Status, cov.Reason = "partial", "could not read "+strings.Join(unread, ", ")
	}
	return obs, cov
}
