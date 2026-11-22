package confcheck

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
)

func TestMCPStartPackage(t *testing.T) {
	cases := []struct {
		cmd  string
		want MCPPackage
		ok   bool
	}{
		{"npx -y @modelcontextprotocol/server-filesystem@2026.1.14 /data", MCPPackage{"npm", "@modelcontextprotocol/server-filesystem", "2026.1.14"}, true},
		{"npx -y @modelcontextprotocol/server-filesystem /data", MCPPackage{"npm", "@modelcontextprotocol/server-filesystem", ""}, true},
		{"npx @playwright/mcp@latest", MCPPackage{"npm", "@playwright/mcp", ""}, true},
		{"npx -y mcp-remote@0.1.16 https://example.com/sse", MCPPackage{"npm", "mcp-remote", "0.1.16"}, true},
		{"npx mcp-remote@^0.1.0", MCPPackage{"npm", "mcp-remote", ""}, true},
		{"npx --package=@scope/srv@1.2.3 srv", MCPPackage{"npm", "@scope/srv", "1.2.3"}, true},
		{"C:\\nodejs\\npx.cmd -y some-server@1.0.0", MCPPackage{"npm", "some-server", "1.0.0"}, true},
		{"pnpm dlx some-server@1.0.0", MCPPackage{"npm", "some-server", "1.0.0"}, true},
		{"bunx some-server", MCPPackage{"npm", "some-server", ""}, true},
		{"uvx mcp-server-fetch", MCPPackage{"pypi", "mcp-server-fetch", ""}, true},
		{"uvx mcp-server-fetch==2025.4.7", MCPPackage{"pypi", "mcp-server-fetch", "2025.4.7"}, true},
		{"uvx --python 3.12 --from Mcp_Server.Git==0.6.2 mcp-server-git", MCPPackage{"pypi", "mcp-server-git", "0.6.2"}, true},
		{"uvx mcp-server-time[extra]@1.0.0", MCPPackage{"pypi", "mcp-server-time", "1.0.0"}, true},
		{"uv tool run mcp-server-git", MCPPackage{"pypi", "mcp-server-git", ""}, true},
		{"pipx run --spec mcp-server-x==0.2 mcp-x", MCPPackage{"pypi", "mcp-server-x", "0.2"}, true},
		{"npx ./local-server", MCPPackage{}, false},
		{"npx git+https://github.com/a/b.git", MCPPackage{}, false},
		{"npx https://example.com/x.tgz", MCPPackage{}, false},
		{"uvx --from git+https://github.com/a/b mcp-b", MCPPackage{}, false},
		{"node /opt/server/index.js", MCPPackage{}, false},
		{"docker run -i --rm mcp/fetch", MCPPackage{}, false},
		{"npx -y", MCPPackage{}, false},
		{"", MCPPackage{}, false},
	}
	for _, c := range cases {
		got, ok := MCPStartPackage(c.cmd)
		if ok != c.ok || got != c.want {
			t.Errorf("MCPStartPackage(%q) = %+v, %v; want %+v, %v", c.cmd, got, ok, c.want, c.ok)
		}
	}
}

func TestMCPPackagePurl(t *testing.T) {
	if got := (MCPPackage{"npm", "@scope/srv", "1.2.3"}).Purl(); got != "pkg:npm/%40scope/srv@1.2.3" {
		t.Errorf("npm purl = %q", got)
	}
	if got := (MCPPackage{"pypi", "mcp-server-fetch", ""}).Purl(); got != "pkg:pypi/mcp-server-fetch" {
		t.Errorf("pypi purl = %q", got)
	}
}

func TestRepoMCPPackages(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".mcp.json", `{"mcpServers": {
		"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2026.1.14", "."]},
		"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
		"local": {"command": "node", "args": ["tools/server.js"]},
		"remote": {"url": "https://mcp.example.com/sse"}
	}}`)
	write(".vscode/mcp.json", `{
		// VS Code keeps comments
		"servers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2026.1.14"]}}
	}`)
	write(".cursor/mcp.json", `{not json`)

	obs, cov := RepoMCPPackages(context.Background(), dir)
	if cov.Scope != "mcp:servers" || cov.Status != "partial" || cov.Reason != "could not read .cursor/mcp.json" {
		t.Errorf("coverage = %+v", cov)
	}
	byKey := map[string]model.Observation{}
	for _, o := range obs {
		byKey[o.Location+" "+o.Purl] = o
	}
	if len(obs) != 3 {
		t.Fatalf("got %d observations, want 3: %+v", len(obs), obs)
	}
	fs := byKey[".mcp.json pkg:npm/%40modelcontextprotocol/server-filesystem@2026.1.14"]
	if fs.Version != "2026.1.14" || fs.Confidence != model.ConfidenceInferred || fs.Evidence["mcp_server"] != "fs" || fs.Evidence["source"] != "mcp-config" {
		t.Errorf("pinned npm server = %+v", fs)
	}
	fetch := byKey[".mcp.json pkg:pypi/mcp-server-fetch"]
	if fetch.Version != "" || fetch.Confidence != model.ConfidenceUnknown || fetch.Evidence["version"] == "" {
		t.Errorf("unpinned server must carry no version and unknown confidence, got %+v", fetch)
	}
	if _, ok := byKey[".vscode/mcp.json pkg:npm/%40modelcontextprotocol/server-filesystem@2026.1.14"]; !ok {
		t.Errorf("VS Code server missing: %+v", obs)
	}

	// The batch these join must still validate.
	b := model.ObservationBatch{SchemaVersion: "1", Collector: model.Collector{ID: "t", Version: "1", Method: "repository"},
		Asset:        model.AssetRef{Kind: model.AssetRepository, Name: "r", Identifiers: []model.Identifier{{Scheme: "git-url", Value: "github.com/a/r"}}},
		Observations: obs, Coverage: []model.CoverageItem{cov}}
	b.ObservedAt = time.Now()
	if err := b.Validate(); err != nil {
		t.Errorf("batch with MCP packages does not validate: %v", err)
	}
}

func TestRepoMCPPackagesNoConfig(t *testing.T) {
	obs, cov := RepoMCPPackages(context.Background(), t.TempDir())
	if len(obs) != 0 || cov.Status != "checked" {
		t.Errorf("empty checkout: %+v %+v", obs, cov)
	}
}

func TestRepoMCPPackagesLinkOutOfCheckout(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "mcp.json"), []byte(`{"mcpServers":{"x":{"command":"npx","args":["evil@1.0.0"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "mcp.json"), filepath.Join(dir, ".mcp.json")); err != nil {
		t.Skip("symlinks not available")
	}
	if obs, _ := RepoMCPPackages(context.Background(), dir); len(obs) != 0 {
		t.Errorf("a link out of the checkout was read: %+v", obs)
	}
}
