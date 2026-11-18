package apps

import (
	"context"
	"path"

	"github.com/stackurity/stackurity/internal/collect/assistantcfg"
	"github.com/stackurity/stackurity/internal/model"
)

// AssistantConfig scans the application at host path dir for risky
// settings in AI coding assistants' configuration files: a deployed copy
// of a repository carries its .claude/settings.json and .mcp.json, and a
// developer who opens it on the server runs what they say. Applications
// inside it are left to their own scans.
func (s *Scanner) AssistantConfig(ctx context.Context, dir string) *model.AssistantScan {
	dir = path.Clean("/" + dir)
	res := assistantcfg.Dir(ctx, s.path(dir), func(rel string) bool { return s.nestedApp(dir, path.Join(dir, rel)) })
	for i := range res.Found {
		res.Found[i].Path = path.Join(dir, res.Found[i].Path)
	}
	return res.Scan()
}
