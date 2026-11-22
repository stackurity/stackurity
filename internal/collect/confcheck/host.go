package confcheck

import (
	"context"
	"sort"
	"strings"

	"github.com/stackurity/stackurity/internal/model"
)

// Host runs the host checks on the filesystem under root ("/" for this
// host): AI coding-agent hooks and MCP start commands in each login
// account's home, the projects directly under it and appDirs (host paths of
// the applications the agent reports), and SSH access for root and for CI
// keys, and known attack tools (attacktools.go). Nothing is run; files are
// only read.
func Host(ctx context.Context, root string, appDirs []string) *model.ConfigScan {
	h := &hostFS{Root: root}
	accounts := h.accounts()
	var found []model.ConfigFinding
	found = append(found, h.hostHooks(accounts, appDirs)...)
	if ctx.Err() == nil {
		found = append(found, h.sshAccess(accounts, h.rootKeyLogins())...)
	}
	if ctx.Err() == nil {
		found = append(found, h.attackTools(accounts, appDirs)...)
	}
	out := &model.ConfigScan{Found: dedupe(found), Complete: ctx.Err() == nil && len(h.problems) == 0}
	if ctx.Err() != nil {
		out.Reason = "stopped before every check ran"
	} else if len(h.problems) > 0 {
		out.Reason = clip("not read: "+strings.Join(h.problems, "; "), model.MaxFieldLen)
	}
	return out
}

// Dedupe keeps one finding per fingerprint and bounds the list, most
// severe first, for collectors outside this package (container images).
func Dedupe(in []model.ConfigFinding) []model.ConfigFinding { return dedupe(in) }

// dedupe keeps one finding per fingerprint and bounds the list, most
// severe first.
func dedupe(in []model.ConfigFinding) []model.ConfigFinding {
	rank := map[string]int{"high": 0, "medium": 1, "low": 2, "info": 3}
	sort.SliceStable(in, func(i, j int) bool { return rank[in[i].Severity] < rank[in[j].Severity] })
	seen := map[string]bool{}
	out := []model.ConfigFinding{}
	for _, f := range in {
		if seen[f.Fingerprint] || len(out) >= model.MaxConfigFindings {
			continue
		}
		seen[f.Fingerprint] = true
		out = append(out, f)
	}
	return out
}
