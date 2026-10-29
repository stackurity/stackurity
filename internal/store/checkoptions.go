package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// agentPollFresh is how recently an agent must have asked about checks for
// Check again to reach it within a minute or two (agents ask every 45
// seconds; 0.6 and older never ask).
const agentPollFresh = 15 * time.Minute

// Why a fix's place cannot be checked on demand (CheckOption.Reason).
const (
	RecheckRemoved  = "removed"   // the application is gone from its host
	RecheckNoPoll   = "agent"     // the agent does not ask for checks (older than 0.7, or stopped)
	RecheckUpload   = "upload"    // an upload (stackurity scan in CI, an SBOM): only the next one shows it
	RecheckNotFound = "not_found" // no such fix (fixed and gone from the plan) or asset
)

// CheckOption says how one place of a fix (or one asset) can be checked
// again: whether a Check again request gets a fresh report within minutes
// (OnDemand), and if not, why, so the dashboard explains what to do
// instead of offering a button that does nothing. LastCheck is the latest
// check of that fix (or asset), if any.
type CheckOption struct {
	FixGroup         string     `json:"fix_group,omitempty"`
	AssetID          int64      `json:"asset_id"`
	AssetName        string     `json:"asset_name"`
	AssetKind        string     `json:"asset_kind"`
	AppDir           string     `json:"app_dir,omitempty"`
	HostName         string     `json:"host_name,omitempty"`
	GitURL           string     `json:"git_url,omitempty"`
	CollectionStatus string     `json:"collection_status"`
	LastSeen         time.Time  `json:"last_seen"`
	AgentPolledAt    *time.Time `json:"agent_polled_at"`
	Method           string     `json:"method"` // agent, integration or report, as a check would use
	OnDemand         bool       `json:"on_demand"`
	Reason           string     `json:"reason,omitempty"` // removed, agent, upload or not_found when not OnDemand
	LastCheck        *Check     `json:"last_check"`
}

// MaxCheckOptions bounds one request for check options.
const MaxCheckOptions = 50

// CheckOptions describes how each fix group (or asset) can be checked
// again. Unknown fix groups (already fixed and gone from the plan) come
// back with Reason not_found and their latest check, if any.
func (s *Store) CheckOptions(ctx context.Context, fixGroups []string, assetIDs []int64) ([]CheckOption, error) {
	var out []CheckOption
	for _, g := range fixGroups {
		var asset int64
		err := s.Pool.QueryRow(ctx, `SELECT asset_id FROM fix_groups WHERE id = $1`, g).Scan(&asset)
		if errors.Is(err, pgx.ErrNoRows) {
			o := CheckOption{FixGroup: g, Reason: RecheckNotFound}
			if o.LastCheck, err = s.lastCheck(ctx, CheckFilter{FixGroup: g}); err != nil {
				return nil, err
			}
			if o.LastCheck != nil {
				// Fixed and gone from the plan: describe its asset as before
				// (the server's name, removed or not) with the fix's last check.
				full, err := s.checkOption(ctx, o.LastCheck.AssetID, g)
				switch {
				case err == nil:
					if full.Reason == "" {
						full.Reason, full.OnDemand = RecheckNotFound, false
					}
					o = *full
				case errors.Is(err, ErrNotFound):
					o.AssetID, o.AssetName, o.AssetKind = o.LastCheck.AssetID, o.LastCheck.AssetName, o.LastCheck.AssetKind
				default:
					return nil, err
				}
			}
			out = append(out, o)
			continue
		}
		if err != nil {
			return nil, err
		}
		o, err := s.checkOption(ctx, asset, g)
		if err != nil {
			return nil, err
		}
		out = append(out, *o)
	}
	for _, id := range assetIDs {
		o, err := s.checkOption(ctx, id, "")
		if errors.Is(err, ErrNotFound) {
			out = append(out, CheckOption{AssetID: id, Reason: RecheckNotFound})
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, *o)
	}
	return out, nil
}

func (s *Store) lastCheck(ctx context.Context, f CheckFilter) (*Check, error) {
	f.Page = Page{Limit: 1}
	list, _, err := s.ListChecks(ctx, f)
	if err != nil || len(list) == 0 {
		return nil, err
	}
	return &list[0], nil
}

func (s *Store) checkOption(ctx context.Context, assetID int64, fixGroup string) (*CheckOption, error) {
	o := CheckOption{FixGroup: fixGroup, AssetID: assetID}
	var integ *int64
	var hostPolled *time.Time
	// The server an application runs on, by its asset's name (a person
	// may have renamed it), else the name its agent gave.
	err := s.Pool.QueryRow(ctx, `SELECT a.name, a.kind, COALESCE(a.attributes->>'app_dir', ''),
		  COALESCE((SELECT h.name FROM asset_relations r JOIN assets h ON h.id = r.to_asset AND h.kind = 'host'
		    WHERE r.from_asset = a.id AND r.kind = 'runs_on' ORDER BY h.id LIMIT 1), a.attributes->>'host', ''),
		  COALESCE(a.attributes->>'git_url', ''), a.collection_status, a.last_seen, a.agent_polled_at,
		  (SELECT max(h.agent_polled_at) FROM asset_relations r JOIN assets h ON h.id = r.to_asset
		    WHERE r.from_asset = a.id AND r.kind = 'runs_on'),
		  (SELECT i.id FROM integrations i WHERE i.asset_id = a.id AND i.enabled ORDER BY i.id LIMIT 1)
		FROM assets a WHERE a.id = $1 AND a.merged_into IS NULL`, assetID).
		Scan(&o.AssetName, &o.AssetKind, &o.AppDir, &o.HostName, &o.GitURL, &o.CollectionStatus, &o.LastSeen, &o.AgentPolledAt, &hostPolled, &integ)
	if err != nil {
		return nil, notFound(err)
	}
	if o.HostName == "" && o.AssetKind == "host" {
		o.HostName = o.AssetName
	}
	// An application's own poll time, or its host's: the host's agent
	// reports it.
	polled := o.AgentPolledAt
	if hostPolled != nil && (polled == nil || hostPolled.After(*polled)) {
		polled = hostPolled
	}
	o.AgentPolledAt = polled
	switch {
	case o.AssetKind == "host" || polled != nil:
		o.Method = CheckAgent
	case integ != nil:
		o.Method = CheckIntegration
	default:
		o.Method = CheckReport
	}
	switch {
	case o.CollectionStatus == AssetRemoved:
		o.Reason = RecheckRemoved
	case o.Method == CheckAgent:
		o.OnDemand = polled != nil && time.Since(*polled) < agentPollFresh
		if !o.OnDemand {
			o.Reason = RecheckNoPoll
		}
	case o.Method == CheckIntegration:
		o.OnDemand = true
	default:
		o.Reason = RecheckUpload
	}
	f := CheckFilter{AssetID: assetID}
	if fixGroup != "" {
		f = CheckFilter{FixGroup: fixGroup}
	}
	if o.LastCheck, err = s.lastCheck(ctx, f); err != nil {
		return nil, err
	}
	return &o, nil
}
