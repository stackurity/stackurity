package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/tenant"
)

// IssueRef is what the dashboard shows of a tracker issue.
type IssueRef struct {
	Tracker   string `json:"tracker"`
	Key       string `json:"key"`
	URL       string `json:"url"`
	ChannelID *int64 `json:"channel_id"`
}

// IssueLink is the issue an incident has in one tracker channel and what the
// issue was last told.
type IssueLink struct {
	ID             int64
	IncidentID     int64
	ChannelID      *int64
	IssueKey       string
	IssueURL       string
	SyncedPriority string
	SyncedFindings int
	SyncedAssets   int
	ResolvedSynced bool
}

const issueLinkCols = `id, incident_id, channel_id, issue_key, issue_url, synced_priority, synced_findings, synced_assets, resolved_synced`

// ErrIssueBeingCreated means another attempt (on this or another replica)
// holds the claim to create the incident's issue in this channel.
var ErrIssueBeingCreated = errors.New("the issue is being created by another attempt; will retry")

func (s *Store) issueRefs(ctx context.Context, incidentIDs []int64) (map[int64][]IssueRef, error) {
	out := map[int64][]IssueRef{}
	// A tracker issue describes the whole incident, across every asset:
	// a caller who sees only some assets gets none (row-level security
	// hides them too, migration 0032).
	if len(incidentIDs) == 0 || tenant.Narrowed(ctx) {
		return out, nil
	}
	rows, err := s.Pool.Query(ctx, `SELECT incident_id, tracker, issue_key, issue_url, channel_id FROM incident_issues
		WHERE incident_id = ANY($1) AND issue_key <> '' ORDER BY id`, incidentIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var r IssueRef
		if err := rows.Scan(&id, &r.Tracker, &r.Key, &r.URL, &r.ChannelID); err != nil {
			return nil, err
		}
		out[id] = append(out[id], r)
	}
	return out, rows.Err()
}

// IssueLinkFor returns the incident's issue in a channel, or ErrNotFound when
// it has none (or it is still being created).
func (s *Store) IssueLinkFor(ctx context.Context, channelID, incidentID int64) (*IssueLink, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+issueLinkCols+` FROM incident_issues
		WHERE channel_id = $1 AND incident_id = $2 AND issue_key <> ''`, channelID, incidentID)
	if err != nil {
		return nil, err
	}
	l, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[IssueLink])
	return l, notFound(err)
}

// ClaimIssueCreation reserves the right to create the incident's issue in a
// channel for lease. It returns the existing link when the issue already
// exists, and ErrIssueBeingCreated while another attempt holds the claim. A
// claim that is never recorded or released expires, and the next attempt
// searches the tracker before creating.
func (s *Store) ClaimIssueCreation(ctx context.Context, channelID, incidentID int64, lease time.Duration) (existing *IssueLink, err error) {
	// Selecting the incident and channel applies row-level security to
	// them, which foreign keys alone do not.
	tag, err := s.Pool.Exec(ctx, `INSERT INTO incident_issues (channel_id, incident_id, creating_until)
		SELECT c.id, i.id, now() + $3::interval FROM channels c, incidents i WHERE c.id = $1 AND i.id = $2
		ON CONFLICT (channel_id, incident_id) DO UPDATE SET creating_until = EXCLUDED.creating_until, updated_at = now()
		WHERE incident_issues.issue_key = '' AND (incident_issues.creating_until IS NULL OR incident_issues.creating_until < now())`,
		channelID, incidentID, lease)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 1 {
		return nil, nil
	}
	l, err := s.IssueLinkFor(ctx, channelID, incidentID)
	if errors.Is(err, ErrNotFound) {
		var claimed bool
		if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM incident_issues WHERE channel_id = $1 AND incident_id = $2)`,
			channelID, incidentID).Scan(&claimed); err != nil {
			return nil, err
		}
		if !claimed {
			return nil, ErrNotFound // no such incident or channel here
		}
		return nil, ErrIssueBeingCreated
	}
	return l, err
}

// ReleaseIssueClaim gives up a creation claim after a failed attempt, so the
// retry need not wait for the lease.
func (s *Store) ReleaseIssueClaim(ctx context.Context, channelID, incidentID int64) error {
	_, err := s.Pool.Exec(ctx, `UPDATE incident_issues SET creating_until = NULL
		WHERE channel_id = $1 AND incident_id = $2 AND issue_key = ''`, channelID, incidentID)
	return err
}

// RecordIssue stores the issue created (or found) for an incident, with the
// state it describes.
func (s *Store) RecordIssue(ctx context.Context, channelID, incidentID int64, key, url, priority string, findings, assets int) error {
	tag, err := s.Pool.Exec(ctx, `INSERT INTO incident_issues (channel_id, incident_id, issue_key, issue_url, synced_priority, synced_findings, synced_assets)
		SELECT c.id, i.id, $3, $4, $5, $6, $7 FROM channels c, incidents i WHERE c.id = $1 AND i.id = $2
		ON CONFLICT (channel_id, incident_id) DO UPDATE SET issue_key = EXCLUDED.issue_key, issue_url = EXCLUDED.issue_url,
		  synced_priority = EXCLUDED.synced_priority, synced_findings = EXCLUDED.synced_findings,
		  synced_assets = EXCLUDED.synced_assets, creating_until = NULL, updated_at = now()`,
		channelID, incidentID, key, url, priority, findings, assets)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// IssueSynced records what the issue has now been told.
func (s *Store) IssueSynced(ctx context.Context, linkID int64, priority string, findings, assets int, resolved bool) error {
	_, err := s.Pool.Exec(ctx, `UPDATE incident_issues SET synced_priority = $2, synced_findings = $3, synced_assets = $4,
		resolved_synced = resolved_synced OR $5, updated_at = now() WHERE id = $1`, linkID, priority, findings, assets, resolved)
	return err
}

// IssueChange is an incident whose tracker issue is out of date.
type IssueChange struct {
	LinkID     int64
	SyncedAt   time.Time // when the issue was last updated; part of the dedupe key
	ChannelID  int64
	Incident   Incident
	IssueKey   string
	Resolution bool // the incident resolved; otherwise priority or counts changed
}

// IssueChanges returns tracker issues to update: open incidents whose
// priority, finding count or asset count differ from what the issue was last
// told, and resolved incidents whose issue has not been told yet.
func (s *Store) IssueChanges(ctx context.Context) ([]IssueChange, error) {
	rows, err := s.Pool.Query(ctx, `SELECT l.id, l.updated_at, l.channel_id, l.issue_key, i.status = 'resolved', `+incidentCols+`
		FROM incident_issues l JOIN channels c ON c.id = l.channel_id AND c.enabled
		JOIN incidents i ON i.id = l.incident_id LEFT JOIN teams t ON t.id = i.owner_team_id
		WHERE l.issue_key <> '' AND (
		  (i.status = 'open' AND (i.priority, i.finding_count, i.asset_count) IS DISTINCT FROM
		     (l.synced_priority, l.synced_findings, l.synced_assets))
		  OR (i.status = 'resolved' AND NOT l.resolved_synced))
		ORDER BY l.id LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IssueChange
	for rows.Next() {
		var c IssueChange
		in := &c.Incident
		if err := rows.Scan(&c.LinkID, &c.SyncedAt, &c.ChannelID, &c.IssueKey, &c.Resolution, &in.ID, &in.Kind, &in.Key, &in.OwnerTeamID, &in.OwnerTeam,
			&in.Title, &in.Priority, &in.SOS, &in.Status, &in.State, &in.FindingCount, &in.AssetCount, &in.Detail, &in.CreatedAt,
			&in.UpdatedAt, &in.ResolvedAt, &in.NotifiedPriority, &in.NotifiedAt, &in.EscalationLevel); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// IssuedChannels returns, per incident, the channels where it already has an
// issue.
func (s *Store) IssuedChannels(ctx context.Context, incidentIDs []int64) (map[int64]map[int64]bool, error) {
	out := map[int64]map[int64]bool{}
	if len(incidentIDs) == 0 {
		return out, nil
	}
	rows, err := s.Pool.Query(ctx, `SELECT incident_id, channel_id FROM incident_issues
		WHERE incident_id = ANY($1) AND issue_key <> '' AND channel_id IS NOT NULL`, incidentIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var inc, ch int64
		if err := rows.Scan(&inc, &ch); err != nil {
			return nil, err
		}
		if out[inc] == nil {
			out[inc] = map[int64]bool{}
		}
		out[inc][ch] = true
	}
	return out, rows.Err()
}

// AffectedItem is one open finding of an incident, for issue descriptions.
type AffectedItem struct {
	Asset        string
	Environment  string
	Exposed      *bool
	Component    string
	Version      string
	FixedVersion string
}

// IncidentBrief is what a tracker issue says about an incident beyond its
// summary: the risk factors of its most urgent finding and the affected
// assets, bounded.
type IncidentBrief struct {
	Factors  []risk.Factor
	SOSRule  string
	Affected []AffectedItem
}

// IncidentBrief returns up to limit affected items, most urgent first.
func (s *Store) IncidentBrief(ctx context.Context, incidentID int64, limit int) (*IncidentBrief, error) {
	b := &IncidentBrief{}
	var factors []byte
	err := s.Pool.QueryRow(ctx, `SELECT priority_factors, sos_rule FROM findings
		WHERE incident_id = $1 AND status = 'open' ORDER BY priority_score DESC, id LIMIT 1`, incidentID).Scan(&factors, &b.SOSRule)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(factors, &b.Factors); err != nil {
			return nil, fmt.Errorf("priority factors: %w", err)
		}
	}
	rows, err := s.Pool.Query(ctx, `SELECT a.name, a.environment, a.internet_exposed,
		  CASE WHEN c.namespace = '' THEN c.name ELSE c.namespace || '/' || c.name END, inv.version, f.fixed_version
		FROM findings f JOIN assets a ON a.id = f.asset_id JOIN components c ON c.id = f.component_id
		JOIN inventory inv ON inv.id = f.inventory_id
		WHERE f.incident_id = $1 AND f.status = 'open'
		ORDER BY f.priority_score DESC, a.name, f.id LIMIT $2`, incidentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a AffectedItem
		if err := rows.Scan(&a.Asset, &a.Environment, &a.Exposed, &a.Component, &a.Version, &a.FixedVersion); err != nil {
			return nil, err
		}
		b.Affected = append(b.Affected, a)
	}
	return b, rows.Err()
}
