package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// ReportingHost is a host asset an agent reports, by the hostname it
// reports. Fleet discovery (DigitalOcean droplets) matches machines to it.
type ReportingHost struct {
	AssetID  int64     `json:"asset_id"`
	Name     string    `json:"name"`
	Hostname string    `json:"hostname"`
	LastSeen time.Time `json:"last_seen"`
}

// ReportingHosts returns the workspace's host assets with the hostnames
// they report (at most limit rows), for matching against a cloud's list of
// machines.
func (s *Store) ReportingHosts(ctx context.Context, limit int) ([]ReportingHost, error) {
	rows, err := s.Pool.Query(ctx, `SELECT a.id, a.name, i.value, a.last_seen
		FROM assets a JOIN asset_identifiers i ON i.asset_id = a.id AND i.scheme = 'hostname'
		WHERE a.kind = 'host' AND a.merged_into IS NULL
		ORDER BY a.last_seen DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[ReportingHost])
}

// EnrolledAddress is an address a host enrolled from, and the hostname it
// gave.
type EnrolledAddress struct {
	RemoteAddr string    `json:"remote_addr"`
	Hostname   string    `json:"hostname"`
	UsedAt     time.Time `json:"used_at"`
}

// EnrolledAddresses returns the addresses hosts enrolled from (newest use of
// each address first, at most limit), so a machine whose agent enrolled but
// has not reported yet, or reports another hostname, can still be matched.
func (s *Store) EnrolledAddresses(ctx context.Context, limit int) ([]EnrolledAddress, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT ON (remote_addr) remote_addr, hostname, used_at
		FROM enrollment_uses WHERE remote_addr <> '' ORDER BY remote_addr, used_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[EnrolledAddress])
}
