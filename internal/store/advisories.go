package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/osv"
)

// PackageRef identifies an OSV package.
type PackageRef struct {
	BaseEcosystem string
	Name          string
}

// storedFormat is part of every advisory's content hash. Changing what is
// stored for an advisory (its columns or the shape of affected) must change
// it, so the next sync rewrites every advisory once in the new form.
const storedFormat = "2"

// StoredAffected is what advisory_packages.affected keeps of an OSV affected
// entry: the ranges and the listed versions. They are all that is read back
// from it: by the matcher (osv.Check, and the fix it reports from every
// range's "fixed" events), by the second check (internal/secondcheck reads
// ranges and versions) and by the explanation, which the matcher stores
// with the finding. The package is in the row's own columns; severities,
// ecosystem_specific and database_specific are read once, when the record
// is synced, to rate the advisory (osv.Rate), and the rating is stored on
// the advisory. Rows written before 0.10 also hold those fields; they read
// the same.
type StoredAffected struct {
	Ranges   []osv.Range `json:"ranges,omitempty"`
	Versions []string    `json:"versions,omitempty"`
}

// CompactAffected returns the stored form of an affected entry.
func CompactAffected(a osv.Affected) []byte {
	b, _ := json.Marshal(StoredAffected{Ranges: a.Ranges, Versions: a.Versions})
	return b
}

type packageRow struct {
	base, ecosystem, name string
	affected              []byte
}

// advisoryRecord is one advisory as it is stored.
type advisoryRecord struct {
	id, feed, groupKey, summary, level, vector, source string
	aliases                                            []string
	score                                              *float32
	published, withdrawn                               *time.Time
	modified                                           time.Time // zero when the record has none
	refs                                               []byte
	rows                                               []packageRow
	hash                                               string
}

func newAdvisoryRecord(feed string, v *osv.Vulnerability) *advisoryRecord {
	r := osv.Rate(v)
	rec := &advisoryRecord{id: v.ID, feed: feed, groupKey: osv.GroupKey(v.ID, v.Aliases, v.Upstream...),
		summary: truncateText(v.Summary, 500), level: r.Level, vector: r.Vector, source: r.Source,
		aliases: v.Aliases, modified: v.Modified, withdrawn: v.Withdrawn}
	if r.Score > 0 || r.Source == "cvss_v3" || r.Source == "cvss_v4" {
		f := float32(r.Score)
		rec.score = &f
	}
	if rec.aliases == nil {
		rec.aliases = []string{}
	}
	if !v.Published.IsZero() {
		rec.published = &v.Published
	}
	rec.refs, _ = json.Marshal(v.References)
	// A withdrawn advisory never matches (the matcher and the second check
	// skip it), so its package rows are not kept: the advisory row records
	// the withdrawal.
	if v.Withdrawn == nil {
		seen := map[string]bool{}
		for _, a := range v.Affected {
			if a.Package.Name == "" || a.Package.Ecosystem == "" {
				continue
			}
			row := packageRow{osv.BaseEcosystem(a.Package.Ecosystem), a.Package.Ecosystem, a.Package.Name, CompactAffected(a)}
			// An identical entry listed twice matches the same way once.
			k := row.ecosystem + "\x00" + row.name + "\x00" + string(row.affected)
			if seen[k] {
				continue
			}
			seen[k] = true
			rec.rows = append(rec.rows, row)
		}
	}
	sort.Slice(rec.rows, func(i, j int) bool {
		a, b := rec.rows[i], rec.rows[j]
		if a.ecosystem != b.ecosystem {
			return a.ecosystem < b.ecosystem
		}
		if a.name != b.name {
			return a.name < b.name
		}
		return bytes.Compare(a.affected, b.affected) < 0
	})
	rec.hash = rec.contentHash()
	return rec
}

// contentHash covers everything stored for the advisory except what other
// feeds maintain (known_exploited, from the KEV catalogue) and the time it
// was stored. Two records with the same hash store the same rows.
func (r *advisoryRecord) contentHash() string {
	h := sha256.New()
	rows := make([][4]string, len(r.rows))
	for i, p := range r.rows {
		rows[i] = [4]string{p.base, p.ecosystem, p.name, string(p.affected)}
	}
	_ = json.NewEncoder(h).Encode([]any{storedFormat, r.id, r.feed, r.groupKey, r.aliases, r.summary, r.level, r.score,
		r.vector, r.source, r.published, r.modified, r.withdrawn, json.RawMessage(r.refs), rows})
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// UpsertAdvisories stores OSV records and returns how many changed.
//
// Only what changed is written. A record whose content hash equals the
// stored one is skipped entirely; for a changed record the advisory row is
// updated and only the package rows that differ are deleted or inserted.
// Each call is one transaction, so an interrupted sync leaves every advisory
// in its old or its new state.
//
// The packages a changed record touches (before and after the change) are
// added to the feed's pending re-evaluation in the same transaction;
// the sync hands them to re-evaluation and clears them when it completes
// (PendingPackages, FeedResult). A record stored by an interrupted sync is
// unchanged when the next sync reads it again, and its packages are still
// re-evaluated.
func (s *Store) UpsertAdvisories(ctx context.Context, feed string, vulns []*osv.Vulnerability) (int, error) {
	touched := map[PackageRef]bool{}
	var changed []string
	byID := map[string]*advisoryRecord{}
	var ids []string
	for _, v := range vulns {
		if _, dup := byID[v.ID]; !dup {
			ids = append(ids, v.ID)
		}
		byID[v.ID] = newAdvisoryRecord(feed, v) // the last copy of a repeated id wins
	}
	if len(ids) == 0 {
		return 0, nil
	}
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		stored := map[string]string{}
		rows, err := tx.Query(ctx, `SELECT id, COALESCE(content_hash, '') FROM advisories WHERE id = ANY($1)`, ids)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, h string
			if err := rows.Scan(&id, &h); err != nil {
				rows.Close()
				return err
			}
			stored[id] = h
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		changed = changed[:0]
		for _, id := range ids {
			if h, ok := stored[id]; !ok || h != byID[id].hash {
				changed = append(changed, id)
			}
		}
		if len(changed) == 0 {
			return nil
		}
		// Packages the old versions referenced are touched too: an advisory
		// that drops a package must clear that package's findings.
		rows, err = tx.Query(ctx, `SELECT DISTINCT base_ecosystem, name FROM advisory_packages WHERE advisory_id = ANY($1)`, changed)
		if err != nil {
			return err
		}
		for rows.Next() {
			var p PackageRef
			if err := rows.Scan(&p.BaseEcosystem, &p.Name); err != nil {
				rows.Close()
				return err
			}
			touched[p] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		batch := &pgx.Batch{}
		var nID, nBase, nEco, nName, nAff []string
		for _, id := range changed {
			r := byID[id]
			modified := r.modified
			if modified.IsZero() {
				modified = time.Now()
			}
			batch.Queue(`INSERT INTO advisories (id, feed, group_key, aliases, summary, severity_level, severity_score,
				severity_vector, severity_source, published, modified, withdrawn, refs, known_exploited, fetched_at, content_hash)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
				  EXISTS (SELECT 1 FROM known_exploited k WHERE k.cve = $3 OR k.cve = ANY($4)), now(), $14)
				ON CONFLICT (id) DO UPDATE SET feed = EXCLUDED.feed, group_key = EXCLUDED.group_key, aliases = EXCLUDED.aliases,
				  summary = EXCLUDED.summary, severity_level = EXCLUDED.severity_level, severity_score = EXCLUDED.severity_score,
				  severity_vector = EXCLUDED.severity_vector, severity_source = EXCLUDED.severity_source,
				  published = EXCLUDED.published, modified = EXCLUDED.modified, withdrawn = EXCLUDED.withdrawn,
				  refs = EXCLUDED.refs, known_exploited = EXCLUDED.known_exploited, fetched_at = now(),
				  content_hash = EXCLUDED.content_hash`,
				r.id, r.feed, r.groupKey, r.aliases, r.summary, r.level, r.score, r.vector, r.source,
				r.published, modified, r.withdrawn, r.refs, r.hash)
			for _, p := range r.rows {
				nID, nBase, nEco, nName, nAff = append(nID, id), append(nBase, p.base), append(nEco, p.ecosystem),
					append(nName, p.name), append(nAff, string(p.affected))
				touched[PackageRef{p.base, p.name}] = true
			}
		}
		if err := tx.SendBatch(ctx, batch).Close(); err != nil {
			return err
		}
		// The package rows that differ: a stored row with no equal new row
		// is deleted, a new row with no equal stored row is inserted, and
		// rows that are the same are left alone. affected is compared as
		// jsonb (key order and spacing do not matter).
		if _, err := tx.Exec(ctx, `WITH n AS MATERIALIZED (
			  SELECT u.id, u.eco, u.name, u.aff::jsonb AS aff FROM unnest($2::text[], $3::text[], $4::text[], $5::text[]) AS u(id, eco, name, aff))
			DELETE FROM advisory_packages p WHERE p.advisory_id = ANY($1)
			  AND NOT EXISTS (SELECT 1 FROM n WHERE n.id = p.advisory_id AND n.eco = p.ecosystem AND n.name = p.name AND n.aff = p.affected)`,
			changed, nID, nEco, nName, nAff); err != nil {
			return err
		}
		if len(nID) > 0 {
			if _, err := tx.Exec(ctx, `INSERT INTO advisory_packages (advisory_id, base_ecosystem, ecosystem, name, affected)
				SELECT u.id, u.base, u.eco, u.name, u.aff::jsonb FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[]) AS u(id, base, eco, name, aff)
				WHERE NOT EXISTS (SELECT 1 FROM advisory_packages p WHERE p.advisory_id = u.id AND p.ecosystem = u.eco
				  AND p.name = u.name AND p.affected = u.aff::jsonb)`,
				nID, nBase, nEco, nName, nAff); err != nil {
				return err
			}
		}
		return addPending(ctx, tx, feed, touched)
	})
	if err != nil {
		return 0, err
	}
	return len(changed), nil
}

// addPending records packages a feed's sync changed, for re-evaluation.
func addPending(ctx context.Context, tx pgx.Tx, feed string, pkgs map[PackageRef]bool) error {
	if len(pkgs) == 0 {
		return nil
	}
	bases, names := make([]string, 0, len(pkgs)), make([]string, 0, len(pkgs))
	for p := range pkgs {
		bases, names = append(bases, p.BaseEcosystem), append(names, p.Name)
	}
	_, err := tx.Exec(ctx, `INSERT INTO feed_pending_packages (feed, base_ecosystem, name)
		SELECT $1, b, n FROM unnest($2::text[], $3::text[]) AS u(b, n)
		WHERE EXISTS (SELECT 1 FROM feeds WHERE name = $1)
		ON CONFLICT DO NOTHING`, feed, bases, names)
	return err
}

// PendingPackages returns the packages a feed's syncs changed since its last
// successful sync: by this sync, and by any earlier attempt that stored
// records and was interrupted or failed before it queued their
// re-evaluation. FeedResult clears them when a sync succeeds.
func (s *Store) PendingPackages(ctx context.Context, feed string) (map[PackageRef]bool, error) {
	rows, err := s.Pool.Query(ctx, `SELECT base_ecosystem, name FROM feed_pending_packages WHERE feed = $1`, feed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[PackageRef]bool{}
	for rows.Next() {
		var p PackageRef
		if err := rows.Scan(&p.BaseEcosystem, &p.Name); err != nil {
			return nil, err
		}
		out[p] = true
	}
	return out, rows.Err()
}
