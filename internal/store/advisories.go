package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
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

// StoredAffected is what is stored of an OSV affected entry (in
// affected_values, referenced from advisory_packages.affected_hash): the
// ranges and the listed versions. They are all that is read back
// from it: by the matcher (osv.Check, and the fix it reports from every
// range's "fixed" events), by the second check (internal/secondcheck reads
// ranges and versions) and by the explanation, which the matcher stores
// with the finding. The package is in the row's own columns; severities,
// ecosystem_specific and database_specific are read once, when the record
// is synced, to rate the advisory (osv.Rate), and the rating is stored on
// the advisory.
//
// Identical values are stored once: most entries repeat across releases and
// advisories (an Ubuntu record lists the same versions for each channel).
// Rows written by earlier versions keep the whole entry in
// advisory_packages.affected until their advisory is next stored; they read
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
	hash                  []byte // affectedHash(affected)
}

// affectedHash identifies a stored affected value.
func affectedHash(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:16]
}

// affectedLock is a transaction-level advisory lock between writers of
// package rows (shared) and PruneAffectedValues (exclusive), so a value is
// never pruned while a sync is about to reference it.
const affectedLock = 0x5354_4b41_4646 // "STKAFF"

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
			aff := CompactAffected(a)
			row := packageRow{osv.BaseEcosystem(a.Package.Ecosystem), a.Package.Ecosystem, osv.PackageName(a.Package.Ecosystem, a.Package.Name), aff, affectedHash(aff)}
			// An identical entry listed twice matches the same way once.
			k := row.ecosystem + "\x00" + row.name + "\x00" + string(row.affected)
			if seen[k] {
				continue
			}
			seen[k] = true
			rec.rows = append(rec.rows, row)
		}
	}
	// The rows keep the order the feed lists them in: they are inserted
	// in it, and AdvisoriesFor reads a package's rows in stored order.
	rec.hash = rec.contentHash()
	return rec
}

// contentHash covers everything stored for the advisory except what other
// feeds maintain (known_exploited, from the KEV catalogue), the time it was
// stored and the feed that stored it. Two records with the same hash store
// the same rows. An advisory that covers packages in several ecosystems is
// in each of their OSV archives; leaving the feed out keeps the syncs of
// those feeds from rewriting it in turn. Its feed is the one that last
// changed it (the column is shown with the advisory; matching uses the
// feed of the installed package's ecosystem).
func (r *advisoryRecord) contentHash() string {
	h := sha256.New()
	// In a fixed order: listing the same entries in another order is not a
	// change (the stored rows keep their order).
	rows := make([][4]string, len(r.rows))
	for i, p := range r.rows {
		rows[i] = [4]string{p.base, p.ecosystem, p.name, string(p.affected)}
	}
	sort.Slice(rows, func(i, j int) bool {
		for k := range rows[i] {
			if rows[i][k] != rows[j][k] {
				return rows[i][k] < rows[j][k]
			}
		}
		return false
	})
	_ = json.NewEncoder(h).Encode([]any{storedFormat, r.id, r.groupKey, r.aliases, r.summary, r.level, r.score,
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
// recorded as pending in the same transaction; the sync of each package's
// ecosystem hands them to re-evaluation and clears them when it completes
// (PendingPackages, ClearPending). A record stored by an interrupted sync is
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
		var nHash [][]byte
		// The advisory rows are locked in id order, so two syncs storing
		// overlapping advisories (an advisory in the npm and the PyPI
		// archive) wait for each other instead of deadlocking. The package
		// rows below keep the order the feed lists the records in.
		locking := slices.Clone(changed)
		slices.Sort(locking)
		for _, id := range locking {
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
		}
		for _, id := range changed {
			for _, p := range byID[id].rows {
				nID, nBase, nEco, nName, nAff = append(nID, id), append(nBase, p.base), append(nEco, p.ecosystem),
					append(nName, p.name), append(nAff, string(p.affected))
				nHash = append(nHash, p.hash)
				touched[PackageRef{p.base, p.name}] = true
			}
		}
		if err := tx.SendBatch(ctx, batch).Close(); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, affectedLock); err != nil {
			return err
		}
		if len(nID) > 0 {
			if _, err := tx.Exec(ctx, `INSERT INTO affected_values (hash, affected)
				SELECT DISTINCT ON (u.hash) u.hash, u.aff::jsonb FROM unnest($1::bytea[], $2::text[]) AS u(hash, aff)
				ORDER BY u.hash
				ON CONFLICT (hash) DO NOTHING`, nHash, nAff); err != nil {
				return err
			}
		}
		// The package rows that differ: a stored row with no equal new row
		// is deleted, a new row with no equal stored row is inserted, and
		// rows that are the same are left alone. A row written by an earlier
		// version (no hash) is never equal, so it is rewritten in the
		// current form.
		if _, err := tx.Exec(ctx, `WITH n AS MATERIALIZED (
			  SELECT u.id, u.eco, u.name, u.hash FROM unnest($2::text[], $3::text[], $4::text[], $5::bytea[]) AS u(id, eco, name, hash))
			DELETE FROM advisory_packages p WHERE p.advisory_id = ANY($1)
			  AND NOT EXISTS (SELECT 1 FROM n WHERE n.id = p.advisory_id AND n.eco = p.ecosystem AND n.name = p.name AND n.hash = p.affected_hash)`,
			changed, nID, nEco, nName, nHash); err != nil {
			return err
		}
		if len(nID) > 0 {
			// ORDER BY: an anti-join plan may return the rows in another
			// order, and the stored order is the order they are read in.
			if _, err := tx.Exec(ctx, `INSERT INTO advisory_packages (advisory_id, base_ecosystem, ecosystem, name, affected_hash)
				SELECT u.id, u.base, u.eco, u.name, u.hash
				FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::bytea[]) WITH ORDINALITY AS u(id, base, eco, name, hash, ord)
				WHERE NOT EXISTS (SELECT 1 FROM advisory_packages p WHERE p.advisory_id = u.id AND p.ecosystem = u.eco
				  AND p.name = u.name AND p.affected_hash = u.hash)
				ORDER BY u.ord`,
				nID, nBase, nEco, nName, nHash); err != nil {
				return err
			}
		}
		return addPending(ctx, tx, touched)
	})
	if err != nil {
		return 0, err
	}
	return len(changed), nil
}

// addPending records packages whose advisory data changed, for
// re-evaluation by the sync of their ecosystem's feed.
func addPending(ctx context.Context, tx pgx.Tx, pkgs map[PackageRef]bool) error {
	if len(pkgs) == 0 {
		return nil
	}
	bases, names := make([]string, 0, len(pkgs)), make([]string, 0, len(pkgs))
	for p := range pkgs {
		bases, names = append(bases, p.BaseEcosystem), append(names, p.Name)
	}
	// In a fixed order, so concurrent syncs touching the same packages
	// (through different advisories) lock their rows in the same order.
	_, err := tx.Exec(ctx, `INSERT INTO pending_packages (base_ecosystem, name)
		SELECT b, n FROM unnest($1::text[], $2::text[]) AS u(b, n) ORDER BY b, n
		ON CONFLICT (base_ecosystem, name) DO UPDATE SET added_at = clock_timestamp()`, bases, names)
	return err
}

// Pending is the set of packages of one ecosystem waiting for
// re-evaluation, as read by PendingPackages.
type Pending struct {
	Packages map[PackageRef]bool
	names    []string
	added    []time.Time
}

// PendingPackages returns the packages of a base ecosystem whose advisory
// data changed since they were last handed to re-evaluation: by the current
// sync, by an earlier attempt that stored records and was interrupted or
// failed before it queued their re-evaluation, or by another feed's sync
// that stored an advisory also covering this ecosystem.
func (s *Store) PendingPackages(ctx context.Context, base string) (*Pending, error) {
	rows, err := s.Pool.Query(ctx, `SELECT name, added_at FROM pending_packages WHERE base_ecosystem = $1`, base)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	p := &Pending{Packages: map[PackageRef]bool{}}
	for rows.Next() {
		var n string
		var at time.Time
		if err := rows.Scan(&n, &at); err != nil {
			return nil, err
		}
		p.Packages[PackageRef{base, n}] = true
		p.names, p.added = append(p.names, n), append(p.added, at)
	}
	return p, rows.Err()
}

// ClearPending removes the pending packages that were read, once their
// re-evaluation is queued. A package changed again since it was read (a
// later added_at) stays pending.
func (s *Store) ClearPending(ctx context.Context, base string, p *Pending) error {
	if p == nil || len(p.names) == 0 {
		return nil
	}
	_, err := s.Pool.Exec(ctx, `DELETE FROM pending_packages x USING unnest($2::text[], $3::timestamptz[]) AS u(name, added_at)
		WHERE x.base_ecosystem = $1 AND x.name = u.name AND x.added_at = u.added_at`, base, p.names, p.added)
	return err
}

// PruneAffectedValues deletes stored affected values no package row
// references any more (their advisories changed or were withdrawn). It
// reads the whole advisory_packages table once, so it runs daily, not with
// every sync, and it waits for syncs that are writing package rows.
func (s *Store) PruneAffectedValues(ctx context.Context) (int64, error) {
	var n int64
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, affectedLock); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM affected_values v
			WHERE NOT EXISTS (SELECT 1 FROM advisory_packages p WHERE p.affected_hash = v.hash)`)
		n = tag.RowsAffected()
		return err
	})
	return n, err
}
