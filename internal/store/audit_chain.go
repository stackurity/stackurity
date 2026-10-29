package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// The audit log is a hash chain per workspace, plus one for platform
// events (migration 0052, docs/security-audit.md "Audit log"). The insert
// trigger links each new event: chain_seq counts from 1, prev_hash is the
// previous event's hash (64 zeros for the first) and
// hash = sha256(prev_hash || payload) in hex, where payload is
// stackurity_audit_payload, the event's canonical text. Events recorded
// before migration 0052 are not in a chain.

// auditGenesis is the prev_hash of the first event of a chain.
var auditGenesis = strings.Repeat("0", 64)

// AuditChain is the verification of one chain.
type AuditChain struct {
	// WorkspaceID is nil for the platform's own events.
	WorkspaceID *int64 `json:"workspace_id"`
	// Events is how many chained events were checked up to the first
	// break, or in all when there is none.
	Events  int64 `json:"events"`
	FirstID int64 `json:"first_id,omitempty"`
	LastID  int64 `json:"last_id,omitempty"`
	// Unchained events were recorded before the chain started.
	Unchained int64 `json:"unchained"`
	// Break is the first place the chain does not hold, nil when it does.
	Break *AuditBreak `json:"break,omitempty"`
}

// AuditBreak says where a chain stops holding and why.
type AuditBreak struct {
	EventID int64  `json:"event_id,omitempty"` // 0 when no event is at fault (the newest are missing)
	Seq     int64  `json:"seq"`
	Reason  string `json:"reason"`
}

// VerifyAudit checks every audit chain, or only workspace ws's when ws is
// not nil (0 for the platform's events), and returns one result per chain
// in workspace order (platform first). It reads one snapshot, so events
// recorded meanwhile do not show as breaks. It reports what it found; an
// error means it could not read.
func (s *Store) VerifyAudit(ctx context.Context, ws *int64) ([]AuditChain, error) {
	sys := tenant.System(ctx)
	var out []AuditChain
	err := pgx.BeginTxFunc(sys, s.Pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		rows, err := tx.Query(sys, `SELECT k FROM (
				SELECT DISTINCT COALESCE(workspace_id, 0) AS k FROM audit_events
				UNION SELECT COALESCE(workspace_id, 0) FROM audit_chain_heads) c
			WHERE $1::bigint IS NULL OR k = $1 ORDER BY k`, ws)
		if err != nil {
			return err
		}
		keys, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			return err
		}
		// Unchained events per chain, in one pass: those from before the
		// chain started are expected; one recorded after it started had its
		// chain columns cleared, or was written with the triggers disabled.
		rows, err = tx.Query(sys, `SELECT COALESCE(a.workspace_id, 0), count(*), COALESCE(min(a.id) FILTER (WHERE a.id >= h.first_id), 0)
			FROM audit_events a LEFT JOIN audit_chain_heads h ON COALESCE(h.workspace_id, 0) = COALESCE(a.workspace_id, 0)
			WHERE a.chain_seq IS NULL AND ($1::bigint IS NULL OR COALESCE(a.workspace_id, 0) = $1) GROUP BY 1`, ws)
		if err != nil {
			return err
		}
		unchained := map[int64][2]int64{}
		var k, n, late int64
		if _, err := pgx.ForEachRow(rows, []any{&k, &n, &late}, func() error {
			unchained[k] = [2]int64{n, late}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range keys {
			c, err := verifyChain(sys, tx, k, unchained[k][0], unchained[k][1])
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return nil
	})
	return out, err
}

// verifyChain walks chain key; late is the first unchained event recorded
// after the chain started, 0 when there is none.
func verifyChain(ctx context.Context, tx pgx.Tx, key, unchained, late int64) (AuditChain, error) {
	c := AuditChain{Unchained: unchained}
	if key != 0 {
		k := key
		c.WorkspaceID = &k
	}
	var headSeq int64
	var headHash string
	err := tx.QueryRow(ctx, `SELECT seq, hash FROM audit_chain_heads WHERE COALESCE(workspace_id, 0) = $1`, key).Scan(&headSeq, &headHash)
	hasHead := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return c, err
	}

	rows, err := tx.Query(ctx, `SELECT a.id, a.chain_seq, COALESCE(a.prev_hash, ''), COALESCE(a.hash, ''), stackurity_audit_payload(a)
		FROM audit_events a WHERE COALESCE(a.workspace_id, 0) = $1 AND a.chain_seq IS NOT NULL ORDER BY a.chain_seq`, key)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	prev := auditGenesis
	var seq int64
	for rows.Next() {
		var id, s int64
		var prevHash, hash, payload string
		if err := rows.Scan(&id, &s, &prevHash, &hash, &payload); err != nil {
			return c, err
		}
		switch {
		case s != seq+1:
			c.Break = &AuditBreak{EventID: id, Seq: s, Reason: fmt.Sprintf("events %d to %d of the chain are missing", seq+1, s-1)}
		case prevHash != prev:
			c.Break = &AuditBreak{EventID: id, Seq: s, Reason: "prev_hash does not match the previous event's hash: an event before it was changed or removed"}
		case hash != AuditHash(prevHash, payload):
			c.Break = &AuditBreak{EventID: id, Seq: s, Reason: "hash does not match the event's content: the event was changed"}
		}
		if c.Break != nil {
			rows.Close()
			return c, nil
		}
		if c.FirstID == 0 {
			c.FirstID = id
		}
		c.LastID = id
		c.Events++
		seq, prev = s, hash
	}
	if err := rows.Err(); err != nil {
		return c, err
	}
	switch {
	case late > 0:
		c.Break = &AuditBreak{EventID: late, Reason: "an event recorded after the chain started is not in the chain"}
	case !hasHead && seq > 0:
		c.Break = &AuditBreak{Seq: seq, Reason: "the chain's head record is missing"}
	case hasHead && (headSeq != seq || headHash != prev):
		c.Break = &AuditBreak{Seq: seq + 1, Reason: fmt.Sprintf("the chain ends at event %d but %d were recorded: the newest events are missing or changed", seq, headSeq)}
	}
	return c, nil
}

// AuditHash is an event's hash: sha256 of the previous event's hash and
// the event's canonical text, in hex.
func AuditHash(prevHash, payload string) string {
	sum := sha256.Sum256([]byte(prevHash + payload))
	return hex.EncodeToString(sum[:])
}
