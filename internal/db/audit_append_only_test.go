package db_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// auditEnv is a migrated schema with the application's pool (role
// stackurity_app) and a connection as the login role, which owns the
// tables (a superuser in the tests).
type auditEnv struct {
	pool  *pgxpool.Pool
	s     *store.Store
	owner *pgx.Conn
	wsA   int64
	wsB   int64
}

func newAuditEnv(t *testing.T) *auditEnv {
	t.Helper()
	pool := testdb.New(t)
	bg := context.Background()
	var schema string
	if err := pool.QueryRow(bg, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(os.Getenv("STACKURITY_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = schema
	owner, err := pgx.ConnectConfig(bg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close(context.Background()) })
	e := &auditEnv{pool: pool, s: store.New(pool), owner: owner, wsA: tenant.DefaultWorkspace}
	b, _, err := e.s.CreateWorkspace(bg, "Beta", "", "admin-b@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	e.wsB = b.ID
	return e
}

func (e *auditEnv) audit(t *testing.T, ctx context.Context, action string) int64 {
	t.Helper()
	if err := e.s.Audit(ctx, store.Actor{Type: "user", ID: 7, Name: "ann", RemoteAddr: "192.0.2.1"}, action, "asset", "1",
		map[string]any{"why": "test", "n": 1}); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := e.pool.QueryRow(tenant.System(context.Background()), `SELECT max(id) FROM audit_events`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// verify returns the chains, failing the test when it cannot read.
func (e *auditEnv) verify(t *testing.T, ws *int64) map[int64]store.AuditChain {
	t.Helper()
	chains, err := e.s.VerifyAudit(context.Background(), ws)
	if err != nil {
		t.Fatal(err)
	}
	out := map[int64]store.AuditChain{}
	for _, c := range chains {
		k := int64(0)
		if c.WorkspaceID != nil {
			k = *c.WorkspaceID
		}
		out[k] = c
	}
	return out
}

func (e *auditEnv) ownerExec(t *testing.T, q string, args ...any) error {
	t.Helper()
	_, err := e.owner.Exec(context.Background(), q, args...)
	return err
}

// TestAuditAppendOnlyForApp: the application role cannot change or remove
// audit events, in its workspace or in system scope; what it asks is
// refused by row-level security (nothing matches) and nothing changes.
func TestAuditAppendOnlyForApp(t *testing.T) {
	e := newAuditEnv(t)
	bg := context.Background()
	a := tenant.WithWorkspace(bg, e.wsA)
	id := e.audit(t, a, "test.one")
	for name, ctx := range map[string]context.Context{"workspace": a, "system": tenant.System(bg)} {
		for _, q := range []string{
			`UPDATE audit_events SET action = 'forged' WHERE id = $1`,
			`DELETE FROM audit_events WHERE id = $1`,
		} {
			tag, err := e.pool.Exec(ctx, q, id)
			if err == nil && tag.RowsAffected() != 0 {
				t.Errorf("%s scope: %q changed %d rows", name, q, tag.RowsAffected())
			}
		}
		// The maintenance setting gives the application role nothing.
		err := pgx.BeginFunc(ctx, e.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL stackurity.audit_maintenance = 'on'`); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `DELETE FROM audit_events WHERE id = $1`, id)
			if err == nil && tag.RowsAffected() != 0 {
				return fmt.Errorf("deleted %d rows", tag.RowsAffected())
			}
			return nil
		})
		if err != nil {
			t.Errorf("%s scope with audit_maintenance: %v", name, err)
		}
		if _, err := e.pool.Exec(ctx, `TRUNCATE audit_events`); err == nil {
			t.Errorf("%s scope: TRUNCATE allowed", name)
		}
		// The chain's heads cannot be changed either.
		if tag, err := e.pool.Exec(ctx, `UPDATE audit_chain_heads SET seq = 0`); err == nil && tag.RowsAffected() != 0 {
			t.Errorf("%s scope: heads changed", name)
		}
		if tag, err := e.pool.Exec(ctx, `DELETE FROM audit_chain_heads`); err == nil && tag.RowsAffected() != 0 {
			t.Errorf("%s scope: heads deleted", name)
		}
	}
	var action string
	if err := e.pool.QueryRow(a, `SELECT action FROM audit_events WHERE id = $1`, id).Scan(&action); err != nil || action != "test.one" {
		t.Errorf("event after the attempts: %q %v", action, err)
	}
	// The policies: SELECT and INSERT only.
	rows, err := e.owner.Query(bg, `SELECT polname, polcmd FROM pg_policy WHERE polrelid = 'audit_events'::regclass ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name, cmd string
		if err := rows.Scan(&name, &cmd); err != nil {
			t.Fatal(err)
		}
		if cmd != "r" && cmd != "a" {
			t.Errorf("policy %s on audit_events is for %q, not SELECT or INSERT", name, cmd)
		}
	}
	if verify := e.verify(t, nil); verify[e.wsA].Break != nil || verify[e.wsA].Events != 1 {
		t.Errorf("chain: %+v", verify[e.wsA])
	}
}

// TestAuditGuardForOwner: the table owner (here a superuser, which row-level
// security does not stop) is refused by the trigger unless the transaction
// set the maintenance context.
func TestAuditGuardForOwner(t *testing.T) {
	e := newAuditEnv(t)
	bg := context.Background()
	id := e.audit(t, tenant.WithWorkspace(bg, e.wsA), "test.one")
	e.audit(t, tenant.WithWorkspace(bg, e.wsA), "test.two")
	for _, q := range []string{
		`UPDATE audit_events SET action = 'forged' WHERE id = $1`,
		`DELETE FROM audit_events WHERE id = $1`,
	} {
		err := e.ownerExec(t, q, id)
		if err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("owner %q: %v", q, err)
		}
	}
	if err := e.ownerExec(t, `TRUNCATE audit_events`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("owner TRUNCATE: %v", err)
	}
	// The maintenance context, set for one transaction, allows it; the
	// next transaction is refused again.
	err := pgx.BeginFunc(bg, e.owner, func(tx pgx.Tx) error {
		if _, err := tx.Exec(bg, `SET LOCAL stackurity.audit_maintenance = 'on'`); err != nil {
			return err
		}
		_, err := tx.Exec(bg, `DELETE FROM audit_events WHERE id = $1`, id)
		return err
	})
	if err != nil {
		t.Fatalf("maintenance delete: %v", err)
	}
	if err := e.ownerExec(t, `DELETE FROM audit_events`); err == nil {
		t.Error("the maintenance context outlived its transaction")
	}
	// What maintenance removed shows: the first event of the chain is gone.
	c := e.verify(t, &e.wsA)[e.wsA]
	if c.Break == nil || c.Break.Seq != 2 || !strings.Contains(c.Break.Reason, "missing") {
		t.Errorf("after removing the first event: %+v", c.Break)
	}
}

// TestAuditChainVerifies: events of each workspace and of the platform form
// their own chains, linked in order whatever the inserter wrote into the
// chain columns, and concurrent inserts keep a chain whole.
func TestAuditChainVerifies(t *testing.T) {
	e := newAuditEnv(t)
	bg := context.Background()
	a, b := tenant.WithWorkspace(bg, e.wsA), tenant.WithWorkspace(bg, e.wsB)
	for i := 0; i < 3; i++ {
		e.audit(t, a, "a.event")
		e.audit(t, b, "b.event")
	}
	e.audit(t, bg, "platform.event") // no workspace: the platform's chain
	// An inserter cannot choose its place in the chain.
	if _, err := e.pool.Exec(a, `INSERT INTO audit_events (actor_type, action, chain_seq, prev_hash, hash) VALUES ('user', 'a.forged', 99, 'x', 'y')`); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.s.Audit(b, store.Actor{Type: "system"}, "b.concurrent", "", "", nil); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	chains := e.verify(t, nil)
	if len(chains) != 3 {
		t.Fatalf("chains: %+v", chains)
	}
	for k, want := range map[int64]int64{e.wsA: 4, e.wsB: 23, 0: 1} {
		c := chains[k]
		if c.Break != nil || c.Events != want || c.Unchained != 0 {
			t.Errorf("chain %d: %+v (break %+v), want %d events", k, c, c.Break, want)
		}
	}
	var seq int64
	var prev, hash, payload string
	if err := e.pool.QueryRow(tenant.System(bg), `SELECT chain_seq, prev_hash, hash, stackurity_audit_payload(a) FROM audit_events a
		WHERE action = 'a.forged'`).Scan(&seq, &prev, &hash, &payload); err != nil {
		t.Fatal(err)
	}
	if seq != 4 || len(prev) != 64 || hash != store.AuditHash(prev, payload) {
		t.Errorf("forged chain columns kept: %d %q %q", seq, prev, hash)
	}
	var first string
	if err := e.pool.QueryRow(tenant.System(bg), `SELECT prev_hash FROM audit_events WHERE workspace_id = $1 AND chain_seq = 1`, e.wsB).Scan(&first); err != nil ||
		first != strings.Repeat("0", 64) {
		t.Errorf("first link of a chain: %q %v", first, err)
	}
	// One workspace only.
	if only := e.verify(t, &e.wsB); len(only) != 1 || only[e.wsB].Events != 23 {
		t.Errorf("one workspace: %+v", only)
	}
}

// TestAuditTamperDetected: an event changed, removed in the middle or at
// the end, or taken out of the chain by someone who can bypass the guard
// (a superuser with the triggers disabled) is reported at the first break.
func TestAuditTamperDetected(t *testing.T) {
	bg := context.Background()
	tamper := func(t *testing.T, e *auditEnv, q string, args ...any) {
		t.Helper()
		err := pgx.BeginFunc(bg, e.owner, func(tx pgx.Tx) error {
			if _, err := tx.Exec(bg, `SET LOCAL session_replication_role = replica`); err != nil { // triggers off
				return err
			}
			// Statements separated by ";;" run in order.
			for _, st := range strings.Split(q, ";;") {
				if _, err := tx.Exec(bg, st, args...); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name   string
		q      string
		seq    int64 // where the break is reported
		reason string
		events int64 // verified before it
	}{
		{"detail changed", `UPDATE audit_events SET detail = '{"why":"nothing to see"}' WHERE id = $1`, 3, "was changed", 2},
		{"actor changed", `UPDATE audit_events SET actor_name = 'bob' WHERE id = $1`, 3, "was changed", 2},
		{"time changed", `UPDATE audit_events SET at = at - interval '1 day' WHERE id = $1`, 3, "was changed", 2},
		// Rewriting the event's own hash moves the break to the next event.
		{"hash recomputed", `UPDATE audit_events SET action = 'x' WHERE id = $1;;
			UPDATE audit_events a SET hash = encode(sha256(convert_to(a.prev_hash || stackurity_audit_payload(a), 'UTF8')), 'hex') WHERE id = $1`, 4, "prev_hash", 3},
		{"removed", `DELETE FROM audit_events WHERE id = $1`, 4, "missing", 2},
		{"unchained", `UPDATE audit_events SET chain_seq = NULL, prev_hash = NULL, hash = NULL WHERE id = $1`, 4, "missing", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newAuditEnv(t)
			a := tenant.WithWorkspace(bg, e.wsA)
			var ids []int64
			for i := 0; i < 5; i++ {
				ids = append(ids, e.audit(t, a, fmt.Sprintf("event.%d", i)))
			}
			e.audit(t, tenant.WithWorkspace(bg, e.wsB), "other")
			tamper(t, e, tc.q, ids[2])
			chains := e.verify(t, nil)
			c := chains[e.wsA]
			if c.Break == nil || c.Break.Seq != tc.seq || !strings.Contains(c.Break.Reason, tc.reason) || c.Events != tc.events {
				t.Errorf("break: %+v after %d events", c.Break, c.Events)
			}
			if chains[e.wsB].Break != nil {
				t.Errorf("another workspace's chain: %+v", chains[e.wsB].Break)
			}
		})
	}
	t.Run("newest removed", func(t *testing.T) {
		e := newAuditEnv(t)
		a := tenant.WithWorkspace(bg, e.wsA)
		e.audit(t, a, "one")
		last := e.audit(t, a, "two")
		tamper(t, e, `DELETE FROM audit_events WHERE id = $1`, last)
		c := e.verify(t, &e.wsA)[e.wsA]
		if c.Break == nil || !strings.Contains(c.Break.Reason, "newest events are missing") || c.Events != 1 {
			t.Errorf("break: %+v", c.Break)
		}
	})
}

// TestAuditUnchainedBeforeMigration: events recorded before migration 0052
// (simulated by inserting with the triggers off) are counted, not breaks;
// one recorded so after the chain started is a break.
func TestAuditUnchainedBeforeMigration(t *testing.T) {
	e := newAuditEnv(t)
	bg := context.Background()
	old := func() {
		t.Helper()
		err := pgx.BeginFunc(bg, e.owner, func(tx pgx.Tx) error {
			if _, err := tx.Exec(bg, `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			_, err := tx.Exec(bg, `INSERT INTO audit_events (workspace_id, actor_type, action) VALUES ($1, 'user', 'old')`, e.wsA)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	old()
	old()
	e.audit(t, tenant.WithWorkspace(bg, e.wsA), "new")
	c := e.verify(t, &e.wsA)[e.wsA]
	if c.Break != nil || c.Unchained != 2 || c.Events != 1 {
		t.Errorf("before the chain: %+v %+v", c, c.Break)
	}
	old()
	c = e.verify(t, &e.wsA)[e.wsA]
	if c.Break == nil || !strings.Contains(c.Break.Reason, "not in the chain") {
		t.Errorf("after the chain started: %+v", c.Break)
	}
}

// TestAuditWorkspaceDeletion: deleting a whole workspace removes its events
// (the cascade the guard allows) with no special setting, as a release from
// before migration 0052 does it; its chain goes, the others still verify.
func TestAuditWorkspaceDeletion(t *testing.T) {
	e := newAuditEnv(t)
	bg := context.Background()
	for i := 0; i < 3; i++ {
		e.audit(t, tenant.WithWorkspace(bg, e.wsA), "a")
		e.audit(t, tenant.WithWorkspace(bg, e.wsB), "b")
	}
	if _, err := e.s.DeleteWorkspace(bg, e.wsB, nil); err != nil {
		t.Fatal(err)
	}
	// Recorded after the deletion, as the hosted edition does.
	e.audit(t, bg, "cloud.workspace_deleted")
	var n int
	if err := e.pool.QueryRow(tenant.System(bg), `SELECT (SELECT count(*) FROM audit_events WHERE workspace_id = $1)
		+ (SELECT count(*) FROM audit_chain_heads WHERE workspace_id = $1)`, e.wsB).Scan(&n); err != nil || n != 0 {
		t.Errorf("left of the deleted workspace: %d %v", n, err)
	}
	chains := e.verify(t, nil)
	if _, ok := chains[e.wsB]; ok || len(chains) != 2 || chains[e.wsA].Break != nil || chains[e.wsA].Events != 3 || chains[0].Events != 1 {
		t.Errorf("after deletion: %+v", chains)
	}
	// Deleting one workspace's events while it exists is still refused.
	if err := e.ownerExec(t, `DELETE FROM audit_events WHERE workspace_id = $1`, e.wsA); err == nil {
		t.Error("events of an existing workspace deleted")
	}
}

// TestAuditIsolation: a workspace sees and records only its own events,
// and the chain heads are not readable outside system scope.
func TestAuditIsolation(t *testing.T) {
	e := newAuditEnv(t)
	bg := context.Background()
	a, b := tenant.WithWorkspace(bg, e.wsA), tenant.WithWorkspace(bg, e.wsB)
	e.audit(t, a, "a")
	e.audit(t, b, "b")
	var n int
	if err := e.pool.QueryRow(a, `SELECT count(*) FROM audit_events WHERE workspace_id <> $1`, e.wsA).Scan(&n); err != nil || n != 0 {
		t.Errorf("A sees %d events of others (%v)", n, err)
	}
	if _, err := e.pool.Exec(a, `INSERT INTO audit_events (workspace_id, actor_type, action) VALUES ($1, 'user', 'x')`, e.wsB); err == nil {
		t.Error("A recorded an event in B")
	}
	if err := e.pool.QueryRow(a, `SELECT count(*) FROM audit_chain_heads`).Scan(&n); err != nil || n != 0 {
		t.Errorf("A sees %d chain heads (%v)", n, err)
	}
	if err := e.pool.QueryRow(tenant.System(bg), `SELECT count(*) FROM audit_events`).Scan(&n); err != nil || n != 2 {
		t.Errorf("system scope sees %d events (%v)", n, err)
	}
}
