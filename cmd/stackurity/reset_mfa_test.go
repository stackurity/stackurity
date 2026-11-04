package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// `stackurity admin reset-mfa` removes a locked-out admin's second factors
// (here a passkey marked as possibly copied, where only passkeys count for
// admins), ends their sessions, and records user.mfa_reset in every
// workspace the account belongs to.
func TestAdminResetMFA(t *testing.T) {
	st := store.New(testdb.New(t))
	bg := context.Background()
	u, err := st.CreateUser(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "ann@x.io", "", auth.RoleAdmin, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateUserInstanceAdmin(bg, "ann@x.io", true); err != nil {
		t.Fatal(err)
	}
	ws, _, err := st.CreateWorkspace(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "Acme", "acme", "boss@acme.io", "Boss", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(tenant.System(bg), `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, 'viewer')`, ws.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetMFAPolicy(bg, tenant.DefaultWorkspace, store.MFAPolicy{Require: store.PolicyAdmins, Methods: []string{"passkey"},
		PhishingResistantAdmins: true}); err != nil {
		t.Fatal(err)
	}
	pk, _, err := st.AddPasskey(bg, u.ID, store.NewPasskey{CredentialID: []byte("cred-1"), Name: "Key", Record: []byte(`{}`)}, [][]byte{[]byte("h")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.PasskeyCloneWarning(bg, u.ID, pk.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSessionWith(bg, u.ID, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginPassword}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := resetMFA(bg, st, "nobody@x.io", &out); err == nil || !strings.Contains(err.Error(), "no account") {
		t.Errorf("unknown address: %v", err)
	}
	if err := resetMFA(bg, st, "ann@x.io", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "ann@x.io") || !strings.Contains(out.String(), "1 sessions ended") ||
		!strings.Contains(out.String(), "recorded in 2 audit logs") {
		t.Errorf("output: %s", out.String())
	}
	if ms, err := st.MFAMethods(bg, u.ID); err != nil || len(ms) != 0 {
		t.Errorf("factors after the reset: %v %v", ms, err)
	}
	var sessions int
	if err := st.Pool.QueryRow(bg, `SELECT count(*) FROM sessions WHERE user_id = $1`, u.ID).Scan(&sessions); err != nil || sessions != 0 {
		t.Errorf("sessions after the reset: %d %v", sessions, err)
	}
	rows, err := st.Pool.Query(tenant.System(bg), `SELECT workspace_id, actor_name FROM audit_events
		WHERE action = 'user.mfa_reset' AND object_id = $1 ORDER BY workspace_id`, fmt.Sprint(u.ID))
	if err != nil {
		t.Fatal(err)
	}
	var got []int64
	for rows.Next() {
		var ws int64
		var actor string
		if err := rows.Scan(&ws, &actor); err != nil {
			t.Fatal(err)
		}
		if actor != "cli" {
			t.Errorf("audited as %q", actor)
		}
		got = append(got, ws)
	}
	if rows.Err() != nil || len(got) != 2 || got[0] != tenant.DefaultWorkspace || got[1] != ws.ID {
		t.Errorf("user.mfa_reset recorded in workspaces %v (%v), want 1 and %d", got, rows.Err(), ws.ID)
	}

	// Nothing left to reset: refused, and not audited again.
	if err := resetMFA(bg, st, "ann@x.io", &out); err == nil || !strings.Contains(err.Error(), "no two-factor sign-in") {
		t.Errorf("second reset: %v", err)
	}
}

// When user.mfa_reset cannot be written, the command fails (exits non-zero)
// and nothing is reset: the record commits with the reset or not at all.
func TestAdminResetMFAFailsClosed(t *testing.T) {
	st := store.New(testdb.New(t))
	bg := context.Background()
	u, err := st.CreateUser(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "ann@x.io", "", auth.RoleAdmin, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.AddPasskey(bg, u.ID, store.NewPasskey{CredentialID: []byte("cred-1"), Name: "Key", Record: []byte(`{}`)}, [][]byte{[]byte("h")}); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := st.Pool.QueryRow(bg, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	owner, err := pgx.Connect(bg, os.Getenv("STACKURITY_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(bg)
	if _, err := owner.Exec(bg, fmt.Sprintf(`CREATE FUNCTION %[1]s.refuse_audit() RETURNS trigger LANGUAGE plpgsql AS
		$$ BEGIN RAISE EXCEPTION 'audit write refused (test)'; END $$;
		CREATE TRIGGER refuse_mfa_reset BEFORE INSERT ON %[1]s.audit_events FOR EACH ROW
		WHEN (NEW.action = 'user.mfa_reset') EXECUTE FUNCTION %[1]s.refuse_audit()`, pgx.Identifier{schema}.Sanitize())); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := resetMFA(bg, st, "ann@x.io", &out); err == nil {
		t.Fatalf("reset-mfa succeeded although its audit record could not be written: %s", out.String())
	}
	if ms, err := st.MFAMethods(bg, u.ID); err != nil || len(ms) != 1 {
		t.Errorf("factors after the failed reset: %v %v; want the passkey kept", ms, err)
	}
}
