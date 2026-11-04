package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// TestRevokePeopleCredentials: people's API tokens and assistant
// connections in one workspace stop working; the kept user's, machines'
// (collector and CI tokens) and another workspace's stay; a rollback
// leaves everything as it was.
func TestRevokePeopleCredentials(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	sys := tenant.System(bg)
	a := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	owner, err := s.CreateUser(a, "owner@a.io", "Owner", auth.RoleAdmin, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	member, err := s.CreateUser(a, "member@a.io", "Member", auth.RoleEngineer, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	wsB, adminB, err := s.CreateWorkspace(bg, "B", "", "b@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	b := tenant.WithWorkspace(bg, wsB.ID)

	token := func(ctx context.Context, role auth.Role, user *int64) string {
		t.Helper()
		_, secret, err := s.CreateToken(ctx, "t", role, user, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		return secret
	}
	ownerTok := token(a, auth.RoleAdmin, &owner.ID)
	memberTok := token(a, auth.RoleEngineer, &member.ID)
	memberTok2 := token(a, auth.RoleViewer, &member.ID)
	collectorTok := token(a, auth.RoleCollector, nil)
	otherWSTok := token(b, auth.RoleAdmin, &adminB.ID)
	trust, err := s.CreateCITrust(a, store.CITrust{Name: "ci", Provider: "github", Issuer: "https://token.actions.githubusercontent.com",
		Repository: "acme/app"})
	if err != nil {
		t.Fatal(err)
	}
	_, ciTok, err := s.IssueCIToken(bg, *trust, store.CIToken{Name: "job", RepositoryURL: "https://github.com/acme/app", TTL: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.Pool.Exec(sys, `INSERT INTO oauth_clients (id, name, redirect_uris) VALUES ('stkc_test', 'Test', '{https://c.example/cb}')`); err != nil {
		t.Fatal(err)
	}
	type conn struct{ access, refresh string }
	connect := func(ws, user int64) conn {
		t.Helper()
		access, _, _ := auth.NewToken("stka")
		refresh, _, _ := auth.NewToken("stkr")
		var id int64
		if err := s.Pool.QueryRow(sys, `INSERT INTO oauth_grants (workspace_id, client_id, user_id, role, refresh_hash, refresh_expires_at)
			VALUES ($1, 'stkc_test', $2, 'viewer', $3, now() + interval '1 day') RETURNING id`, ws, user, auth.HashToken(refresh)).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Pool.Exec(sys, `INSERT INTO oauth_access_tokens (token_hash, workspace_id, grant_id, expires_at)
			VALUES ($1, $2, $3, now() + interval '1 hour')`, auth.HashToken(access), ws, id); err != nil {
			t.Fatal(err)
		}
		return conn{access, refresh}
	}
	memberConn := connect(tenant.DefaultWorkspace, member.ID)
	ownerConn := connect(tenant.DefaultWorkspace, owner.ID)
	otherWSConn := connect(wsB.ID, adminB.ID)
	// A consent the member gave but the assistant has not exchanged yet.
	code, _, _ := auth.NewToken("stko")
	if _, err := s.Pool.Exec(sys, `INSERT INTO oauth_codes (workspace_id, code_hash, client_id, user_id, role, redirect_uri, code_challenge, expires_at)
		VALUES ($1, $2, 'stkc_test', $3, 'viewer', 'https://c.example/cb', $4, now() + interval '2 minutes')`,
		tenant.DefaultWorkspace, auth.HashToken(code), member.ID, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"); err != nil {
		t.Fatal(err)
	}

	tokenWorks := func(secret string) bool {
		_, _, err := s.TokenPrincipal(bg, secret)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		return err == nil
	}
	connWorks := func(c conn) bool {
		_, _, err := s.AssistantPrincipal(bg, c.access)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		return err == nil
	}
	everything := func() map[string]bool {
		return map[string]bool{"owner token": tokenWorks(ownerTok), "member token": tokenWorks(memberTok), "member token 2": tokenWorks(memberTok2),
			"collector token": tokenWorks(collectorTok), "CI token": tokenWorks(ciTok), "other workspace's token": tokenWorks(otherWSTok),
			"member connection": connWorks(memberConn), "owner connection": connWorks(ownerConn), "other workspace's connection": connWorks(otherWSConn)}
	}
	for what, ok := range everything() {
		if !ok {
			t.Fatalf("before: %s does not work", what)
		}
	}

	// Scoped to the workspace only: system scope, another workspace or a
	// narrowed scope is refused.
	for _, ctx := range []context.Context{sys, b, tenant.WithProject(a, 1)} {
		err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
			_, err := store.RevokePeopleCredentials(ctx, tx, tenant.DefaultWorkspace, owner.ID)
			return err
		})
		if err == nil {
			t.Error("revoked outside the workspace's own scope")
		}
	}

	// Rolled back with the change that called for it: nothing changes.
	boom := errors.New("boom")
	err = pgx.BeginFunc(a, s.Pool, func(tx pgx.Tx) error {
		n, err := store.RevokePeopleCredentials(a, tx, tenant.DefaultWorkspace, owner.ID)
		if err != nil || n.APITokens != 2 || n.AssistantConnections != 1 {
			t.Errorf("in the rolled-back transaction: %+v %v", n, err)
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	for what, ok := range everything() {
		if !ok {
			t.Errorf("after a rollback: %s does not work", what)
		}
	}

	var n store.PeopleCredentialsRevoked
	if err := pgx.BeginFunc(a, s.Pool, func(tx pgx.Tx) error {
		var err error
		n, err = store.RevokePeopleCredentials(a, tx, tenant.DefaultWorkspace, owner.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n.APITokens != 2 || n.AssistantConnections != 1 {
		t.Errorf("counts: %+v", n)
	}
	want := map[string]bool{"owner token": true, "member token": false, "member token 2": false, "collector token": true, "CI token": true,
		"other workspace's token": true, "member connection": false, "owner connection": true, "other workspace's connection": true}
	for what, ok := range everything() {
		if ok != want[what] {
			t.Errorf("after revoking: %s works = %v, want %v", what, ok, want[what])
		}
	}
	// The connection's refresh token is gone too, and the pending consent
	// cannot make a new connection.
	if _, err := s.RefreshOAuthGrant(bg, memberConn.refresh, "stkc_test"); !errors.Is(err, store.ErrOAuthInvalidGrant) {
		t.Errorf("member's refresh token: %v", err)
	}
	if _, err := s.RefreshOAuthGrant(bg, ownerConn.refresh, "stkc_test"); err != nil {
		t.Errorf("owner's refresh token: %v", err)
	}
	if _, err := s.RedeemOAuthCode(bg, code, func(store.OAuthCode) error { return nil }); !errors.Is(err, store.ErrOAuthInvalidGrant) {
		t.Errorf("pending consent: %v", err)
	}
	var reason string
	if err := s.Pool.QueryRow(sys, `SELECT revoked_reason FROM oauth_grants WHERE user_id = $1`, member.ID).Scan(&reason); err != nil ||
		reason != "single sign-on required" {
		t.Errorf("revoked reason: %q %v", reason, err)
	}
	// Again: nothing left to revoke.
	if err := pgx.BeginFunc(a, s.Pool, func(tx pgx.Tx) error {
		var err error
		n, err = store.RevokePeopleCredentials(a, tx, tenant.DefaultWorkspace, owner.ID)
		return err
	}); err != nil || n != (store.PeopleCredentialsRevoked{}) {
		t.Errorf("second time: %+v %v", n, err)
	}
}
