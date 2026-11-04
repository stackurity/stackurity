package store_test

import (
	"context"
	"errors"
	"sync"
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
	owner, err := s.CreateUser(a, "owner@a.io", "Owner", auth.RoleAdmin, "Correct horse battery 1!")
	if err != nil {
		t.Fatal(err)
	}
	member, err := s.CreateUser(a, "member@a.io", "Member", auth.RoleEngineer, "Correct horse battery 1!")
	if err != nil {
		t.Fatal(err)
	}
	wsB, adminB, err := s.CreateWorkspace(bg, "B", "", "b@x.io", "", "Correct horse battery 1!")
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

	// Slack accounts linked to people, and a link request not yet confirmed.
	slackLink := func(ws, user int64, slackUser string) {
		t.Helper()
		if _, err := s.Pool.Exec(sys, `INSERT INTO slack_links (workspace_id, team_id, slack_user_id, user_id) VALUES ($1, 'T1', $2, $3)`,
			ws, slackUser, user); err != nil {
			t.Fatal(err)
		}
	}
	slackLink(tenant.DefaultWorkspace, member.ID, "UMEMBER")
	slackLink(tenant.DefaultWorkspace, owner.ID, "UOWNER")
	slackLink(wsB.ID, adminB.ID, "UOTHER")
	if _, err := s.Pool.Exec(sys, `INSERT INTO slack_link_requests (workspace_id, team_id, slack_user_id, token_hash, expires_at)
		VALUES ($1, 'T1', 'UNEW', '\x01', now() + interval '15 minutes')`, tenant.DefaultWorkspace); err != nil {
		t.Fatal(err)
	}
	linked := func(ws int64, slackUser string) bool {
		var n int
		if err := s.Pool.QueryRow(sys, `SELECT count(*) FROM slack_links WHERE workspace_id = $1 AND slack_user_id = $2`, ws, slackUser).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
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
			"member connection": connWorks(memberConn), "owner connection": connWorks(ownerConn), "other workspace's connection": connWorks(otherWSConn),
			"member Slack link": linked(tenant.DefaultWorkspace, "UMEMBER"), "owner Slack link": linked(tenant.DefaultWorkspace, "UOWNER"),
			"other workspace's Slack link": linked(wsB.ID, "UOTHER")}
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
		if err != nil || n != (store.PeopleCredentialsRevoked{APITokens: 2, AssistantConnections: 1, SlackLinks: 1}) {
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
	if n != (store.PeopleCredentialsRevoked{APITokens: 2, AssistantConnections: 1, SlackLinks: 1}) {
		t.Errorf("counts: %+v", n)
	}
	want := map[string]bool{"owner token": true, "member token": false, "member token 2": false, "collector token": true, "CI token": true,
		"other workspace's token": true, "member connection": false, "owner connection": true, "other workspace's connection": true,
		"member Slack link": false, "owner Slack link": true, "other workspace's Slack link": true}
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
	var pending int
	if err := s.Pool.QueryRow(sys, `SELECT count(*) FROM slack_link_requests WHERE used_at IS NULL`).Scan(&pending); err != nil || pending != 0 {
		t.Errorf("Slack link requests left usable: %d %v", pending, err)
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

// TestRevokePeopleCredentialsDuringRedeem: a consent being exchanged for a
// connection while the revocation runs ends revoked too. RedeemOAuthCode
// holds the code's row lock while it makes the connection; the revocation
// waits for it on that row and then sees the new connection.
func TestRevokePeopleCredentialsDuringRedeem(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	sys := tenant.System(bg)
	a := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	member, err := s.CreateUser(a, "member@a.io", "Member", auth.RoleEngineer, "Correct horse battery 1!")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(sys, `INSERT INTO oauth_clients (id, name, redirect_uris) VALUES ('stkc_test', 'Test', '{https://c.example/cb}')`); err != nil {
		t.Fatal(err)
	}
	code, _, _ := auth.NewToken("stko")
	if _, err := s.Pool.Exec(sys, `INSERT INTO oauth_codes (workspace_id, code_hash, client_id, user_id, role, redirect_uri, code_challenge, expires_at)
		VALUES ($1, $2, 'stkc_test', $3, 'viewer', 'https://c.example/cb', $4, now() + interval '2 minutes')`,
		tenant.DefaultWorkspace, auth.HashToken(code), member.ID, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"); err != nil {
		t.Fatal(err)
	}

	// The exchange stops inside its transaction, holding the code's lock.
	// Released at the end whatever happens, so a failure cannot leave the
	// pool waiting for its connection.
	locked, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	t.Cleanup(release)
	type redeemed struct {
		tok *store.OAuthTokens
		err error
	}
	redeem := make(chan redeemed, 1)
	go func() {
		tok, err := s.RedeemOAuthCode(bg, code, func(store.OAuthCode) error {
			close(locked)
			<-resume
			return nil
		})
		redeem <- redeemed{tok, err}
	}()
	<-locked

	type revoked struct {
		n   store.PeopleCredentialsRevoked
		err error
	}
	revoke := make(chan revoked, 1)
	pid := make(chan int32, 1)
	go func() {
		var n store.PeopleCredentialsRevoked
		err := pgx.BeginFunc(a, s.Pool, func(tx pgx.Tx) error {
			var p int32
			if err := tx.QueryRow(a, `SELECT pg_backend_pid()`).Scan(&p); err != nil {
				return err
			}
			pid <- p
			var err error
			n, err = store.RevokePeopleCredentials(a, tx, tenant.DefaultWorkspace, 0)
			return err
		})
		revoke <- revoked{n, err}
	}()
	// The revocation is waiting for a lock (the code's row).
	var revokePID int32
	select {
	case revokePID = <-pid:
	case r := <-revoke:
		t.Fatalf("revocation: %+v %v", r.n, r.err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := s.Pool.QueryRow(sys, `SELECT count(*) FROM pg_locks WHERE pid = $1 AND NOT granted`, revokePID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		select {
		case r := <-revoke:
			t.Fatalf("the revocation did not wait for the exchange: %+v %v", r.n, r.err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the revocation never waited for the exchange")
		}
		time.Sleep(10 * time.Millisecond)
	}
	release()
	rd := <-redeem
	if rd.err != nil {
		t.Fatalf("exchange: %v", rd.err)
	}
	rv := <-revoke
	if rv.err != nil || rv.n.AssistantConnections != 1 {
		t.Fatalf("revocation: %+v %v", rv.n, rv.err)
	}
	if _, _, err := s.AssistantPrincipal(bg, rd.tok.Access); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the connection made during the revocation works: %v", err)
	}
	if _, err := s.RefreshOAuthGrant(bg, rd.tok.Refresh, "stkc_test"); !errors.Is(err, store.ErrOAuthInvalidGrant) {
		t.Errorf("its refresh token: %v", err)
	}
}
