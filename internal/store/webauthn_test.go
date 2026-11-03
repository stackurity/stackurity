package store_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// PasskeyUsed is a compare-and-set on the signature counter: of two
// assertions checked against the same stored counter (both carrying the
// next one), only one is recorded; the other is refused as a clone. An
// authenticator that always reports 0 keeps working.
func TestPasskeyUsedIsCompareAndSet(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	u, err := s.CreateUser(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "ann@x.io", "", auth.RoleViewer, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	rec := func(n uint32) []byte { return fmt.Appendf(nil, `{"authenticator": {"signCount": %d}}`, n) }
	pk, _, err := s.AddPasskey(bg, u.ID, store.NewPasskey{CredentialID: []byte("cred-1"), Name: "Key", Record: rec(10)}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Two uses at the same counter, at once.
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.PasskeyUsed(bg, u.ID, pk.ID, rec(11), 11, false)
		}()
	}
	wg.Wait()
	ok, refused := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, store.ErrPasskeyCounter):
			refused++
		default:
			t.Fatal(err)
		}
	}
	if ok != 1 || refused != 1 {
		t.Fatalf("two uses at counter 11: %d recorded, %d refused (%v)", ok, refused, errs)
	}
	// The same counter again, and one behind: refused. Ahead: recorded.
	for _, n := range []uint32{11, 5} {
		if err := s.PasskeyUsed(bg, u.ID, pk.ID, rec(n), n, false); !errors.Is(err, store.ErrPasskeyCounter) {
			t.Errorf("counter %d after 11: %v", n, err)
		}
	}
	if err := s.PasskeyUsed(bg, u.ID, pk.ID, rec(12), 12, false); err != nil {
		t.Errorf("counter 12 after 11: %v", err)
	}

	// An authenticator without a counter.
	zero, _, err := s.AddPasskey(bg, u.ID, store.NewPasskey{CredentialID: []byte("cred-2"), Name: "No counter", Record: rec(0)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if err := s.PasskeyUsed(bg, u.ID, zero.ID, rec(0), 0, true); err != nil {
			t.Errorf("use %d of a passkey that always reports 0: %v", i, err)
		}
	}

	// Another account's passkey, or none: not found.
	if err := s.PasskeyUsed(bg, u.ID+1000, pk.ID, rec(50), 50, false); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another account's passkey: %v", err)
	}
	// A marked passkey is never recorded as used, whatever its counter.
	if _, err := s.PasskeyCloneWarning(bg, u.ID, pk.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.PasskeyUsed(bg, u.ID, pk.ID, rec(99), 99, false); !errors.Is(err, store.ErrPasskeyCounter) {
		t.Errorf("marked passkey: %v", err)
	}
}

// A clone warning ends the sessions signed in or confirmed with that
// passkey, and only those.
func TestPasskeyCloneWarningEndsItsSessions(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	u, err := s.CreateUser(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "ann@x.io", "", auth.RoleViewer, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	add := func(id string) int64 {
		pk, _, err := s.AddPasskey(bg, u.ID, store.NewPasskey{CredentialID: []byte(id), Name: id, Record: []byte(`{}`)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return pk.ID
	}
	cloned, other := add("cloned"), add("other")
	session := func(opts store.SessionOpts) string {
		sec, err := s.CreateSessionWith(bg, u.ID, tenant.DefaultWorkspace, opts)
		if err != nil {
			t.Fatal(err)
		}
		return sec
	}
	withIt := session(store.SessionOpts{Login: store.LoginPasskey, MFA: store.MFAPasskey, MFACredential: cloned})
	afterPassword := session(store.SessionOpts{Login: store.LoginPassword, MFA: store.MFAPasskey, MFACredential: cloned})
	withOther := session(store.SessionOpts{Login: store.LoginPasskey, MFA: store.MFAPasskey, MFACredential: other})
	withApp := session(store.SessionOpts{Login: store.LoginPassword, MFA: store.MFATOTP})
	ended, err := s.PasskeyCloneWarning(bg, u.ID, cloned)
	if err != nil || ended != 2 {
		t.Fatalf("clone warning: %d sessions ended, %v", ended, err)
	}
	for name, sec := range map[string]string{"with it": withIt, "after a password": afterPassword} {
		if _, err := s.SessionInfo(bg, sec); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("session %s: %v", name, err)
		}
	}
	for name, sec := range map[string]string{"with another passkey": withOther, "with the app": withApp} {
		if _, err := s.SessionInfo(bg, sec); err != nil {
			t.Errorf("session %s: %v", name, err)
		}
	}
	// Another account's passkey id: nothing happens.
	if ended, err := s.PasskeyCloneWarning(bg, u.ID+1000, other); err != nil || ended != 0 {
		t.Errorf("another account's passkey: %d %v", ended, err)
	}
}

// A session with a passkey is not created once the passkey is marked, even
// when its insert races the marking: the insert waits for the marking's
// transaction and then creates nothing, so no session of a possibly copied
// key survives.
func TestSessionWithAMarkedPasskeyIsNotCreated(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	u, err := s.CreateUser(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "ann@x.io", "", auth.RoleViewer, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	pk, _, err := s.AddPasskey(bg, u.ID, store.NewPasskey{CredentialID: []byte("key"), Name: "Key", Record: []byte(`{}`)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	withKey := store.SessionOpts{Login: store.LoginPasskey, MFA: store.MFAPasskey, MFACredential: pk.ID}
	sessions := func() int {
		t.Helper()
		var n int
		if err := s.Pool.QueryRow(bg, `SELECT count(*) FROM sessions WHERE user_id = $1 AND mfa_credential_id = $2`, u.ID, pk.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// The race: the marking's transaction is open when the sign-in's
	// session is inserted.
	tx, err := s.Pool.Begin(bg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(bg, `UPDATE webauthn_credentials SET clone_warning_at = now() WHERE id = $1`, pk.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(bg, `DELETE FROM sessions WHERE user_id = $1 AND mfa_credential_id = $2`, u.ID, pk.ID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.CreateSessionWith(bg, u.ID, tenant.DefaultWorkspace, withKey)
		done <- err
	}()
	time.Sleep(300 * time.Millisecond) // let the insert reach the lock
	if err := tx.Commit(bg); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, store.ErrPasskeyCounter) {
		t.Errorf("session insert racing the marking: %v", err)
	}
	if n := sessions(); n != 0 {
		t.Errorf("%d sessions of the marked passkey survived", n)
	}
	// Once marked, plainly refused; other sessions are unaffected.
	if _, err := s.CreateSessionWith(bg, u.ID, tenant.DefaultWorkspace, withKey); !errors.Is(err, store.ErrPasskeyCounter) {
		t.Errorf("session with a marked passkey: %v", err)
	}
	if _, err := s.CreateSessionWith(bg, u.ID, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginPassword, MFA: store.MFATOTP}); err != nil {
		t.Errorf("session with the app: %v", err)
	}
}
