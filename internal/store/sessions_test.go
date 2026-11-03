package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Your account → Active sessions: a person sees and signs out their own
// sessions only, by an ID that is not the token, and a signed-out session
// stops working at once.
func TestActiveSessions(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	ws := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	ann, err := s.CreateUser(ws, "ann@x.io", "", auth.RoleViewer, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := s.CreateUser(ws, "bob@x.io", "", auth.RoleViewer, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	laptop := store.WithSessionClient(bg, store.SessionClient{UserAgent: "Mozilla/5.0 (Macintosh) Firefox/140.0\x00\n", IP: "203.0.113.7"})
	mine, err := s.CreateSessionWith(laptop, ann.ID, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginPassword, MFA: store.MFATOTP})
	if err != nil {
		t.Fatal(err)
	}
	phone, err := s.CreateSessionWith(store.WithSessionClient(bg, store.SessionClient{UserAgent: strings.Repeat("x", 2000), IP: "198.51.100.2"}),
		ann.ID, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginPasskey})
	if err != nil {
		t.Fatal(err)
	}
	third, err := s.CreateSession(bg, ann.ID, tenant.DefaultWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	bobs, err := s.CreateSession(bg, bob.ID, tenant.DefaultWorkspace)
	if err != nil {
		t.Fatal(err)
	}

	list, err := s.ListSessions(bg, ann.ID, mine, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("ann's sessions: %+v", list)
	}
	byIP := map[string]store.ActiveSession{}
	current := 0
	for _, a := range list {
		byIP[a.IP] = a
		if a.Current {
			current++
		}
		if a.ID == "" || strings.Contains(a.ID, mine) || a.ID == string(auth.HashToken(mine)) {
			t.Errorf("session ID %q", a.ID)
		}
	}
	got := byIP["203.0.113.7"]
	if current != 1 || !got.Current || got.UserAgent != "Mozilla/5.0 (Macintosh) Firefox/140.0" || got.LoginMethod != "password" || got.MFAMethod != "totp" {
		t.Errorf("this session: %+v", got)
	}
	if p := byIP["198.51.100.2"]; len(p.UserAgent) != 512 || p.LoginMethod != "passkey" || p.Current {
		t.Errorf("phone: %+v", p)
	}
	if u := byIP[""]; u.UserAgent != "" || u.SignedInAt.IsZero() || u.LastSeenAt.IsZero() {
		t.Errorf("session with no client: %+v", u)
	}

	// Bob's list has his only; Bob cannot end Ann's session, by any ID.
	if bl, err := s.ListSessions(bg, bob.ID, bobs, 0); err != nil || len(bl) != 1 || !bl[0].Current {
		t.Fatalf("bob's sessions: %+v %v", bl, err)
	}
	phoneID := byIP["198.51.100.2"].ID
	for _, id := range []string{phoneID, strings.ToUpper(phoneID), "not-a-uuid", "", "00000000-0000-0000-0000-000000000000"} {
		if _, err := s.RevokeSession(bg, bob.ID, id, bobs, 0); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob ends %q: %v", id, err)
		}
	}
	if _, err := s.SessionInfo(bg, phone); err != nil {
		t.Fatalf("ann's phone after bob's attempts: %v", err)
	}

	// The current session is not ended by ID.
	if _, err := s.RevokeSession(bg, ann.ID, got.ID, mine, 0); !errors.Is(err, store.ErrCurrentSession) {
		t.Errorf("ending this session by ID: %v", err)
	}
	ended, err := s.RevokeSession(bg, ann.ID, phoneID, mine, 0)
	if err != nil || ended.ID != phoneID || ended.LoginMethod != "passkey" || ended.Workspace != tenant.DefaultWorkspace {
		t.Fatalf("ending the phone: %+v %v", ended, err)
	}
	if _, err := s.SessionInfo(bg, phone); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the phone's session after it was ended: %v", err)
	}
	if _, err := s.RevokeSession(bg, ann.ID, phoneID, mine, 0); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("ending it twice: %v", err)
	}

	// All others: Ann keeps this one; Bob keeps his.
	if _, err := s.RevokeOtherSessions(bg, ann.ID, "", 0); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("all others without a current session: %v", err)
	}
	if n, err := s.RevokeOtherSessions(bg, ann.ID, mine, 0); err != nil || n != 1 {
		t.Fatalf("all others: %d %v", n, err)
	}
	if _, err := s.SessionInfo(bg, third); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("third session after all others: %v", err)
	}
	for _, sec := range []string{mine, bobs} {
		if _, err := s.SessionInfo(bg, sec); err != nil {
			t.Errorf("kept session: %v", err)
		}
	}

	// A new ID for the same sign-in keeps when and where it was signed in.
	elsewhere := store.WithSessionClient(bg, store.SessionClient{UserAgent: "curl/8", IP: "192.0.2.9"})
	rotated, err := s.CreateSessionWith(elsewhere, ann.ID, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginPassword, Replaces: mine})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(bg, mine); err != nil {
		t.Fatal(err)
	}
	list, err = s.ListSessions(bg, ann.ID, rotated, 0)
	if err != nil || len(list) != 1 {
		t.Fatalf("after a new ID: %+v %v", list, err)
	}
	if r := list[0]; !r.Current || r.IP != "203.0.113.7" || !r.SignedInAt.Equal(got.SignedInAt) || r.ID == got.ID {
		t.Errorf("replaced session: %+v, was %+v", r, got)
	}
	// Replacing another person's session copies nothing of it.
	stolen, err := s.CreateSessionWith(elsewhere, ann.ID, tenant.DefaultWorkspace, store.SessionOpts{Replaces: bobs})
	if err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListSessions(bg, ann.ID, stolen, 0)
	for _, a := range list {
		if a.Current && a.IP != "192.0.2.9" {
			t.Errorf("replacing bob's session: %+v", a)
		}
	}
}

// A session pinned by an organisation's single sign-on sees and ends only
// the sessions pinned to that organisation; an ordinary session sees all.
func TestActiveSessionsPinned(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	ws := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	ann, err := s.CreateUser(ws, "ann@x.io", "", auth.RoleViewer, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := s.CreateWorkspace(bg, "Other Org", "", "owner@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(tenant.System(bg), `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, 'viewer')`, other.ID, ann.ID); err != nil {
		t.Fatal(err)
	}
	plain, err := s.CreateSession(bg, ann.ID, tenant.DefaultWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := s.CreateSSOSession(bg, ann.ID, other.ID)
	if err != nil {
		t.Fatal(err)
	}
	pinned2, err := s.CreateSSOSession(bg, ann.ID, other.ID)
	if err != nil {
		t.Fatal(err)
	}

	all, err := s.ListSessions(bg, ann.ID, plain, 0)
	if err != nil || len(all) != 3 {
		t.Fatalf("from the ordinary session: %+v %v", all, err)
	}
	var plainID string
	for _, a := range all {
		if a.Current {
			plainID = a.ID
		} else if a.Organisation != "Other Org" || a.LoginMethod != "sso" {
			t.Errorf("pinned session listed as %+v", a)
		}
	}
	mine, err := s.ListSessions(bg, ann.ID, pinned, other.ID)
	if err != nil || len(mine) != 2 {
		t.Fatalf("from the pinned session: %+v %v", mine, err)
	}
	for _, a := range mine {
		if a.ID == plainID {
			t.Error("the pinned session sees the ordinary one")
		}
	}
	if _, err := s.RevokeSession(bg, ann.ID, plainID, pinned, other.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the pinned session ends the ordinary one: %v", err)
	}
	if n, err := s.RevokeOtherSessions(bg, ann.ID, pinned, other.ID); err != nil || n != 1 {
		t.Fatalf("all others from the pinned session: %d %v", n, err)
	}
	if _, err := s.SessionInfo(bg, plain); err != nil {
		t.Errorf("ordinary session after the pinned one ended its others: %v", err)
	}
	if _, err := s.SessionInfo(bg, pinned2); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second pinned session: %v", err)
	}
}
