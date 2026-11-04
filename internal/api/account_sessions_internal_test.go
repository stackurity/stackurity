package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// A request authenticated before its session was signed out (Your account →
// Active sessions) that then changes the password or a factor gets no new
// session: rotateSession answers 401 through fail and sets no cookie, and
// the account has no session left from it.
func TestRotateSignedOutSession(t *testing.T) {
	st := store.New(testdb.New(t))
	bg := context.Background()
	u, err := st.CreateUser(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "ann@x.io", "", auth.RoleViewer, "Correct horse battery 1!")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	secret, err := st.CreateSessionWith(bg, u.ID, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginPassword})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := st.SessionInfo(bg, secret)
	if err != nil {
		t.Fatal(err)
	}
	p := &Principal{User: sess.User, Session: true, Workspace: sess.Workspace, Login: sess.Login, SessionExpires: sess.ExpiresAt}
	req := httptest.NewRequest("POST", "/api/v1/auth/password", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: secret})
	req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, p))

	// Signed out between authentication and the new ID.
	if err := st.DeleteSession(bg, secret); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	err = s.rotateSession(w, req, store.SessionOpts{Login: p.Login})
	if err == nil {
		t.Fatal("a signed-out session got a new ID")
	}
	s.fail(w, req, err)
	if w.Code != 401 || w.Header().Get("Set-Cookie") != "" {
		t.Errorf("answer %d, Set-Cookie %q", w.Code, w.Header().Get("Set-Cookie"))
	}
	list, err := st.ListSessions(bg, u.ID, "", 0)
	if err != nil || len(list) != 0 {
		t.Errorf("sessions left: %+v %v", list, err)
	}

	// Still signed in: a new cookie, the same public ID.
	secret, err = st.CreateSessionWith(bg, u.ID, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginPassword})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := st.ListSessions(bg, u.ID, secret, 0)
	req = httptest.NewRequest("POST", "/api/v1/auth/password", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: secret})
	req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, p))
	w = httptest.NewRecorder()
	if err := s.rotateSession(w, req, store.SessionOpts{Login: p.Login}); err != nil {
		t.Fatal(err)
	}
	var fresh string
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			fresh = c.Value
		}
	}
	after, _ := st.ListSessions(bg, u.ID, fresh, 0)
	if fresh == "" || fresh == secret || len(before) != 1 || len(after) != 1 || after[0].ID != before[0].ID || !after[0].Current {
		t.Errorf("rotation: cookie %t, before %+v, after %+v", fresh != "", before, after)
	}
}
