package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
	"github.com/stackurity/stackurity/internal/webauthntest"
)

// A passkey does not get round an organisation's "Require single sign-on":
// a passwordless session is an ordinary one, refused there like a password
// session, except for the owner's break-glass access, which a passkey may
// use as a password can.
func TestPasswordlessInSSORequiredWorkspace(t *testing.T) {
	const password = "correct horse battery"
	st := store.New(testdb.New(t))
	bg := context.Background()
	ws1 := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	if _, err := st.CreateUser(ws1, "first@x.io", "", auth.RoleAdmin, password); err != nil {
		t.Fatal(err)
	}
	acme, owner, err := st.CreateWorkspace(ws1, "Acme", "acme", "owner@acme.io", "Owner", password)
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.CreateUser(tenant.WithWorkspace(bg, acme.ID), "member@acme.io", "", auth.RoleEngineer, password)
	if err != nil {
		t.Fatal(err)
	}
	holder := &license.Holder{}
	s := &Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Licence: holder, Gate: &license.Gate{Licence: holder},
		BaseURL: "https://stk.example"}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	type client struct{ http *http.Client }
	newClient := func() *client {
		jar, _ := cookiejar.New(nil)
		return &client{http: &http.Client{Jar: jar}}
	}
	do := func(c *client, method, path string, in, out any) int {
		t.Helper()
		var body io.Reader
		if in != nil {
			b, _ := json.Marshal(in)
			body = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, srv.URL+path, body)
		req.Header.Set("X-Stackurity-CSRF", "1")
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if out != nil {
			_ = json.NewDecoder(resp.Body).Decode(out)
		}
		return resp.StatusCode
	}
	// Each person registers a passkey while Acme does not require single
	// sign-on yet.
	keys := map[string]*webauthntest.Authenticator{}
	for _, email := range []string{"owner@acme.io", "member@acme.io"} {
		c := newClient()
		if code := do(c, "POST", "/api/v1/auth/login", map[string]string{"email": email, "password": password}, nil); code != 200 {
			t.Fatalf("login %s: %d", email, code)
		}
		var begin struct{ Options json.RawMessage }
		if code := do(c, "POST", "/api/v1/auth/mfa/passkeys/begin", map[string]string{"password": password}, &begin); code != 200 {
			t.Fatalf("begin %s: %d", email, code)
		}
		a := &webauthntest.Authenticator{Origin: "https://stk.example"}
		cred, _, err := a.Create(begin.Options)
		if err != nil {
			t.Fatal(err)
		}
		if code := do(c, "POST", "/api/v1/auth/mfa/passkeys/finish", map[string]any{"name": "Key", "credential": cred}, nil); code != 200 {
			t.Fatalf("finish %s: %d", email, code)
		}
		keys[email] = a
	}

	// Acme now requires its own single sign-on (as the hosted edition's
	// hook decides), with the owner's break-glass access.
	prev := editionSessionAccess
	defer func() { editionSessionAccess = prev }()
	editionSessionAccess = func(s *Server, r *http.Request, user *store.User, ws, sso int64) *SSORequired {
		if ws == acme.ID && sso != acme.ID && user.ID != owner.ID {
			return &SSORequired{WorkspaceID: acme.ID, WorkspaceName: "Acme", LoginURL: "/sso/acme/login"}
		}
		return nil
	}
	signIn := func(email string) *client {
		t.Helper()
		c := newClient()
		var begin struct{ Options json.RawMessage }
		if code := do(c, "POST", "/api/v1/auth/passkey/begin", nil, &begin); code != 200 {
			t.Fatalf("begin: %d", code)
		}
		cred, err := keys[email].Get(begin.Options, nil)
		if err != nil {
			t.Fatal(err)
		}
		if code := do(c, "POST", "/api/v1/auth/passkey/finish", map[string]any{"credential": cred}, nil); code != 200 {
			t.Fatalf("passwordless %s: %d", email, code)
		}
		return c
	}
	type meResp struct {
		Workspace *struct {
			ID int64 `json:"id"`
		} `json:"workspace"`
		SSORequired *SSORequired `json:"sso_required"`
	}

	m := signIn("member@acme.io")
	var me meResp
	do(m, "GET", "/api/v1/auth/me", nil, &me)
	if me.Workspace != nil || me.SSORequired == nil || me.SSORequired.LoginURL != "/sso/acme/login" {
		t.Errorf("member's passkey session in an SSO-only organisation: %+v %+v", me.Workspace, me.SSORequired)
	}
	if code := do(m, "GET", "/api/v1/assets", nil, nil); code == 200 {
		t.Error("member's passkey session read the organisation's data")
	}

	o := signIn("owner@acme.io")
	me = meResp{}
	do(o, "GET", "/api/v1/auth/me", nil, &me)
	if me.Workspace == nil || me.Workspace.ID != acme.ID || me.SSORequired != nil {
		t.Errorf("owner's break-glass with a passkey: %+v %+v", me.Workspace, me.SSORequired)
	}
	if code := do(o, "GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Errorf("owner's passkey session: %d", code)
	}
}
