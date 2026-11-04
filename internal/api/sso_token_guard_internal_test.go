package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// TestCreateTokenUnderRequiredSSO: where the edition says a workspace
// requires single sign-on of a person (editionSSORequiredFor), that
// person's API token cannot make tokens; another person's token can, and
// without the hook (Community) nobody is refused.
func TestCreateTokenUnderRequiredSSO(t *testing.T) {
	st := store.New(testdb.New(t))
	bg := context.Background()
	ws1 := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	held, err := st.CreateUser(ws1, "held@acme.io", "", auth.RoleAdmin, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	free, err := st.CreateUser(ws1, "free@acme.io", "", auth.RoleAdmin, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	_, heldTok, err := st.CreateToken(ws1, "t", auth.RoleAdmin, &held.ID, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, freeTok, err := st.CreateToken(ws1, "t", auth.RoleAdmin, &free.ID, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	holder := &license.Holder{}
	s := &Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Licence: holder, Gate: &license.Gate{Licence: holder}}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	newToken := func(tok string) (int, string) {
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/tokens", strings.NewReader(`{"name":"cli","role":"viewer"}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var e struct {
			Error struct{ Code string }
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return resp.StatusCode, e.Error.Code
	}

	restore := editionSSORequiredFor
	defer func() { editionSSORequiredFor = restore }()
	editionSSORequiredFor = nil
	if code, _ := newToken(heldTok); code != 201 {
		t.Errorf("without the hook: %d", code)
	}
	editionSSORequiredFor = func(_ *Server, _ *http.Request, ws, userID int64) (bool, error) {
		return ws == tenant.DefaultWorkspace && userID == held.ID, nil
	}
	if code, ec := newToken(heldTok); code != 403 || ec != "sso_required" {
		t.Errorf("token of a person single sign-on is required of: %d %q", code, ec)
	}
	if code, _ := newToken(freeTok); code != 201 {
		t.Errorf("token of a person it is not required of: %d", code)
	}
}
