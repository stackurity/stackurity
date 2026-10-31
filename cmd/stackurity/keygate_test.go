package main

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// stackurity scan (as CI and the GitHub scan action run it) works against a
// self-hosted server that has no key yet: the upload is accepted and kept,
// with --project too.
func TestScanWithoutKey(t *testing.T) {
	st := store.New(testdb.New(t))
	holder := &license.Holder{}
	req := &license.Requirement{From: time.Now().Add(-time.Hour), Licence: holder}
	s := &api.Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test",
		Licence: holder, Gate: &license.Gate{Licence: holder}, KeyRequirement: req}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	if !req.Blocked() {
		t.Fatal("the server should be waiting for its key")
	}

	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	p, err := st.CreateProject(ctx, "Payments", "")
	if err != nil {
		t.Fatal(err)
	}
	// Filing uploads in a project takes an admin token (or a collector
	// token made for the project), which also reads the project by name.
	_, secret, err := st.CreateToken(ctx, "ci", auth.RoleAdmin, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, collector, err := st.CreateToken(ctx, "action", auth.RoleCollector, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STACKURITY_SERVER", srv.URL)
	t.Setenv("STACKURITY_PROJECT", "")
	run := func(token string, args ...string) error {
		t.Setenv("STACKURITY_TOKEN", token)
		cmd := scanCmd()
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		return cmd.Execute()
	}
	if err := run(collector, dir, "--no-packs", "--git-url", "https://github.com/acme/shop"); err != nil {
		t.Fatalf("scan without a key: %v", err)
	}
	if err := run(secret, dir, "--no-packs", "--git-url", "https://github.com/acme/payments", "--project", strconv.FormatInt(p.ID, 10)); err != nil {
		t.Fatalf("scan --project without a key: %v", err)
	}
	if err := run(secret, dir, "--no-packs", "--git-url", "https://github.com/acme/payments", "--project", "Payments"); err != nil {
		t.Fatalf("scan --project NAME without a key: %v", err)
	}
	var n int
	if err := st.Pool.QueryRow(tenant.System(ctx), `SELECT count(*) FROM assets`).Scan(&n); err != nil || n != 2 {
		t.Errorf("assets kept from scans without a key: %d %v", n, err)
	}
}
