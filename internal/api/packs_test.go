package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/packs"
	"github.com/stackurity/stackurity/internal/tenant"
)

func TestStackPacks(t *testing.T) {
	e := newEnv(t)
	keys, err := packs.DefaultKeyring()
	if err != nil {
		t.Fatal(err)
	}
	mgr := &packs.Manager{Store: e.st, Keys: keys, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Gate: e.api.Gate}
	e.api.Packs = mgr
	e.user("owner@x.io", auth.RoleAdmin)
	e.user("admin@x.io", auth.RoleAdmin)
	e.instanceAdmin("owner@x.io")
	owner, admin := e.login("owner@x.io"), e.login("admin@x.io")

	// A repository with a pom.xml is reported as unsupported without the pack...
	b := model.NewBatch(model.Collector{ID: lockfile.CollectorID, Method: "lockfile"}, model.AssetRef{Kind: model.AssetRepository, Name: "shop",
		Identifiers: []model.Identifier{{Scheme: "git-url", Value: "github.com/acme/shop"}}})
	b.Observations = []model.Observation{{Purl: "pkg:npm/react@18.2.0", Confidence: model.ConfidenceConfirmed}}
	b.Coverage = []model.CoverageItem{{Scope: "maven:pom.xml:backend/pom.xml", Status: "unsupported"}}
	if _, err := e.st.Ingest(tenant.WithWorkspace(context.Background(), 1), b, 0); err != nil {
		t.Fatal(err)
	}
	// ...so the workspace is told which pack would read it.
	var view struct {
		Installed   []map[string]any
		Suggestions []struct {
			ID    string
			Files int64
		}
	}
	if code := admin.do("GET", "/api/v1/packs", nil, &view); code != 200 || len(view.Suggestions) != 1 || view.Suggestions[0].ID != "java" {
		t.Fatalf("suggestions: %d %+v", code, view)
	}

	// Only instance admins install.
	if code := admin.do("POST", "/api/v1/admin/packs/install", map[string]string{"id": "java"}, nil); code != 403 {
		t.Errorf("workspace admin installed a pack: %d", code)
	}
	var installed struct {
		ID, Version, Trust string
	}
	if code := owner.do("POST", "/api/v1/admin/packs/install", map[string]string{"id": "java"}, &installed); code != 200 || installed.Trust != "official" {
		t.Fatalf("install: %d %+v", code, installed)
	}
	admin.do("GET", "/api/v1/packs", nil, &view)
	if len(view.Installed) != 1 || len(view.Suggestions) != 0 {
		t.Errorf("after install: %+v", view)
	}

	// The installed pack now reads Java files in scans.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(`<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId>
		<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>`), 0o644)
	ws1 := tenant.WithWorkspace(context.Background(), 1)
	obs, _, err := lockfile.ScanWith(ws1, os.DirFS(dir), mgr.Active(ws1))
	if err != nil || len(obs) != 1 || obs[0].Purl != "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" {
		t.Fatalf("scan with installed pack: %+v %v", obs, err)
	}

	// Another replica picks the pack up on its next refresh.
	replica := &packs.Manager{Store: e.st, Keys: keys, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Gate: e.api.Gate}
	if err := replica.Refresh(ws1); err != nil || len(replica.Active(ws1)) != 1 {
		t.Fatalf("other replica after install: %v %d", err, len(replica.Active(ws1)))
	}

	// Clients download the exact archive that was installed.
	resp := admin.req("GET", "/api/v1/packs/java/archive", nil, nil)
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	a, err := packs.ReadArchive(data)
	if err != nil || a.Manifest.ID != "java" {
		t.Fatalf("archive: %v", err)
	}

	// A tampered pack is refused.
	a.Wasm = append(a.Wasm, 0)
	bad, _ := a.Bytes()
	r := owner.req("POST", "/api/v1/admin/packs/upload", bytes.NewReader(bad), map[string]string{"X-Stackurity-CSRF": "1", "Content-Type": "application/octet-stream"})
	var e1 map[string]map[string]any
	_ = json.NewDecoder(r.Body).Decode(&e1)
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Errorf("tampered pack: %d %v", r.StatusCode, e1)
	}

	// Disable, then nothing reads Java; there is no earlier version to roll back to.
	if code := owner.do("PATCH", "/api/v1/admin/packs/java", map[string]bool{"enabled": false}, nil); code != 204 {
		t.Errorf("disable: %d", code)
	}
	if len(mgr.Active(ws1)) != 0 {
		t.Error("disabled pack still active")
	}
	if err := replica.Refresh(ws1); err != nil || len(replica.Active(ws1)) != 0 {
		t.Errorf("other replica after disable: %v %d", err, len(replica.Active(ws1)))
	}
	if code := owner.do("POST", "/api/v1/admin/packs/java/rollback", nil, nil); code != 409 {
		t.Errorf("rollback without a previous version: %d", code)
	}
	if code := owner.do("DELETE", "/api/v1/admin/packs/java", nil, nil); code != 204 {
		t.Errorf("remove: %d", code)
	}
}
