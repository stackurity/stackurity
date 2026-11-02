package main

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

var testToken = strings.Join([]string{"ghp", "_", "Zq7Lm2Xr9Tb4Kc8Vn3Pw6Hy1Jd5Fs0Ga2Qex"}, "")

func leakyProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deploy.py"), []byte("TOKEN = '"+testToken+"'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runScan(t *testing.T, args ...string) (stderr string, err error) {
	t.Helper()
	cmd := scanCmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	// printLeaks writes to the process's stderr.
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	old := os.Stderr
	os.Stderr = w
	err = cmd.Execute()
	os.Stderr = old
	w.Close()
	out, _ := io.ReadAll(r)
	return string(out), err
}

// --fail-on-leak needs no server: it works with --output, prints the leak
// masked and exits 3.
func TestScanFailOnLeak(t *testing.T) {
	dir := leakyProject(t)
	out := filepath.Join(t.TempDir(), "batch.json")
	stderr, err := runScan(t, dir, "--no-packs", "--output", out, "--fail-on-leak", "high")
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != gateExitCode {
		t.Fatalf("err = %v, want exit %d", err, gateExitCode)
	}
	if !strings.Contains(stderr, "leak: critical GitHub token ghp_…2Qex at deploy.py:1") || strings.Contains(stderr, testToken) {
		t.Errorf("stderr %q", stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), testToken) {
		t.Error("the batch file holds the token")
	}
	var b model.ObservationBatch
	if err := json.Unmarshal(data, &b); err != nil || b.Leaks == nil || len(b.Leaks.Found) != 1 {
		t.Fatalf("batch leaks %+v (%v)", b.Leaks, err)
	}
	// Below the threshold, or with the scan off, it passes.
	if _, err := runScan(t, dir, "--no-packs", "--output", out); err != nil {
		t.Errorf("no gate: %v", err)
	}
	if _, err := runScan(t, dir, "--no-packs", "--output", out, "--fail-on-leak", "high", "--no-leaks"); err == nil {
		t.Error("--fail-on-leak with --no-leaks accepted")
	}
	if _, err := runScan(t, dir, "--no-packs", "--output", out, "--fail-on-leak", "urgent"); err == nil {
		t.Error("--fail-on-leak urgent accepted")
	}
}

// Leaks are sent only to a server that takes them: an older one refuses
// the field, and the upload would fail.
func TestScanSendsLeaksOnlyWhenTaken(t *testing.T) {
	for _, takes := range []bool{true, false} {
		var mu sync.Mutex
		var body []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/api/v1/meta":
				m := map[string]any{"version": "0.15.0", "features": []string{"upload_project"}}
				if takes {
					m["features"] = []string{"upload_project", "leaks"}
				}
				_ = json.NewEncoder(w).Encode(m)
			case "/api/v1/ingest":
				var rd io.Reader = r.Body
				if r.Header.Get("Content-Encoding") == "gzip" {
					zr, err := gzip.NewReader(r.Body)
					if err != nil {
						t.Error(err)
						return
					}
					rd = zr
				}
				mu.Lock()
				body, _ = io.ReadAll(rd)
				mu.Unlock()
				w.WriteHeader(201)
				_ = json.NewEncoder(w).Encode(map[string]any{"asset_id": 1, "collection_id": 1})
			default:
				w.WriteHeader(404)
			}
		}))
		t.Setenv("STACKURITY_TOKEN", "stk_test")
		t.Setenv("STACKURITY_SERVER", srv.URL)
		if _, err := runScan(t, leakyProject(t), "--no-packs"); err != nil {
			t.Fatal(err)
		}
		srv.Close()
		mu.Lock()
		sent := strings.Contains(string(body), `"leaks"`)
		mu.Unlock()
		if sent != takes {
			t.Errorf("server takes leaks %v: sent %v", takes, sent)
		}
		if strings.Contains(string(body), testToken) {
			t.Error("the upload holds the token")
		}
	}
}
