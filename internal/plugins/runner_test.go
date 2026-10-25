package plugins

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// buildExample compiles the json-endpoint example plugin into dir.
func buildExample(t *testing.T, dir string) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	src := filepath.Join(filepath.Dir(file), "..", "..", "examples", "plugins", "json-endpoint")
	cmd := exec.Command("go", "build", "-o", filepath.Join(dir, "json-endpoint"), ".")
	cmd.Dir = src
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build example: %v\n%s", err, out)
	}
}

func script(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestExamplePlugin(t *testing.T) {
	dir := t.TempDir()
	buildExample(t, dir)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3cret" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"build": {"version": "2.14.1", "commit": "abc"}}`))
	}))
	defer srv.Close()
	r := &Runner{Dir: dir, WorkDir: t.TempDir(), Timeout: time.Minute}
	ctx := context.Background()

	list, err := r.List(ctx)
	if err != nil || len(list) != 1 || list[0].Metadata == nil || list[0].Metadata.ID != "json-endpoint" {
		t.Fatalf("list = %+v %v", list, err)
	}
	cfg := json.RawMessage(`{"targets": [{"name": "billing-api", "url": "` + srv.URL + `/version", "version_pointer": "/build/version",
		"environment": "production", "allow_http": true}, {"name": "down", "url": "http://127.0.0.1:1/v", "version_pointer": "/v", "allow_http": true}]}`)
	if v, err := r.Validate(ctx, "json-endpoint", json.RawMessage(`{"targets": [{"name": "x", "url": "http://x/v", "version_pointer": "v"}]}`)); err != nil || v.OK {
		t.Errorf("bad config validated: %+v %v", v, err)
	}
	batches, _, err := r.Collect(ctx, "json-endpoint", cfg, map[string]string{"bearer_token": "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 {
		t.Fatalf("batches = %d", len(batches))
	}
	ok, down := batches[0], batches[1]
	if ok.Collector.ID != "plugin:json-endpoint" || ok.Observations[0].Purl != "pkg:generic/billing-api@2.14.1" || ok.Asset.Environment != "production" {
		t.Errorf("batch = %+v", ok)
	}
	if down.Complete || down.Coverage[0].Status != "failed" {
		t.Errorf("unreachable endpoint must be reported as failed coverage: %+v", down.Coverage)
	}
	if h, err := r.Health(ctx, "json-endpoint", cfg, map[string]string{"bearer_token": "s3cret"}); err != nil || !h.OK {
		t.Errorf("health = %+v %v", h, err)
	}
}

func TestMisbehavingPlugins(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts")
	}
	dir := t.TempDir()
	meta := `{"protocol_version":"1","metadata":{"id":"x","name":"x","version":"1","maintainer":"m","license":"MIT","schema_version":"1","permissions":[],"network_access":[],"known_limitations":[]}}`
	script(t, dir, "garbage", `echo "not json"`)
	script(t, dir, "slow", `sleep 5`)
	script(t, dir, "leaky", `if [ "$1" = metadata ]; then echo '`+meta+`'; exit 0; fi
env | grep -q STACKURITY_ && { echo '{"protocol_version":"1","error":"saw server env"}'; exit 0; }
cat >/dev/null; echo '{"protocol_version":"1","batches":[]}'`)
	script(t, dir, "badbatch", `if [ "$1" = metadata ]; then echo '`+meta+`'; exit 0; fi
cat >/dev/null; echo '{"protocol_version":"1","batches":[{"schema_version":"1","collector":{"id":"x"},"asset":{"kind":"host","name":"h","identifiers":[{"scheme":"a","value":"b"}]},"observed_at":"2026-01-01T00:00:00Z","observations":[{"purl":"not a purl"}],"coverage":[]}]}'`)
	script(t, dir, "oldproto", `echo '{"protocol_version":"0"}'`)
	script(t, dir, "nometa", `echo '{"protocol_version":"1","metadata":{"id":"nometa","name":"n","version":"1"}}'`)
	writable := filepath.Join(dir, "writable")
	_ = os.WriteFile(writable, []byte("#!/bin/sh\necho {}\n"), 0o777)
	_ = os.Chmod(writable, 0o777)

	t.Setenv("STACKURITY_DATABASE_URL", "postgres://secret")
	r := &Runner{Dir: dir, WorkDir: t.TempDir(), Timeout: time.Second}
	ctx := context.Background()
	cases := map[string]string{
		"garbage":  "invalid JSON",
		"oldproto": "protocol",
		"nometa":   "metadata incomplete",
		"writable": "writable",
		"../etc/x": "invalid plugin name",
		"missing":  "not installed",
	}
	for name, want := range cases {
		if _, err := r.Metadata(ctx, name); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", name, err, want)
		}
	}
	if _, _, err := Exec(ctx, filepath.Join(dir, "slow"), t.TempDir(), 300*time.Millisecond, "metadata", nil); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("slow: %v", err)
	}
	if _, _, err := r.Collect(ctx, "leaky", json.RawMessage(`{}`), nil); err != nil {
		t.Errorf("server environment leaked into plugin: %v", err)
	}
	if _, _, err := r.Collect(ctx, "badbatch", json.RawMessage(`{}`), nil); err == nil || !strings.Contains(err.Error(), "purl") {
		t.Errorf("invalid batch accepted: %v", err)
	}
}
