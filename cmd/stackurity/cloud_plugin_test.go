package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/cloudconnect"
	"github.com/stackurity/stackurity/internal/plugins"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
	"github.com/stackurity/stackurity/internal/worker"
)

// A scheduled run of azure-managed in a second workspace gets the server's
// credentials for that workspace (its own proof, never one from the
// workspace's stored secret), and what the plugin reports is stored.
func TestPlatformCredentialsForPluginRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script plugin")
	}
	st := store.New(testdb.New(t))
	key := bytes.Repeat([]byte{6}, 32)
	box, err := secrets.NewBox(key)
	if err != nil {
		t.Fatal(err)
	}
	cloud, err := cloudconnect.New("https://stackurity.example", key, "11111111-2222-3333-4444-555555555555", "platform-app-secret")
	if err != nil {
		t.Fatal(err)
	}
	ws, _, err := st.CreateWorkspace(context.Background(), "Beta", "", "b@x.io", "", "correct horse battery staple 1")
	if err != nil {
		t.Fatal(err)
	}
	ctx := tenant.WithWorkspace(context.Background(), ws.ID)
	if err := st.PutSecret(ctx, box, "AZ", `{"stackurity_workspace_proof": "forged", "azure_client_id": "c", "azure_client_secret": "s"}`, 0); err != nil {
		t.Fatal(err)
	}

	dir, work := t.TempDir(), t.TempDir()
	// The plugin writes the request it was given to dump. The worker can
	// run it twice (the queued job, and the scheduler finding the new
	// integration due), and the second run may still be writing while the
	// first one's result is read: write a temporary file and rename it, so
	// that dump is only ever a whole request.
	dump := filepath.Join(t.TempDir(), "request.json")
	meta := `{"protocol_version":"1","metadata":{"id":"azure-managed","name":"a","version":"1","maintainer":"m","license":"MIT","schema_version":"1","permissions":[],` +
		`"credentials":["stackurity_azure_app_id (server)","stackurity_azure_app_secret (server)","stackurity_workspace_proof (server)","azure_client_id","azure_client_secret"],"network_access":[],"known_limitations":[]}}`
	batch := `{"schema_version":"1","collector":{"id":"azure-managed"},"asset":{"kind":"managed_service","name":"aks-main","provider":"azure","identifiers":[{"scheme":"azure-resource-id","value":"/subscriptions/s/aks-main"}]},` +
		`"observed_at":"` + time.Now().UTC().Format(time.RFC3339) + `","observations":[{"purl":"pkg:generic/azure-kubernetes-service@1.29.7","confidence":"confirmed","evidence":{"kind":"managed-service"}}],"complete":true}`
	script := "#!/bin/sh\ncase \"$1\" in\nmetadata) echo '" + meta + "' ;;\ncollect) cat > " + dump + ".$$ && mv " + dump + ".$$ " + dump + "; echo '{\"protocol_version\":\"1\",\"batches\":[" + batch + "]}' ;;\n" +
		"*) cat >/dev/null; echo '{\"protocol_version\":\"1\",\"validation\":{\"ok\":true}}' ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "azure-managed"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	in, err := st.CreateIntegration(ctx, "plugin", "az", map[string]any{"plugin": "azure-managed", "config": map[string]any{}}, "secret:AZ", 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := worker.New(st, log)
	w.Poll = 50 * time.Millisecond
	res := secrets.Resolver{Stored: func(ctx context.Context, name string) (string, error) { return st.SecretValue(ctx, box, name) }}
	registerJobs(w, st, res, t.TempDir(), log, &plugins.Runner{Dir: dir, WorkDir: work, Timeout: time.Minute}, nil, cloud, nil, nil, nil)
	if _, err := st.Enqueue(ctx, "integration.run", map[string]int64{"integration_id": in.ID}, "", time.Time{}); err != nil {
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(runCtx); close(done) }()
	defer func() { stop(); <-done }()

	deadline := time.Now().Add(60 * time.Second)
	var got *store.Integration
	for {
		got, err = st.GetIntegration(ctx, in.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.LastSuccess != nil || got.LastError != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the integration never ran")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got.LastError != "" || got.AssetID == nil {
		t.Fatalf("run: %+v", got)
	}
	raw, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	var req struct{ Secrets map[string]string }
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	if req.Secrets[cloudconnect.CredWorkspaceProof] != cloud.WorkspaceProof(ws.ID) || strings.Contains(string(raw), "forged") ||
		req.Secrets[cloudconnect.CredAzureAppSecret] != "platform-app-secret" || req.Secrets["azure_client_id"] != "c" {
		t.Errorf("plugin was given %v", req.Secrets)
	}
	if req.Secrets[cloudconnect.CredWorkspaceProof] == cloud.WorkspaceProof(tenant.DefaultWorkspace) {
		t.Error("the default workspace's proof was used")
	}
}
