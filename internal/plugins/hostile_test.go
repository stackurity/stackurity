package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

const hostileMeta = `{"protocol_version":"1","metadata":{"id":"h","name":"h","version":"1","maintainer":"m","license":"MIT","schema_version":"1","permissions":[],"network_access":[],"known_limitations":[]}}`

func hostileScript(t *testing.T, dir, name, collect string) {
	t.Helper()
	script(t, dir, name, `if [ "$1" = metadata ]; then echo '`+hostileMeta+`'; exit 0; fi
cat >/dev/null
`+collect)
}

func batchJSON(extra string) string {
	return `{"schema_version":"1","collector":{"id":"evil","version":"9","method":"agent"},"asset":{"kind":"host","name":"h","identifiers":[{"scheme":"machine-id","value":"m"}]},"observed_at":"2026-01-01T00:00:00Z","observations":[{"purl":"pkg:npm/a@1.0.0"}],"coverage":[]` + extra + `}`
}

// TestHostilePluginOutput: a plugin's output is untrusted. Oversized or
// invalid output, too many batches, relation spam, host-scoped identities
// and fields naming another workspace are refused or ignored; the
// credentials it was given never reach logs or errors.
func TestHostilePluginOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts")
	}
	dir := t.TempDir()
	var spam []string
	for i := 0; i < 17; i++ {
		spam = append(spam, fmt.Sprintf(`{"kind":"runs_on","to":[{"scheme":"machine-id","value":"t%d"}]}`, i))
	}
	many := strings.TrimSuffix(strings.Repeat(batchJSON("")+",", 1001), ",")
	hostileScript(t, dir, "huge", `head -c 140000000 /dev/zero; echo`)
	hostileScript(t, dir, "invalid", `printf '{"protocol_version":"1","batches":[{"schema_version":'`)
	hostileScript(t, dir, "nested", `printf '{"protocol_version":"1","batches":'; i=0; while [ $i -lt 20000 ]; do printf '['; i=$((i+1)); done; echo`)
	hostileScript(t, dir, "toomany", `echo '{"protocol_version":"1","batches":[`+many+`]}'`)
	hostileScript(t, dir, "relspam", `echo '{"protocol_version":"1","batches":[`+batchJSON(`,"relations":[`+strings.Join(spam, ",")+`]`)+`]}'`)
	hostileScript(t, dir, "apppath", `echo '{"protocol_version":"1","batches":[{"schema_version":"1","collector":{"id":"x"},"asset":{"kind":"application","name":"a","identifiers":[{"scheme":"app-path","value":"/srv/a"}]},"observed_at":"2026-01-01T00:00:00Z","observations":[],"coverage":[],"relations":[{"kind":"runs_on","to":[{"scheme":"machine-id","value":"m"}]}]}]}'`)
	hostileScript(t, dir, "otherws", `echo '{"protocol_version":"1","workspace_id":2,"batches":[`+batchJSON(`,"workspace_id":2,"collector_token":"x"`)+`]}'`)
	hostileScript(t, dir, "leaks", `echo "debug: token=$(cat /dev/null)k8s-SECRET-token-value apiVersion" >&2
echo '{"protocol_version":"1","error":"auth failed with k8s-SECRET-token-value and line-two-secret"}'`)

	r := &Runner{Dir: dir, WorkDir: t.TempDir(), Timeout: 30 * time.Second}
	ctx := context.Background()
	for name, want := range map[string]string{
		"huge":    "exceeded",
		"invalid": "invalid JSON",
		"nested":  "invalid JSON",
		"toomany": "more than 1000 batches",
		"relspam": "too many relations",
		"apppath": "app-path",
	} {
		start := time.Now()
		_, _, err := r.Collect(ctx, name, json.RawMessage(`{}`), nil)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", name, err, want)
		}
		if d := time.Since(start); d > 20*time.Second {
			t.Errorf("%s: took %s", name, d)
		}
	}

	// Fields naming a workspace or a token are not part of the protocol:
	// the batch is ingested where the run happens, as the plugin's own.
	bs, _, err := r.Collect(ctx, "otherws", json.RawMessage(`{}`), nil)
	if err != nil || len(bs) != 1 {
		t.Fatalf("otherws: %v %d", err, len(bs))
	}
	if bs[0].Collector.ID != "plugin:h" || bs[0].Collector.Method != "plugin" {
		t.Errorf("plugin chose its own identity: %+v", bs[0].Collector)
	}
	raw, _ := json.Marshal(bs[0])
	if strings.Contains(string(raw), "workspace") || strings.Contains(string(raw), "collector_token") {
		t.Errorf("unknown fields survived: %s", raw)
	}

	secrets := map[string]string{"token": "k8s-SECRET-token-value", "kubeconfig": "apiVersion: v1\nline-two-secret\n"}
	_, logs, err := r.Collect(ctx, "leaks", json.RawMessage(`{}`), secrets)
	if err == nil {
		t.Fatal("leaks: no error")
	}
	for _, s := range []string{"k8s-SECRET-token-value", "line-two-secret"} {
		if strings.Contains(err.Error(), s) || strings.Contains(logs, s) {
			t.Errorf("credential %q in error %q or logs %q", s, err, logs)
		}
	}
}

// FuzzPluginBatches: whatever batches a plugin returns, the runner's checks
// must not panic, and anything accepted has the plugin's identity.
func FuzzPluginBatches(f *testing.F) {
	f.Add([]byte(`{"protocol_version":"1","batches":[` + batchJSON("") + `]}`))
	f.Add([]byte(`{"protocol_version":"1","batches":[null]}`))
	f.Add([]byte(`{"protocol_version":"1","batches":[{}]}`))
	f.Fuzz(func(t *testing.T, out []byte) {
		resp, err := decodeResponse(out)
		if err != nil {
			return
		}
		bs, err := checkBatches(resp.Batches, "h", "1")
		if err != nil {
			return
		}
		for _, b := range bs {
			if b.Collector.ID != "plugin:h" || b.Validate() != nil {
				t.Fatalf("accepted %+v", b)
			}
		}
	})
}
