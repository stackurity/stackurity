# Writing a collector plugin

Plugins add inventory sources that Stackurity doesn't ship, such as an appliance API, an internal service registry or a cloud you use. A plugin is **any executable**: Go, Python, a shell script, anything that can read JSON from stdin and write JSON to stdout.

Plugins can only report observations. They cannot trigger remediation, and their output is validated like any other untrusted input.

## Protocol (version 1)

Stackurity runs `<plugin> <command>` with one JSON request on stdin and reads one JSON response from stdout. Anything written to stderr is logged, truncated to 256 KiB.

| Command | Request fields | Response field |
|---|---|---|
| `metadata` | none (stdin is empty) | `metadata` |
| `validate` | `config` | `validation: {ok, problems[]}` |
| `collect` | `config`, `secrets`, `deadline`, `network` | `batches: [ObservationBatch...]` |
| `health` | `config`, `secrets`, `network` | `health: {ok, message}` |

Every response includes `"protocol_version": "1"`. On failure, set `"error": "..."` and exit non-zero.

```json
// request (stdin)
{"protocol_version": "1", "command": "collect", "config": {...}, "secrets": {"bearer_token": "..."}, "deadline": "2026-10-23T10:00:00Z"}
// response (stdout)
{"protocol_version": "1", "batches": [{"schema_version": "1", "collector": {...}, "asset": {...}, "observations": [...], "coverage": [...], "complete": true}]}
```

[docs/api.md](api.md#observationbatch) describes the `ObservationBatch` format.

### Metadata

Administrators read this before enabling a plugin, and `stackurity plugin test` enforces it:

```json
{"id": "json-endpoint", "name": "JSON version endpoint", "version": "0.1.0", "maintainer": "...", "license": "Apache-2.0",
 "description": "...", "capabilities": ["inventory:application"],
 "permissions": [], "credentials": ["bearer_token (optional)"], "network_access": ["the target URLs listed in config"],
 "config_schema": [{"name": "targets", "type": "list", "required": true, "description": "..."}],
 "default_frequency": "6h", "known_limitations": ["..."]}
```

`permissions`, `network_access` and `known_limitations` must be present. Use `[]` when there are none.

### Rules for good plugins

- **Report what you did not check.** Add a coverage item (`failed`, `skipped`, `unsupported`, `partial`) with a reason. If an endpoint is down, return a batch whose coverage says so. Don't return nothing.
- **Be honest about confidence.** Use `confirmed` only for authoritative sources such as a package database or a vendor API. Self-reported versions are `inferred`.
- **Use real package URLs** (`pkg:npm/...`, `pkg:deb/debian/...?distro=debian-12`) when you know them. That way vulnerability matching and lifecycle data apply. Otherwise use `pkg:generic/<name>@<version>`.
- **Reject unknown config fields** in `validate`.
- **Never execute what you inspect.** Read data; don't run it.
- **Respect the deadline** in the request.
- **Respect the network policy.** `network` is `{"allow_private": false, "allowed_cidrs": ["10.20.0.0/16"]}`: whether the workspace that runs the plugin may reach internal addresses (loopback, private ranges, link-local such as cloud metadata), and the ranges it may reach anyway. A plugin that connects to targets taken from its config must refuse other internal addresses; in Go, use `plugin.Dialer(ctx)` as the transport's `DialContext`. `stackurity plugin test` sends no policy, which allows everything.
- **Images to scan.** An `image` asset with an `image-ref` identifier and no observations asks the server to read that image with its image scanner, as the Kubernetes plugin does for running images. The integration's `image_scans` setting bounds how many are queued per run (default 25, 0 for none).

## How Stackurity runs plugins

- Plugins are installed by an administrator into `STACKURITY_PLUGIN_DIR`. Only regular files there that are executable and not group- or world-writable can run, and names must match `[a-z0-9-]+`.
- Each run gets a clean environment (`PATH`, `HOME` and `TMPDIR` set to a scratch directory, and nothing from the server's environment), a scratch working directory that is deleted afterwards, a deadline (15 minutes by default), and output limits (128 MiB stdout, 256 KiB stderr).
- Credentials are passed only in the `secrets` field. An integration's secret reference must resolve to a JSON object such as `{"bearer_token": "..."}`.
- Returned batches are stamped with the plugin's id and version for provenance (`collector.id = "plugin:<id>"`), validated, and then ingested.
- In the Compose deployment the server, and therefore every plugin, runs as a non-root user on a read-only filesystem with all capabilities dropped. For stronger isolation, run Stackurity with a seccomp profile, or run untrusted plugins in their own container and submit batches with `POST /api/v1/ingest`.

## Writing one in Go

```go
import "github.com/stackurity/stackurity/pkg/plugin"

type mine struct{}

func (mine) Metadata() plugin.Metadata                       { /* ... */ }
func (mine) Validate(cfg json.RawMessage) plugin.ValidationResult { /* ... */ }
func (mine) Collect(ctx context.Context, cfg json.RawMessage, secrets map[string]string) ([]*plugin.ObservationBatch, error) { /* ... */ }
func (mine) Health(ctx context.Context, cfg json.RawMessage, secrets map[string]string) plugin.HealthStatus { /* ... */ }

func main() { plugin.Serve(mine{}) }
```

[examples/plugins/json-endpoint](../examples/plugins/json-endpoint) is a complete example. It reads versions from HTTP JSON endpoints, such as an appliance's `/version`.

## Writing one in another language

A minimal Python plugin:

```python
#!/usr/bin/env python3
import json, sys, datetime
cmd = sys.argv[1]
P = "1"
if cmd == "metadata":
    print(json.dumps({"protocol_version": P, "metadata": {
        "id": "hello", "name": "Hello", "version": "0.1.0", "maintainer": "you", "license": "MIT",
        "description": "example", "schema_version": "1", "capabilities": ["inventory:application"],
        "permissions": [], "credentials": [], "network_access": [], "config_schema": [], "known_limitations": []}}))
    sys.exit(0)
req = json.load(sys.stdin)
if cmd == "validate":
    ok = set(req.get("config", {})) <= set()
    print(json.dumps({"protocol_version": P, "validation": {"ok": ok, "problems": [] if ok else ["unknown field"]}}))
elif cmd == "health":
    print(json.dumps({"protocol_version": P, "health": {"ok": True, "message": "fine"}}))
elif cmd == "collect":
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    batch = {"schema_version": "1", "collector": {"id": "hello"}, "observed_at": now, "complete": True,
             "asset": {"kind": "application", "name": "hello-app", "identifiers": [{"scheme": "name:application", "value": "hello-app"}]},
             "observations": [{"purl": "pkg:generic/hello@1.0.0", "confidence": "inferred"}],
             "coverage": [{"scope": "hello", "status": "checked"}]}
    print(json.dumps({"protocol_version": P, "batches": [batch]}))
```

## Checking a plugin

```sh
stackurity plugin test ./my-plugin --config config.json --secrets secrets.json
```

This runs `metadata`, `validate` (with your config, then with an unknown field), `health` and `collect`. It checks every response against the protocol and exits non-zero if any check fails. `collect` is given 5 minutes; `--timeout 10m` allows longer. Run it in your plugin's CI.

## Installing

```sh
install -m 0755 my-plugin /var/lib/stackurity/plugins/my-plugin   # STACKURITY_PLUGIN_DIR
```

Then go to **Integrations → Add → Plugin**, or call the API:

```json
{"kind": "plugin", "config": {"plugin": "my-plugin", "config": {...}}, "secret_ref": "file:/run/secrets/my-plugin.json", "schedule_minutes": 360}
```

The protocol and metadata format are versioned. A breaking change gets a new `protocol_version`, and Stackurity keeps supporting the previous version for at least one minor release.
