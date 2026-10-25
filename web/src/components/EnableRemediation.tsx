import { useState } from "react";
import { api, type Asset, type InventoryRow, type List, type Token } from "../api";
import { useAction } from "../hooks";
import { Card, CodeBlock, CopyBox, ErrorBox } from "./ui";

/**
 * Admin-only: mints a collector token bound to one host and shows the setup
 * steps from docs/remediation.md. The secret is shown once.
 */
export function EnableRemediation({ asset }: { asset: Asset }) {
  const act = useAction();
  const [created, setCreated] = useState<{ token: Token; secret: string; suggestions: string[] } | null>(null);
  const [open, setOpen] = useState(false);

  const mint = async () => {
    if (
      !window.confirm(
        `Create a remediation token bound to ${asset.name}?\n\nWith it, an agent running as root with --remediate on this host can apply approved package changes ` +
          `(only for packages in its local allowlist). Existing tokens are not affected.`,
      )
    )
      return;
    const r = await act.run(async () => {
      const t = await api.post<{ token: Token; secret: string }>(`/assets/${asset.id}/remediation-token`);
      // Packages with open findings, offered as commented-out allowlist suggestions.
      let suggestions: string[] = [];
      try {
        const inv = await api.get<List<InventoryRow>>(`/assets/${asset.id}/inventory`, { limit: 500 });
        suggestions = [...new Set(inv.items.filter((i) => (i.open_findings ?? 0) > 0).map((i) => i.name))].sort().slice(0, 40);
      } catch {
        suggestions = [];
      }
      return { ...t, suggestions };
    });
    if (r) setCreated(r);
  };

  const server = window.location.origin;
  const env = asset.environment || "production";
  const allow = [
    "# Package patterns this host may upgrade (one per line, shell globs).",
    "# Only listed packages can ever be changed, whatever the server asks.",
    ...(created?.suggestions.length
      ? ["# Packages with open findings on this host; uncomment the ones you allow:", ...created.suggestions.map((s) => `# ${s}`)]
      : ["# libssl*", "# openssl"]),
  ].join("\n");
  const shell = created
    ? `# On ${asset.name}, as root:
install -d -m 700 /etc/stackurity
printf '%s\\n' '${created.secret}' > /etc/stackurity/token && chmod 600 /etc/stackurity/token
cat > /etc/stackurity/remediation-allow <<'EOF'
${allow}
EOF`
    : "";
  const unit = `# /etc/systemd/system/stackurity-remediate.service
[Unit]
Description=Stackurity agent (remediation enabled)
After=network-online.target

[Service]
Environment=STACKURITY_SERVER=${server}
Environment=STACKURITY_TOKEN_FILE=/etc/stackurity/token
Environment=STACKURITY_ENVIRONMENT=${env}
ExecStart=/usr/local/bin/stackurity agent --remediate --interval 6h --action-interval 5m

[Install]
WantedBy=multi-user.target`;

  if (!open && !created) {
    return (
      <Card title="Remediation on this host">
        <p>
          This host only receives changes after you enrol it: a token bound to this host, plus the agent running with{" "}
          <span className="mono">--remediate</span> and a local allowlist.
        </p>
        <button type="button" className="btn" onClick={() => setOpen(true)}>
          Enable remediation…
        </button>
      </Card>
    );
  }

  return (
    <Card title="Enable remediation on this host">
      <div className="alert alert-warn" role="note">
        <strong>The remediation agent runs as root</strong> so it can use the package manager. It only changes packages that are installed{" "}
        <em>and</em> match the allowlist file on the host, only for plans approved under an enabled policy, and never through a shell. Hosts you
        don't enrol keep the unprivileged, read-only agent.
      </div>
      {!created && (
        <>
          <ErrorBox error={act.error} title="Could not create token" />
          <div className="form-actions">
            <button type="button" className="btn btn-primary" disabled={act.pending} onClick={mint}>
              Create host token
            </button>
            <button type="button" className="btn" onClick={() => setOpen(false)}>
              Cancel
            </button>
          </div>
        </>
      )}
      {created && (
        <>
          <div className="alert alert-warn secret-reveal" role="alert">
            <p>
              <strong>Copy this token now.</strong> It is shown only once. It can report inventory only for {asset.name} and fetch only this
              host's changes. Revoke it under Settings → API tokens ({created.token.prefix}…) to un-enrol the host.
            </p>
            <CopyBox value={created.secret} label={`Remediation token for ${asset.name}`} />
          </div>
          <h4 className="h-sm">1. Token and allowlist</h4>
          <CodeBlock label="Host setup commands" text={shell} />
          <h4 className="h-sm">2. systemd unit</h4>
          <CodeBlock label="systemd unit" text={unit} />
          <h4 className="h-sm">3. Start it</h4>
          <CodeBlock label="Start commands" text={"systemctl daemon-reload\nsystemctl enable --now stackurity-remediate.service"} />
          <p className="hint">
            Stop the existing read-only agent on this host if it uses a different token, so only one agent reports for it. Nothing is
            changed until a plan covering this host is approved.
          </p>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => {
              setCreated(null);
              setOpen(false);
            }}
          >
            I have stored the token
          </button>
        </>
      )}
    </Card>
  );
}
