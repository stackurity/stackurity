import { Link } from "react-router";
import { useState } from "react";
import { api, type Asset, type InventoryRow, type List, type Token } from "../api";
import { useAction } from "../hooks";
import { Card, CodeBlock, CopyBox, ErrorBox } from "./ui";
import { confirmAction } from "./ConfirmDialog";

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
      !(await confirmAction({
        title: `Create a remediation token bound to ${asset.name}?`,
        message: "Existing tokens are not affected.",
        consequence:
          "With it, an agent running as root with --remediate on this host can apply approved package changes (only for packages in its local allowlist).",
        action: "Create remediation token",
      }))
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

  const allow = [
    "# Package patterns this host may upgrade (one per line, shell globs).",
    "# Only listed packages can ever be changed, whatever the server asks.",
    ...(created?.suggestions.length
      ? ["# Packages with open findings on this host; uncomment the ones you allow:", ...created.suggestions.map((s) => `# ${s}`)]
      : ["# libssl*", "# openssl"]),
  ].join("\n");
  // docs/remediation.md, Enabling a host: the token goes in a file of its
  // own, readable by root only; /etc/stackurity/token stays as it is (the
  // installer gives the stackurity user read access to it and treats it as
  // "already enrolled" on upgrade).
  const shell = created
    ? `# On ${asset.name}, as root:
install -m 600 -o root -g root /dev/null /etc/stackurity/remediation-token
printf '%s\\n' '${created.secret}' > /etc/stackurity/remediation-token
cat > /etc/stackurity/remediation-allow <<'EOF'
${allow}
EOF
chmod 644 /etc/stackurity/remediation-allow`
    : "";
  // The installer's settings file keeps the server, environment, application
  // directories, application discovery and Docker containers as they were;
  // --token-file takes precedence over its STACKURITY_TOKEN_FILE.
  const unit = `# /etc/systemd/system/stackurity-remediate.service
[Unit]
Description=Stackurity agent (remediation enabled)
After=network-online.target
Wants=network-online.target

[Service]
# The installer's settings: server, environment, application directories,
# application discovery and Docker containers.
EnvironmentFile=/etc/stackurity/agent.env
ExecStart=/usr/local/bin/stackurity agent --remediate --token-file /etc/stackurity/remediation-token --interval 6h --action-interval 5m
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target`;
  const start = `# One agent reports for the host: stop the read-only one, then start this one.
systemctl disable --now stackurity-agent
systemctl daemon-reload
systemctl enable --now stackurity-remediate`;
  const check = `systemctl status stackurity-remediate
journalctl -u stackurity-remediate -f
# The approved changes waiting for this host (none until a plan covering it is approved):
. /etc/stackurity/agent.env
curl -fsS -H "Authorization: Bearer $(cat /etc/stackurity/remediation-token)" "$STACKURITY_SERVER/api/v1/agent/actions"`;

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
              host's changes. Revoke it under <Link to="/integrations/tokens">Integrations → API tokens</Link> ({created.token.prefix}…) to un-enrol the host.
            </p>
            <CopyBox value={created.secret} label={`Remediation token for ${asset.name}`} />
          </div>
          <p className="small">
            The host must already be reporting. Before you start, note what it collects now (<span className="mono">cat /etc/stackurity/agent.env</span>),
            to compare after the switch.
          </p>
          <h4 className="h-sm">1. Token and allowlist</h4>
          <CodeBlock label="Host setup commands" text={shell} />
          <p className="hint">
            The token gets a file of its own, readable by root only. Leave <span className="mono">/etc/stackurity/token</span> as it is: the read-only
            agent and the installer use it.
          </p>
          <h4 className="h-sm">2. systemd unit</h4>
          <CodeBlock label="systemd unit" text={unit} />
          <p className="hint">
            It reads the installer&apos;s settings from <span className="mono">/etc/stackurity/agent.env</span>, so applications and Docker
            containers stay checked. An agent installed by hand has no such file: copy the <span className="mono">Environment=</span> lines from{" "}
            <span className="mono">systemctl cat stackurity-agent</span> instead.
          </p>
          <h4 className="h-sm">3. Switch services</h4>
          <CodeBlock label="Switch commands" text={start} />
          <h4 className="h-sm">4. Check it</h4>
          <CodeBlock label="Check commands" text={check} />
          <p className="hint">
            The first collection should list as much as before (the host, its applications and images). Running the agent installer again
            re-enables <span className="mono">stackurity-agent</span>: disable it again and restart <span className="mono">stackurity-remediate</span>.
            Once the new agent reports, revoke the old collector token. Nothing is changed until a plan covering this host is approved.
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
