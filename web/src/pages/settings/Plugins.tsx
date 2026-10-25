import type { ReactNode } from "react";
import { api, safeHttpUrl, type InstalledPlugin, type PluginList } from "../../api";
import { useLoad } from "../../hooks";
import { Badge, Chip } from "../../components/Badge";
import { Card, Code, CodeBlock, EmptyState, ErrorBox, Loading, PageHeader } from "../../components/ui";

function ReviewList({ title, items, empty, hint }: { title: string; items: string[] | null | undefined; empty: string; hint?: ReactNode }) {
  return (
    <section>
      <h3 className="h-sm">{title}</h3>
      {hint && <p className="hint">{hint}</p>}
      {items && items.length > 0 ? (
        <ul className="small">
          {items.map((x, i) => (
            <li key={i} className="mono">
              {x}
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted small">{empty}</p>
      )}
    </section>
  );
}

function PluginCard({ p }: { p: InstalledPlugin }) {
  const m = p.metadata;
  const home = safeHttpUrl(m?.homepage);
  return (
    <section className="card plugin-card" aria-labelledby={`pl-${p.name}`}>
      <header className="card-head">
        <h2 id={`pl-${p.name}`} className="badges">
          {m?.name ?? p.name} <span className="mono small muted">{p.name}</span>
          {m && <Chip>v{m.version}</Chip>}
          {p.error ? <Badge status="failed" label="broken" /> : <Badge status="ok" label="installed" />}
        </h2>
      </header>
      {p.error && (
        <div className="alert alert-error" role="alert">
          <strong>This plugin cannot be used:</strong> <span className="break">{p.error}</span>
          <p className="small">Integrations using it will fail until it is fixed or reinstalled.</p>
        </div>
      )}
      {m && (
        <>
          <p>{m.description}</p>
          <p className="small muted">
            Maintainer: {m.maintainer || "unknown"} · License: <span className="mono">{m.license || "unknown"}</span>
            {home && (
              <>
                {" "}
                ·{" "}
                <a href={home} target="_blank" rel="noopener noreferrer">
                  Homepage<span className="sr-only"> (opens in a new tab)</span>
                </a>
              </>
            )}{" "}
            · Protocol {m.protocol_version}, schema {m.schema_version}
            {m.default_frequency ? ` · suggested every ${m.default_frequency}` : ""}
          </p>
          {m.capabilities?.length ? (
            <p className="chips">
              {m.capabilities.map((c) => (
                <Chip key={c}>
                  <span className="mono">{c}</span>
                </Chip>
              ))}
            </p>
          ) : null}
          <div className="review">
            <ReviewList
              title="Permissions"
              items={m.permissions}
              empty="None declared."
              hint="Grant only these to the credentials or role you give it (read-only where listed)."
            />
            <ReviewList
              title="Credentials"
              items={m.credentials}
              empty="None needed."
              hint={
                <>
                  Supplied through the integration's secret reference, which must resolve to a JSON object with these keys.
                </>
              }
            />
            <ReviewList title="Network access" items={m.network_access} empty="None declared." hint="Hosts the plugin contacts; allow these in egress rules." />
            <ReviewList title="Known limitations" items={m.known_limitations} empty="None listed." />
            <section>
              <h3 className="h-sm">Config fields</h3>
              {m.config_schema?.length ? (
                <ul className="small">
                  {m.config_schema.map((f) => (
                    <li key={f.name}>
                      <span className="mono">{f.name}</span>{" "}
                      <span className="muted">
                        ({f.type}
                        {f.required ? ", required" : ""})
                      </span>{" "}
                      — {f.description}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="muted small">No configuration.</p>
              )}
            </section>
            {m.rate_limits && (
              <section>
                <h3 className="h-sm">Rate limits</h3>
                <p className="small">{m.rate_limits}</p>
              </section>
            )}
          </div>
        </>
      )}
    </section>
  );
}

export function PluginsPage() {
  const res = useLoad(() => api.get<PluginList>("/plugins"), []);
  return (
    <>
      <PageHeader help="cloud-plugins"
        title="Plugins"
        sub="Installed collector plugins and what each one needs. Review permissions, credentials and network access before using one in an integration."
      />
      <ErrorBox error={res.error} title="Could not load plugins" />
      {!res.data && !res.error && <Loading />}
      {res.data && !res.data.enabled && (
        <Card title="Plugins are not enabled">
          <p>
            Set <Code>STACKURITY_PLUGIN_DIR</Code> to a directory that only administrators can write, install plugin executables there and
            restart the server. Files must be executable, not group- or world-writable, and named <Code>[a-z0-9-]+</Code>.
          </p>
          <CodeBlock
            label="Plugin installation example"
            text={"install -d -m 0755 /var/lib/stackurity/plugins\ninstall -m 0755 aws-managed /var/lib/stackurity/plugins/aws-managed\n# then start the server with STACKURITY_PLUGIN_DIR=/var/lib/stackurity/plugins"}
          />
          <p className="hint">See docs/plugins.md for the protocol and how to write a plugin.</p>
        </Card>
      )}
      {res.data?.enabled && res.data.items.length === 0 && (
        <EmptyState title="No plugins installed">
          <p>
            Copy plugin executables into <Code>STACKURITY_PLUGIN_DIR</Code>. See docs/plugins.md.
          </p>
        </EmptyState>
      )}
      {res.data?.items.map((p) => <PluginCard key={p.name} p={p} />)}
      {res.data?.enabled && res.data.items.length > 0 && (
        <p className="hint">Use a plugin under Integrations → Add integration → Plugin. Protocol and authoring guide: docs/plugins.md.</p>
      )}
    </>
  );
}
