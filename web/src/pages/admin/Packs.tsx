import { useRef, useState } from "react";
import { api, type AdminPacks, type InstalledPack } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { Badge, Chip } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import { Card, Code, EmptyState, ErrorBox, Loading, Notice, PageHeader } from "../../components/ui";
import { plural } from "../../format";
import { confirmAction } from "../../components/ConfirmDialog";

const TRUST_TONE = { official: "good", verified: "info", unsigned: "warn" } as const;

/** Instance administration: which technologies this installation can read. */
export function PacksPage() {
  const res = useLoad(() => api.get<AdminPacks>("/admin/packs"), []);
  const act = useAction();
  const [msg, setMsg] = useState<string | null>(null);
  const file = useRef<HTMLInputElement>(null);

  const done = (text: string) => {
    setMsg(text);
    res.reload();
  };
  const installed = (r: { id: string; version: string; rescans_queued: number } | undefined, verb: string) => {
    if (r)
      done(`${verb} ${r.id} ${r.version}.${r.rescans_queued ? ` ${plural(r.rescans_queued, "repository", "repositories")} will be scanned again now.` : ""}`);
  };
  const install = async (id: string) => {
    setMsg(null);
    installed(await act.run(() => api.post<{ id: string; version: string; rescans_queued: number }>("/admin/packs/install", { id })), "Installed");
  };
  const upload = async (f: File) => {
    setMsg(null);
    const body = await f.arrayBuffer();
    const r = await act.run(async () => {
      const resp = await fetch("/api/v1/admin/packs/upload", {
        method: "POST",
        body,
        headers: { "X-Stackurity-CSRF": "1", "Content-Type": "application/octet-stream" },
        credentials: "same-origin",
      });
      const json = await resp.json();
      if (!resp.ok) throw Object.assign(new Error(json?.error?.message ?? "upload failed"), json?.error ?? {});
      return json as { id: string; version: string; rescans_queued: number };
    });
    installed(r, "Installed");
    if (file.current) file.current.value = "";
  };
  const simple = async (fn: () => Promise<unknown>, text: string) => {
    setMsg(null);
    const ok = await act.run(async () => {
      await fn();
      return true;
    });
    if (ok) done(text);
  };

  const columns: Column<InstalledPack>[] = [
    {
      key: "pack",
      header: "Pack",
      cell: (p) => (
        <>
          <div>
            {p.name} <span className="muted small">{p.version}</span>
          </div>
          <div className="small muted">by {p.publisher}</div>
        </>
      ),
    },
    { key: "trust", header: "Signature", cell: (p) => <Badge status={p.trust} tone={TRUST_TONE[p.trust as keyof typeof TRUST_TONE] ?? "muted"} /> },
    {
      key: "files",
      header: "Reads",
      cell: (p) => (
        <span className="chips">
          {p.files.map((f) => (
            <Chip key={f}>{f}</Chip>
          ))}
        </span>
      ),
    },
    { key: "status", header: "Status", cell: (p) => (p.enabled ? <Badge status="active" /> : <Badge status="disabled" />) },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (p) => (
        <div className="row-actions">
          <button
            type="button"
            className="btn btn-sm"
            disabled={act.pending}
            onClick={() => void simple(() => api.patch(`/admin/packs/${p.id}`, { enabled: !p.enabled }), `${p.name} ${p.enabled ? "disabled" : "enabled"}.`)}
          >
            {p.enabled ? "Disable" : "Enable"}
          </button>
          <button
            type="button"
            className="btn btn-sm"
            disabled={act.pending}
            title="Reinstall the version this one replaced"
            onClick={async () => {
              setMsg(null);
              installed(await act.run(() => api.post<{ id: string; version: string; rescans_queued: number }>(`/admin/packs/${p.id}/rollback`)), "Rolled back to");
            }}
          >
            Roll back
          </button>
          <button
            type="button"
            className="btn btn-sm btn-link-danger"
            disabled={act.pending}
            onClick={async () => {
              if (
                await confirmAction({
                  title: `Remove ${p.name}?`,
                  consequence: "Its files are reported as unsupported again from the next scan.",
                  action: "Remove stack pack",
                  destructive: true,
                  typeToConfirm: p.name,
                })
              )
                void simple(() => api.del(`/admin/packs/${p.id}`), `Removed ${p.name}.`);
            }}
          >
            Remove
          </button>
        </div>
      ),
    },
  ];

  const data = res.data;
  const installedIDs = new Set((data?.installed ?? []).map((p) => p.id));
  const suggested = new Map((data?.suggestions ?? []).map((s) => [s.id, s.files]));

  return (
    <>
      <PageHeader
        title="Stack packs"
        sub="Signed, sandboxed packs that teach Stackurity to read more technologies, for every workspace."
      />
      {msg && <Notice kind="success">{msg}</Notice>}
      <ErrorBox error={act.error} title="That did not work" />
      <ErrorBox error={res.error} title="Could not load packs" />
      {!data && !res.error && <Loading />}
      {data && (
        <>
          <Card title="Installed">
            {data.installed.length === 0 ? (
              <EmptyState title="No packs installed">The core reads Linux packages, npm, Composer, Python, Go, Ruby, NuGet and Dart. Install packs below for more.</EmptyState>
            ) : (
              <Table caption="Installed packs" columns={columns} rows={data.installed} rowKey={(p) => p.id} />
            )}
          </Card>
          <Card title="Available">
            <div className="pack-grid">
              {data.catalog.map((c) => {
                const n = suggested.get(c.manifest.id);
                return (
                  <div key={c.manifest.id} className={`pack-card${n ? " pack-card-suggested" : ""}`}>
                    <div className="pack-card-head">
                      <strong>{c.manifest.name}</strong> <span className="muted small">{c.manifest.version}</span>{" "}
                      <Badge status="official" tone="good" />
                    </div>
                    {n ? <p className="small">{plural(n, "file")} across your workspaces need this pack.</p> : null}
                    <p className="small muted">{c.manifest.description}</p>
                    <p className="small">
                      Reads{" "}
                      {c.manifest.files.map((f, i) => (
                        <span key={f}>
                          {i > 0 && ", "}
                          <Code>{f}</Code>
                        </span>
                      ))}
                    </p>
                    {c.manifest.known_limitations?.length ? (
                      <details className="small">
                        <summary>Known limitations</summary>
                        <ul>
                          {c.manifest.known_limitations.map((l) => (
                            <li key={l}>{l}</li>
                          ))}
                        </ul>
                      </details>
                    ) : null}
                    <div className="form-actions">
                      {installedIDs.has(c.manifest.id) && c.installed_version === c.manifest.version ? (
                        <span className="muted small">Installed</span>
                      ) : (
                        <button type="button" className="btn btn-primary btn-sm" disabled={act.pending} onClick={() => void install(c.manifest.id)}>
                          {installedIDs.has(c.manifest.id) ? `Update to ${c.manifest.version}` : "Install"}
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </Card>
          <Card title="Install a pack file">
            <p className="small muted">
              Packs from other publishers are accepted only if their signing key is trusted on this server (STACKURITY_PACK_TRUSTED_KEYS).
            </p>
            <input
              ref={file}
              type="file"
              accept=".stkpack,application/gzip"
              aria-label="Pack file"
              disabled={act.pending}
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void upload(f);
              }}
            />
          </Card>
        </>
      )}
    </>
  );
}
