import { useEffect } from "react";
import {
  api,
  PRIORITIES,
  startJiraConnect,
  type JiraConnection,
  type JiraProjectMeta,
  type List,
  type Priority,
} from "../api";
import { useAction, useLoad } from "../hooks";
import { Badge } from "./Badge";
import { ErrorBox } from "./ui";
import { confirmAction } from "./ConfirmDialog";

/*
 * Connect Jira (the Stackurity Atlassian app): the connection, then the
 * site, project, issue type, done status and priorities picked from lists
 * read from Jira with it. The parent ChannelForm keeps the values.
 */

export interface JiraPick {
  connectionId: number;
  cloudId: string;
  project: string;
  issueType: string;
  transition: string;
  priorities: Partial<Record<Priority, string>>;
}

const siteKey = (connectionId: number, cloudId: string) => `${connectionId}:${cloudId}`;

/** "Reconnect needed" and its reason, with Reconnect. */
export function JiraConnectionStatus({ connection, returnTo }: { connection: JiraConnection; returnTo: string }) {
  const act = useAction();
  if (connection.status === "active") return null;
  return (
    <div className="alert alert-error" role="alert">
      <Badge status="failed" label="Reconnect needed" />{" "}
      <span className="break">{connection.status_reason || "Atlassian no longer accepts this connection."}</span>{" "}
      <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => void act.run(() => startJiraConnect(returnTo, connection.id))}>
        Reconnect Jira
      </button>
      <ErrorBox error={act.error} title="Could not start Connect Jira" />
    </div>
  );
}

export function JiraConnectFields({
  idp,
  value,
  onChange,
  returnTo,
  onName,
}: {
  idp: string;
  value: JiraPick;
  onChange: (v: JiraPick) => void;
  returnTo: string;
  /** Suggests a name for the integration when a project is picked. */
  onName?: (name: string) => void;
}) {
  const conns = useLoad(() => api.get<List<JiraConnection>>("/integrations/jira/connections"), []);
  const act = useAction();
  const items = conns.data?.items ?? [];
  const sites = items.flatMap((c) => c.sites.map((s) => ({ conn: c, site: s })));
  const current = items.find((c) => c.id === value.connectionId);
  const set = (p: Partial<JiraPick>) => onChange({ ...value, ...p });

  // Back from Atlassian (?jira_connection=id) or a single site: pick it.
  useEffect(() => {
    if (!conns.data || value.cloudId) return;
    const wanted = Number(new URLSearchParams(window.location.search).get("jira_connection")) || 0;
    const pick = sites.find((x) => x.conn.id === wanted) ?? (sites.length === 1 ? sites[0] : undefined);
    if (pick) onChange({ ...value, connectionId: pick.conn.id, cloudId: pick.site.id });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [conns.data]);

  const ready = value.connectionId > 0 && value.cloudId !== "" && current?.status === "active";
  const q = `site=${encodeURIComponent(value.cloudId)}`;
  const projects = useLoad(
    () =>
      ready ? api.get<List<{ key: string; name: string }>>(`/integrations/jira/connections/${value.connectionId}/projects?${q}`) : Promise.resolve(null),
    [ready, value.connectionId, value.cloudId],
  );
  const meta = useLoad(
    () =>
      ready && value.project
        ? api.get<JiraProjectMeta>(`/integrations/jira/connections/${value.connectionId}/projects/${encodeURIComponent(value.project)}?${q}`)
        : Promise.resolve(null),
    [ready, value.connectionId, value.cloudId, value.project],
  );
  const types = (meta.data?.issue_types ?? []).filter((t) => !t.subtask);
  const statuses = meta.data?.statuses[value.issueType || "Task"] ?? Object.values(meta.data?.statuses ?? {})[0] ?? [];
  const dones = statuses.filter((s) => s.category === "done");
  const others = statuses.filter((s) => s.category !== "done");

  const connect = () => void act.run(() => startJiraConnect(returnTo));
  const disconnect = async (c: JiraConnection) => {
    if (
      !(await confirmAction({
        title: "Disconnect Jira?",
        consequence:
          "Stackurity forgets this connection's tokens, and every Jira integration that uses it is switched off. To revoke it at Atlassian too, remove Stackurity under Connected apps in your Atlassian account.",
        action: "Disconnect",
        destructive: true,
      }))
    )
      return;
    const ok = await act.run(() => api.del(`/integrations/jira/connections/${c.id}`).then(() => true));
    if (ok) {
      set({ connectionId: 0, cloudId: "", project: "" });
      conns.reload();
    }
  };

  if (conns.error) return <ErrorBox error={conns.error} title="Could not load the Jira connections" />;
  if (!conns.data) return <p className="field-span muted">Loading Jira connections…</p>;

  if (sites.length === 0)
    return (
      <div className="field field-span">
        <p>Atlassian asks you to allow Stackurity and pick a site, then brings you back here to choose the project. No API token to create or paste.</p>
        <button type="button" className="btn btn-primary" onClick={connect} disabled={act.pending}>
          Connect Jira
        </button>
        <ErrorBox error={act.error} title="Could not start Connect Jira" />
      </div>
    );

  return (
    <>
      <div className="field">
        <label htmlFor={`${idp}-jsite`}>Jira site</label>
        <select
          id={`${idp}-jsite`}
          required
          value={value.cloudId ? siteKey(value.connectionId, value.cloudId) : ""}
          onChange={(e) => {
            const [c, s] = e.target.value.split(/:(.*)/s);
            set({ connectionId: Number(c) || 0, cloudId: s ?? "", project: "", issueType: "", transition: "" });
          }}
        >
          <option value="">Pick a site</option>
          {sites.map(({ conn, site }) => (
            <option key={siteKey(conn.id, site.id)} value={siteKey(conn.id, site.id)}>
              {site.name} ({site.url.replace(/^https:\/\//, "")}){conn.status !== "active" ? " — reconnect needed" : ""}
            </option>
          ))}
        </select>
        <p className="hint">
          <button type="button" className="btn btn-link btn-inline" onClick={connect} disabled={act.pending}>
            Connect another Jira site
          </button>
          {current && (
            <>
              {" · "}
              <button type="button" className="btn btn-link-danger btn-inline" onClick={() => void disconnect(current)} disabled={act.pending}>
                Disconnect
              </button>
            </>
          )}
        </p>
      </div>
      {current && current.status !== "active" && (
        <div className="field-span">
          <JiraConnectionStatus connection={current} returnTo={returnTo} />
        </div>
      )}
      <ErrorBox error={act.error} title="Jira" />
      {ready && (
        <>
          <div className="field">
            <label htmlFor={`${idp}-jproj`}>Project</label>
            <select
              id={`${idp}-jproj`}
              required
              value={value.project}
              disabled={!projects.data}
              onChange={(e) => {
                set({ project: e.target.value, issueType: "", transition: "" });
                const p = projects.data?.items.find((x) => x.key === e.target.value);
                if (p && onName) onName(`Jira ${p.key}`);
              }}
            >
              <option value="">{projects.data ? "Pick a project" : "Loading projects…"}</option>
              {value.project && !projects.data?.items.some((p) => p.key === value.project) && <option value={value.project}>{value.project}</option>}
              {(projects.data?.items ?? []).map((p) => (
                <option key={p.key} value={p.key}>
                  {p.name} ({p.key})
                </option>
              ))}
            </select>
            <ErrorBox error={projects.error} title="Could not list the projects" />
          </div>
          {value.project && (
            <>
              <div className="field">
                <label htmlFor={`${idp}-jtype`}>Issue type</label>
                <select id={`${idp}-jtype`} value={value.issueType} onChange={(e) => set({ issueType: e.target.value, transition: "" })} disabled={!meta.data}>
                  <option value="">Task (default)</option>
                  {value.issueType && !types.some((t) => t.name === value.issueType) && <option value={value.issueType}>{value.issueType}</option>}
                  {types
                    .filter((t) => t.name !== "Task")
                    .map((t) => (
                      <option key={t.name} value={t.name}>
                        {t.name}
                      </option>
                    ))}
                </select>
                <ErrorBox error={meta.error} title="Could not read the project" />
              </div>
              <div className="field">
                <label htmlFor={`${idp}-jdone`}>When the incident resolves</label>
                <select id={`${idp}-jdone`} value={value.transition} onChange={(e) => set({ transition: e.target.value })}>
                  <option value="">Only comment on the issue</option>
                  {value.transition && !statuses.some((s) => s.name === value.transition) && (
                    <option value={value.transition}>Move to {value.transition}</option>
                  )}
                  {[...dones, ...others].map((s) => (
                    <option key={s.name} value={s.name}>
                      Move to {s.name}
                      {s.category === "done" ? " (done)" : ""}
                    </option>
                  ))}
                </select>
              </div>
              <fieldset className="field field-span">
                <legend>Jira priority per Stackurity priority (optional)</legend>
                <div className="form-grid">
                  {PRIORITIES.map((p) => (
                    <div className="field" key={p}>
                      <label htmlFor={`${idp}-jprio-${p}`}>{p}</label>
                      <select
                        id={`${idp}-jprio-${p}`}
                        value={value.priorities[p] ?? ""}
                        onChange={(e) => set({ priorities: { ...value.priorities, [p]: e.target.value } })}
                      >
                        <option value="">Project default</option>
                        {value.priorities[p] && !meta.data?.priorities.includes(value.priorities[p]!) && (
                          <option value={value.priorities[p]}>{value.priorities[p]}</option>
                        )}
                        {(meta.data?.priorities ?? []).map((n) => (
                          <option key={n} value={n}>
                            {n}
                          </option>
                        ))}
                      </select>
                    </div>
                  ))}
                </div>
              </fieldset>
            </>
          )}
        </>
      )}
    </>
  );
}
