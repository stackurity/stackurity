import { useState, type FormEvent } from "react";
import { api, type LicenseInfo } from "../../api";
import { useAuth } from "../../auth";
import { useAction, useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Card, ErrorBox, KeyValues, Loading, Notice, PageHeader } from "../../components/ui";

const EDITION_LABEL = { community: "Community", pro: "Pro", enterprise: "Enterprise" } as const;
const FEATURE_LABEL: Record<string, string> = {
  remediation: "Automatic fixing",
  teams: "Several teams, routing by team, escalation",
  evidence_report: "Evidence report",
  sso: "Single sign-on",
  enterprise_packs: "Enterprise stack packs",
};

/** Instance administration: the installation's licence. */
export function LicensePage() {
  const { refresh, me } = useAuth();
  const res = useLoad(() => api.get<LicenseInfo>("/admin/license"), []);
  const act = useAction();
  const [key, setKey] = useState("");
  const [msg, setMsg] = useState<string | null>(null);

  const install = async (e: FormEvent) => {
    e.preventDefault();
    setMsg(null);
    if (await act.run(() => api.put<LicenseInfo>("/admin/license", { key: key.trim() }))) {
      setKey("");
      setMsg("Licence installed.");
      res.reload();
      void refresh();
    }
  };
  const remove = async () => {
    const msg = me?.license_key
      ? "Remove the key? This server then waits for a key before the dashboard and API can be used again; agents and scans carry on."
      : "Remove the licence? Paid features stop at once; detection and alerts carry on.";
    if (!window.confirm(msg)) return;
    const ok = await act.run(async () => {
      await api.del("/admin/license");
      return true;
    });
    if (ok) {
      setMsg("Licence removed. This server now runs as Community.");
      res.reload();
      void refresh();
    }
  };

  const d = res.data;
  const l = d?.status.license;
  return (
    <>
      <PageHeader
        title="Licence"
        sub={
          me?.license_key
            ? "This server's key: the free Community key, or a paid licence that also sets the most any workspace can use. Keys are checked here, offline."
            : "The licence sets the most any workspace on this server can use. Detection, alerts and the free features never depend on it."
        }
      />
      {msg && <Notice kind="success">{msg}</Notice>}
      <ErrorBox error={act.error} title="That did not work" />
      <ErrorBox error={res.error} title="Could not load the licence" />
      {!d && !res.error && <Loading />}
      {d && (
        <>
          {d.status.state === "grace" && (
            <Notice kind="warn">
              This licence expired. Paid features keep working until {new Date(d.status.grace_ends!).toLocaleDateString()}; renew before then.
            </Notice>
          )}
          {d.status.state === "expired" && <Notice kind="warn">This licence has expired; paid features are off until it is renewed.</Notice>}
          {l && l.max_assets > 0 && d.active_assets > l.max_assets && (
            <Notice kind="warn">
              {d.active_assets} assets are active, above the licence&apos;s {l.max_assets}. Nothing stops working; please extend the licence.
            </Notice>
          )}
          <Card title={`Stackurity ${EDITION_LABEL[d.status.edition]}`}>
            <KeyValues
              entries={[
                ["Status", <Badge key="s" status={d.status.state === "none" ? "community" : d.status.state} />],
                ...(l
                  ? ([
                      ["Licensed to", [l.customer, l.name && l.name !== l.customer ? l.name : "", l.email ? `(${l.email})` : ""].filter(Boolean).join(" ")],
                      ["Edition", EDITION_LABEL[l.edition]],
                      ["Valid until", l.edition === "community" ? "Does not expire" : new Date(l.expires_at).toLocaleDateString()],
                      ["Assets", l.max_assets ? `${d.active_assets} of ${l.max_assets}` : `${d.active_assets} (no limit)`],
                      ["Licence id", l.id],
                    ] as [string, React.ReactNode][])
                  : ([["Assets", String(d.active_assets)]] as [string, React.ReactNode][])),
                [
                  "Paid features",
                  d.status.features.length ? d.status.features.map((f) => FEATURE_LABEL[f] ?? f).join(", ") : "None (Community)",
                ],
              ]}
            />
            {l && !d.managed_by_env && (
              <div className="form-actions">
                <button type="button" className="btn btn-sm btn-link-danger" disabled={act.pending} onClick={() => void remove()}>
                  Remove licence
                </button>
              </div>
            )}
          </Card>
          {d.managed_by_env ? (
            <Notice kind="info">This server reads its licence from STACKURITY_LICENSE; change it there.</Notice>
          ) : (
            <Card title={l ? "Replace the key" : "Add a key"}>
              {me?.license_key && !l && (
                <p className="small">
                  Self-hosted Stackurity Community is free; each server needs a free key.{" "}
                  <a href={me.license_key.signup_url} target="_blank" rel="noopener noreferrer">
                    Get a free key
                  </a>
                  .
                </p>
              )}
              <form className="form" onSubmit={install}>
                <div className="field">
                  <label htmlFor="lic-key">Free key or licence key</label>
                  <textarea id="lic-key" rows={4} required value={key} onChange={(e) => setKey(e.target.value)} spellCheck={false} />
                  <p className="hint">Checked on this server; nothing is sent anywhere.</p>
                </div>
                <div className="form-actions">
                  <button type="submit" className="btn btn-primary" disabled={act.pending || key.trim() === ""}>
                    Install key
                  </button>
                </div>
              </form>
            </Card>
          )}
        </>
      )}
    </>
  );
}
