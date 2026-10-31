import { useEffect, useState, type ChangeEvent, type FormEvent } from "react";
import { useSearchParams } from "react-router";
import { api, type OrgSSO, type OrgSSOChange, type UserRole } from "../../api";
import { useAuth } from "../../auth";
import { useAction, useLoad } from "../../hooks";
import { Card, CopyBox, ErrorBox, Loading, Notice, PageHeader } from "../../components/ui";
import { confirmAction } from "../../components/ConfirmDialog";

const ROLES: UserRole[] = ["viewer", "engineer", "security", "admin"];

function emptyForm(): OrgSSOChange {
  return {
    label: "",
    idp_metadata_url: "",
    idp_metadata: "",
    email_attribute: "",
    name_attribute: "",
    groups_attribute: "",
    role_map: {},
    default_role: "viewer",
    link_existing: false,
  };
}

/** "group=role" lines, one per line, to and from the role map. */
function mapToText(m: Record<string, UserRole>): string {
  return Object.entries(m)
    .map(([g, r]) => `${g}=${r}`)
    .join("\n");
}

function textToMap(t: string): Record<string, UserRole> | string {
  const out: Record<string, UserRole> = {};
  for (const line of t.split("\n").map((l) => l.trim()).filter(Boolean)) {
    const i = line.lastIndexOf("=");
    const g = line.slice(0, i).trim();
    const r = line.slice(i + 1).trim() as UserRole;
    if (i < 1 || !g || !ROLES.includes(r)) return `"${line}" must be group=viewer, engineer, security or admin`;
    out[g] = r;
  }
  return out;
}

/**
 * Settings, Single sign-on (Stackurity Cloud): the organisation's own SAML
 * identity provider, the email domains it has proven, a test, and switching
 * it on or requiring it.
 */
export function SingleSignOnPage() {
  const { can, state } = useAuth();
  const me = state.phase === "ready" ? state.me : null;
  const res = useLoad(() => api.orgSSO(), []);
  const act = useAction();
  const [params] = useSearchParams();
  const [form, setForm] = useState<OrgSSOChange>(emptyForm());
  const [roleText, setRoleText] = useState("");
  const [source, setSource] = useState<"url" | "file">("url");
  const [localErr, setLocalErr] = useState<string | null>(null);
  const [domain, setDomain] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const data: OrgSSO | undefined = res.data ?? undefined;
  const cfg = data?.config ?? null;
  const admin = can("admin");

  useEffect(() => {
    if (!cfg) return;
    setForm({
      label: cfg.label,
      idp_metadata_url: cfg.idp_metadata_url,
      idp_metadata: "",
      email_attribute: cfg.email_attribute,
      name_attribute: cfg.name_attribute,
      groups_attribute: cfg.groups_attribute,
      role_map: cfg.role_map,
      default_role: cfg.default_role,
      link_existing: cfg.link_existing,
    });
    setRoleText(mapToText(cfg.role_map ?? {}));
    setSource(cfg.idp_metadata_url ? "url" : "file");
  }, [cfg?.version]); // eslint-disable-line react-hooks/exhaustive-deps

  const set = (k: keyof OrgSSOChange) => (e: ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setForm({ ...form, [k]: e.target.type === "checkbox" ? (e.target as HTMLInputElement).checked : e.target.value });

  const upload = async (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    if (f.size > 1 << 20) return setLocalErr("The metadata file is larger than 1 MiB.");
    setForm({ ...form, idp_metadata: await f.text(), idp_metadata_url: "" });
  };

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setLocalErr(null);
    setNotice(null);
    const map = textToMap(roleText);
    if (typeof map === "string") return setLocalErr(map);
    const body = { ...form, role_map: map };
    if (source === "url") body.idp_metadata = "";
    else body.idp_metadata_url = "";
    const r = await act.run(() => api.saveOrgSSO(body));
    if (r) {
      setNotice("Saved. Test the connection, then switch single sign-on on.");
      res.reload();
    }
  };

  const setState = async (enabled: boolean, require: boolean) => {
    setNotice(null);
    if (await act.run(() => api.setOrgSSOState({ enabled, require_sso: require }))) res.reload();
  };
  const addDomain = async (e: FormEvent) => {
    e.preventDefault();
    if (await act.run(() => api.addOrgSSODomain(domain.trim()))) {
      setDomain("");
      res.reload();
    }
  };
  const verify = async (id: number) => {
    if (await act.run(() => api.verifyOrgSSODomain(id))) res.reload();
  };
  const removeDomain = async (id: number, name: string) => {
    if (
      !(await confirmAction({
        title: `Remove ${name}?`,
        consequence: `People with ${name} addresses can no longer sign in with single sign-on.`,
        action: "Remove domain",
        destructive: true,
        typeToConfirm: name,
      }))
    )
      return;
    if (await act.run(() => api.deleteOrgSSODomain(id))) res.reload();
  };
  const remove = async () => {
    if (
      !(await confirmAction({
        title: "Remove single sign-on?",
        consequence: "Accounts it made can sign in again only after setting a password.",
        action: "Remove single sign-on",
        destructive: true,
      }))
    )
      return;
    if (await act.run(() => api.deleteOrgSSO())) res.reload();
  };

  const tested = cfg ? cfg.tested_version === cfg.version && Boolean(cfg.tested_at) : false;
  const verified = (data?.domains ?? []).some((d) => d.verified_at);
  const testParam = params.get("test");
  const isOwner = me?.user?.id === data?.owner_id;

  return (
    <>
      <PageHeader title="Single sign-on" sub="Let people in your organisation sign in with your SAML identity provider (Okta, Microsoft Entra ID, Google Workspace and others)." />
      <ErrorBox error={res.error} title="Could not load single sign-on" />
      <ErrorBox error={act.error} title="That did not work" />
      {localErr && (
        <div className="alert alert-error" role="alert">
          {localErr}
        </div>
      )}
      {notice && <Notice kind="success">{notice}</Notice>}
      {testParam === "true" && <Notice kind="success">The test sign-in worked. You can switch single sign-on on.</Notice>}
      {testParam === "false" && <Notice kind="warn">The test sign-in did not pass. The result is below.</Notice>}
      {!data && !res.error && <Loading />}
      {data && !data.available && <Notice kind="info">{data.plan_message}</Notice>}
      {data && (
        <>
          {cfg && data.service_provider && (
            <Card title="1. Give these to your identity provider">
              <p className="label">Entity ID (Audience URI, Identifier)</p>
              <CopyBox label="Entity ID" value={data.service_provider.entity_id} />
              <p className="label">ACS URL (Single sign-on URL, Reply URL)</p>
              <CopyBox label="ACS URL" value={data.service_provider.acs_url} />
              <p className="label">Service provider metadata, for providers that import it</p>
              <CopyBox label="Service provider metadata" value={data.service_provider.metadata_url} />
              <p className="hint">Name ID format: email address. Send the attributes email, firstName and lastName, and groups if you map groups to roles.</p>
            </Card>
          )}
          <Card title={cfg ? "2. Your identity provider" : "1. Your identity provider"}>
            {!cfg && <p>Save your identity provider's metadata first; the addresses to give it appear here afterwards.</p>}
            <form className="form" onSubmit={save}>
              <fieldset disabled={!admin || !data.available || act.pending}>
                <div className="field">
                  <label htmlFor="sso-label">Button label</label>
                  <input id="sso-label" maxLength={60} value={form.label} onChange={set("label")} placeholder="Okta" />
                </div>
                <div className="field">
                  <span className="label">Identity provider metadata</span>
                  <label className="choice">
                    <input type="radio" checked={source === "url"} onChange={() => setSource("url")} /> Metadata URL
                  </label>
                  <label className="choice">
                    <input type="radio" checked={source === "file"} onChange={() => setSource("file")} /> Upload the metadata file
                  </label>
                  {source === "url" ? (
                    <input
                      aria-label="Metadata URL"
                      type="url"
                      placeholder="https://"
                      value={form.idp_metadata_url}
                      onChange={set("idp_metadata_url")}
                      required
                    />
                  ) : (
                    <input aria-label="Metadata file" type="file" accept=".xml,application/xml,text/xml" onChange={(e) => void upload(e)} />
                  )}
                  {cfg?.idp_entity_id && <p className="hint">Current provider: {cfg.idp_entity_id}</p>}
                </div>
                <details>
                  <summary>Attributes and roles</summary>
                  <div className="field">
                    <label htmlFor="sso-email">Email attribute</label>
                    <input id="sso-email" value={form.email_attribute} onChange={set("email_attribute")} placeholder="email (usual names are tried when empty)" />
                  </div>
                  <div className="field">
                    <label htmlFor="sso-name">Name attribute</label>
                    <input id="sso-name" value={form.name_attribute} onChange={set("name_attribute")} placeholder="displayName" />
                  </div>
                  <div className="field">
                    <label htmlFor="sso-groups">Groups attribute</label>
                    <input id="sso-groups" value={form.groups_attribute} onChange={set("groups_attribute")} placeholder="groups" />
                  </div>
                  <div className="field">
                    <label htmlFor="sso-roles">Groups that grant a role</label>
                    <textarea
                      id="sso-roles"
                      rows={4}
                      value={roleText}
                      onChange={(e) => setRoleText(e.target.value)}
                      placeholder={"stackurity-admins=admin\nsecurity-team=security"}
                    />
                    <p className="hint">One group=role per line. When set, the provider decides each member's role at every sign-in; the owner's role and the last admin's admin role never change.</p>
                  </div>
                  <div className="field">
                    <label htmlFor="sso-default">Role for people in no listed group</label>
                    <select id="sso-default" value={form.default_role} onChange={set("default_role")}>
                      {ROLES.map((r) => (
                        <option key={r} value={r}>
                          {r}
                        </option>
                      ))}
                      <option value="">nobody: refuse them</option>
                    </select>
                  </div>
                  <label className="choice">
                    <input type="checkbox" checked={form.link_existing} onChange={set("link_existing")} />
                    <span>
                      Link existing members by email
                      <span className="hint"> An account that is already a member here can sign in with single sign-on. Accounts outside this organisation and instance administrators are never linked.</span>
                    </span>
                  </label>
                </details>
                <button type="submit" className="btn btn-primary">
                  {act.pending ? "Saving…" : cfg ? "Save changes" : "Save"}
                </button>
                {cfg?.enabled && <p className="hint">Saving a change switches single sign-on off until you test it again.</p>}
              </fieldset>
            </form>
          </Card>
          <Card title={cfg ? "3. Email domains" : "2. Email domains"}>
            <p>People sign in with single sign-on only with addresses in domains you have proven you own. Add a domain, publish the TXT record at your DNS provider, then check it.</p>
            {data.domains.length > 0 && (
              <table className="table">
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>TXT record</th>
                    <th>Status</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {data.domains.map((d) => (
                    <tr key={d.id}>
                      <td>{d.domain}</td>
                      <td>
                        {d.verified_at ? (
                          "—"
                        ) : (
                          <>
                            <span className="hint">TXT name</span>
                            <CopyBox label="TXT record name" value={d.record_name} />
                            <span className="hint">TXT value</span>
                            <CopyBox label="TXT record value" value={d.record_value} />
                          </>
                        )}
                      </td>
                      <td>{d.verified_at ? "Verified" : d.checked_at ? "Not found yet" : "Waiting"}</td>
                      <td>
                        {admin && !d.verified_at && (
                          <button type="button" className="btn" disabled={act.pending || !data.available} onClick={() => void verify(d.id)}>
                            Check
                          </button>
                        )}
                        {admin && (
                          <button type="button" className="btn btn-link" disabled={act.pending} onClick={() => void removeDomain(d.id, d.domain)}>
                            Remove
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {admin && data.available && (
              <form className="form form-inline" onSubmit={addDomain}>
                <input aria-label="Domain" placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value)} required />
                <button type="submit" className="btn" disabled={act.pending}>
                  Add domain
                </button>
              </form>
            )}
          </Card>
          {cfg && (
            <Card title="4. Test and switch on">
              <p>
                A test signs you in at your identity provider and shows what it sent; it signs nobody in here. Single sign-on can be switched on after a test of the
                current settings passes and a domain is verified.
              </p>
              {cfg.test_result && (
                <dl className="kv">
                  <dt>Last test</dt>
                  <dd>{cfg.test_result.passed ? "Passed" : `Did not pass: ${cfg.test_result.reason}`}</dd>
                  <dt>Email</dt>
                  <dd>
                    {cfg.test_result.email || "—"} {cfg.test_result.email && !cfg.test_result.domain_verified && "(domain not verified)"}
                  </dd>
                  <dt>Name</dt>
                  <dd>{cfg.test_result.name || "—"}</dd>
                  <dt>Groups</dt>
                  <dd>{cfg.test_result.groups.join(", ") || "—"}</dd>
                  <dt>Role</dt>
                  <dd>{cfg.test_result.role || "—"}</dd>
                </dl>
              )}
              {admin && (
                <p>
                  {/* A full-page navigation: the identity provider takes over. */}
                  <a className={tested ? "btn" : "btn btn-primary"} href={`/sso/${cfg.key}/test`}>
                    Test connection
                  </a>
                </p>
              )}
              <fieldset disabled={!admin || act.pending}>
                <label className="choice">
                  <input
                    type="checkbox"
                    checked={cfg.enabled}
                    disabled={!cfg.enabled && (!tested || !verified || !data.available)}
                    onChange={(e) => void setState(e.target.checked, false)}
                  />
                  <span>
                    Single sign-on is on
                    {!cfg.enabled && (!tested || !verified) && <span className="hint"> Test the connection and verify a domain first.</span>}
                  </span>
                </label>
                <label className="choice">
                  <input type="checkbox" checked={cfg.require_sso} disabled={!cfg.enabled} onChange={(e) => void setState(true, e.target.checked)} />
                  <span>
                    Require single sign-on for members
                    <span className="hint">
                      {" "}
                      Members can then work here only after signing in with single sign-on. The organisation's owner can always sign in with their password, as a
                      way back in if the identity provider is down{isOwner ? " (that is you)" : ""}. API tokens and connected AI assistants made before
                      keep working; revoke existing tokens if you need to.
                    </span>
                  </span>
                </label>
              </fieldset>
              {data.service_provider && (
                <>
                  <p className="hint">People can also start at your organisation's sign-in link:</p>
                  <CopyBox label="Sign-in link" value={data.service_provider.login_url} />
                </>
              )}
              {admin && (
                <p>
                  <button type="button" className="btn btn-link" onClick={() => void remove()} disabled={act.pending}>
                    Remove single sign-on
                  </button>
                </p>
              )}
            </Card>
          )}
        </>
      )}
    </>
  );
}
