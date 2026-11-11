import { useState } from "react";
import { api, type Asset, type List, type Project } from "../../api";
import { useAction, useLoad } from "../../hooks";
import {
  Card,
  CardFooter,
  CheckCard,
  ChoiceCards,
  ErrorBox,
  GoodToKnow,
  Loading,
  OptionBadge,
  PageHeader,
  SettingRow,
} from "../../components/ui";

/*
 * Settings, Trust badge (Stackurity Cloud only): a "Monitored by
 * Stackurity" badge for a README or website, linking to a public trust
 * page. Off by default; nothing is public until an admin accepts the badge
 * terms and turns it on. See docs/trust-badge.md.
 */

export interface TrustBadge {
  id: number;
  slug: string;
  enabled: boolean;
  scope_kind: "projects" | "assets";
  project_ids: number[];
  asset_ids: number[];
  terms_version: string;
  terms_accepted_at: string | null;
  terms_current: boolean;
  show_marketing: boolean;
  show_checked_time: boolean;
  show_kinds: boolean;
  show_logo: boolean;
  listed: boolean;
  display_name: string;
  website_url: string;
  has_logo: boolean;
}

interface TrustPlan {
  hide_marketing: boolean;
  max_badges: number;
  logo: boolean;
}

interface TrustList {
  badges: TrustBadge[];
  total: number;
  plan: TrustPlan;
  terms: { version: string; text: string };
  base_url: string;
  trust_base: string;
  org_admin: boolean;
}

interface TrustPublic {
  slug: string;
  name: string;
  website_url: string | null;
  logo_url: string | null;
  state: "active" | "not_active";
  last_evaluated_at: string | null;
  kinds: string[] | null;
  unsupported_kinds: string[];
  show_marketing: boolean;
}

interface Preview {
  trust: TrustPublic;
  svg_light: string;
  svg_dark: string;
  svg_time: string;
  reason_text: string;
  failed: string[];
  systems: number;
}

interface HistoryEntry {
  decided_at: string;
  result: "active" | "not_active";
  reason_text: string;
  rule_version: string;
}

/** Alt text of every snippet; claims go through the website's claims check. */
const ALT = "Monitored by Stackurity. Not a security certification.";

const svgSrc = (svg: string) => "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);

type Draft = Omit<TrustBadge, "id" | "enabled" | "terms_version" | "terms_accepted_at" | "terms_current" | "has_logo">;

const emptyDraft: Draft = {
  slug: "",
  scope_kind: "projects",
  project_ids: [],
  asset_ids: [],
  show_marketing: true,
  show_checked_time: true,
  show_kinds: false,
  show_logo: true,
  listed: true,
  display_name: "",
  website_url: "",
};

export function TrustBadgePage() {
  const res = useLoad(() => api.getAll<TrustList>("/trust-badges"), []);
  const [creating, setCreating] = useState(false);
  const data = res.data;
  return (
    <>
      <PageHeader
        title="Trust badge"
        sub="Show a “Monitored by Stackurity” badge on your README or website. It links to a public trust page that says which of your systems Stackurity monitors and when they were last evaluated. It never shows findings, package names or host names."
      />
      <ErrorBox error={res.error} title="Could not load the trust badge" />
      {!data && !res.error && <Loading />}
      {data && (
        <>
          {data.badges.map((b) => (
            <BadgeEditor key={b.id} badge={b} list={data} onChange={res.reload} />
          ))}
          {data.badges.length === 0 && !creating && (
            <Card
              title="No badge yet"
              description="A badge covers projects or servers you choose. It stays off, and nothing is public, until you accept the badge terms and turn it on."
            >
              <CardFooter
                status={
                  data.total >= data.plan.max_badges
                    ? `Your plan allows ${data.plan.max_badges} badge${data.plan.max_badges === 1 ? "" : "s"}.`
                    : "Start by choosing what the badge covers. You can preview it before anything is public."
                }
              >
                <button className="btn primary" disabled={data.total >= data.plan.max_badges} onClick={() => setCreating(true)}>
                  Set up a badge
                </button>
              </CardFooter>
            </Card>
          )}
          {data.badges.length > 0 && data.total < data.plan.max_badges && !creating && (
            <p>
              <button className="btn" onClick={() => setCreating(true)}>
                Add another badge
              </button>
            </p>
          )}
          {creating && (
            <BadgeForm
              list={data}
              initial={emptyDraft}
              submitLabel="Create badge (stays off)"
              onCancel={() => setCreating(false)}
              onSave={async (d) => {
                await api.post("/trust-badges", d);
                setCreating(false);
                res.reload();
              }}
            />
          )}
          <GoodToKnow title="What the badge says, and what it doesn’t">
            The badge says only that the systems you chose are monitored by Stackurity. It is not a security certification, audit or
            guarantee, and must never be described as one. It changes to “Stackurity badge not active” when any covered system hasn’t
            reported for 7 days, its inventory wasn’t processed, or it wasn’t evaluated against fresh vulnerability data. You can’t
            switch that rule off.
          </GoodToKnow>
        </>
      )}
    </>
  );
}

function BadgeEditor({ badge, list, onChange }: { badge: TrustBadge; list: TrustList; onChange: () => void }) {
  const act = useAction();
  const [editing, setEditing] = useState(false);
  const [accept, setAccept] = useState(false);
  const preview = useLoad(() => api.getAll<Preview>(`/trust-badges/${badge.id}/preview`), [badge]);
  const [showHistory, setShowHistory] = useState(false);
  const imageURL = `${list.base_url}/badge/${badge.slug}.svg`;
  const pageURL = `${list.trust_base}/${badge.slug}`;
  const run = async (fn: () => Promise<unknown>) => {
    await act.run(fn);
    onChange();
  };

  if (editing) {
    return (
      <BadgeForm
        list={list}
        initial={badge}
        hasLogo={badge.has_logo}
        badgeID={badge.id}
        submitLabel="Save changes"
        onCancel={() => setEditing(false)}
        onSave={async (d) => {
          await api.put(`/trust-badges/${badge.id}`, d);
          setEditing(false);
          onChange();
        }}
      />
    );
  }
  return (
    <>
      <Card
        title={`Badge: ${badge.slug}`}
        description="What the public sees right now if this badge is on, worked out from the same rule and data as the live badge."
        actions={
          <button className="btn" onClick={() => setEditing(true)}>
            Edit
          </button>
        }
      >
        <ErrorBox error={act.error} title="Could not save" />
        <ErrorBox error={preview.error} title="Could not load the preview" />
        {preview.data && <PublicPreview p={preview.data} />}
        <SettingRow
          title="Public"
          description={
            badge.enabled
              ? "The badge and trust page are public. Turning it off shows “Stackurity badge not active” at once and clears cached copies."
              : "The badge is off: the image shows “Stackurity badge not active” and there is no trust page."
          }
          badge={badge.enabled ? <OptionBadge tone="info">On</OptionBadge> : <OptionBadge tone="muted">Off</OptionBadge>}
        >
          {badge.enabled ? (
            <button className="btn" disabled={act.pending} onClick={() => void run(() => api.post(`/trust-badges/${badge.id}/enabled`, { enabled: false }))}>
              Turn off
            </button>
          ) : (
            <button
              className="btn primary"
              disabled={act.pending || !badge.terms_current}
              onClick={() => void run(() => api.post(`/trust-badges/${badge.id}/enabled`, { enabled: true }))}
            >
              Turn on
            </button>
          )}
        </SettingRow>
        {!badge.terms_current && (
          <SettingRow
            title="Badge terms"
            description="Before the badge can go public, someone authorised to publish it for your organisation must accept the badge terms. Who accepted, and when, is recorded."
          >
            <CheckCard checked={accept} onChange={setAccept} label="I accept" description={list.terms.text} />
            <button
              className="btn primary"
              disabled={!accept || act.pending}
              onClick={() => void run(() => api.post(`/trust-badges/${badge.id}/terms`, { version: list.terms.version, accepted: true }))}
            >
              Accept the badge terms
            </button>
          </SettingRow>
        )}
        <CardFooter
          status={
            badge.terms_current
              ? `Badge terms accepted${badge.terms_accepted_at ? " on " + new Date(badge.terms_accepted_at).toLocaleDateString() : ""}.`
              : "Badge terms not accepted yet."
          }
        >
          <button
            className="btn danger"
            disabled={act.pending}
            onClick={() => {
              if (confirm("Delete this badge? Its public image will show “not active” and the trust page will go.")) {
                void run(() => api.del(`/trust-badges/${badge.id}`));
              }
            }}
          >
            Delete badge
          </button>
        </CardFooter>
      </Card>
      <Card
        title="Add it to your README or website"
        description="Copy one of these. Always embed the live image from Stackurity, never a saved copy, so the badge changes when its status does."
      >
        <Snippet label="Markdown" text={`[![${ALT}](${imageURL})](${pageURL})`} />
        <Snippet label="HTML" text={`<a href="${pageURL}"><img src="${imageURL}" alt="${ALT}" height="44"></a>`} />
        <Snippet label="Image address" text={imageURL} />
        <Snippet label="Dark backgrounds" text={`${imageURL}?theme=dark`} />
        {badge.show_checked_time && <Snippet label="With the evaluation time" text={`${imageURL}?time=1`} />}
      </Card>
      <Card
        title="Status history"
        description="Every decision about this badge, newest first, with the reason. Each time you open this, the read is recorded in the audit log."
        actions={
          <button className="btn" onClick={() => setShowHistory((v) => !v)}>
            {showHistory ? "Hide" : "Show history"}
          </button>
        }
      >
        {showHistory ? <History id={badge.id} /> : <p className="muted small">Hidden until you open it.</p>}
      </Card>
    </>
  );
}

function History({ id }: { id: number }) {
  const res = useLoad(() => api.getAll<List<HistoryEntry>>(`/trust-badges/${id}/history`, { limit: 100 }), [id]);
  if (res.error) return <ErrorBox error={res.error} title="Could not load the history" />;
  if (!res.data) return <Loading />;
  const items = res.data.items ?? [];
  if (items.length === 0) return <p className="muted">No decisions yet. The badge is evaluated when it is turned on, then every hour.</p>;
  return (
    <table className="table">
      <thead>
        <tr>
          <th>When</th>
          <th>Result</th>
          <th>Why</th>
        </tr>
      </thead>
      <tbody>
        {items.map((e, i) => (
          <tr key={i}>
            <td>{new Date(e.decided_at).toLocaleString()}</td>
            <td>{e.result === "active" ? "Monitored by Stackurity" : "Not active"}</td>
            <td>{e.reason_text}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Snippet({ label, text }: { label: string; text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <SettingRow title={label}>
      <code className="snippet">{text}</code>
      <button
        className="btn"
        onClick={() => {
          void navigator.clipboard?.writeText(text).then(() => setCopied(true));
        }}
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </SettingRow>
  );
}

/** The badge images and the trust page as the public would see them. */
function PublicPreview({ p }: { p: Preview }) {
  const t = p.trust;
  const unsupported = t.unsupported_kinds.length > 0 ? `, including some ${t.unsupported_kinds.join(", ")}` : "";
  return (
    <div className="trust-preview">
      <SettingRow title="Badge" description="Light and dark versions, exactly as served.">
        <img src={svgSrc(p.svg_light)} alt={ALT} height={44} />
        <img src={svgSrc(p.svg_dark)} alt={ALT} height={44} />
      </SettingRow>
      <SettingRow
        title="Trust page"
        description={
          t.state === "active"
            ? `Covers ${p.systems} system${p.systems === 1 ? "" : "s"}. Only what is below is public.`
            : `Not active now: ${p.reason_text}${p.failed.length > 1 ? " (" + p.failed.join("; ") + ")" : ""}`
        }
      >
        <div className="trust-preview-page">
          <strong>{t.name}</strong>
          {t.website_url && <div className="small">{t.website_url}</div>}
          <p>{t.state === "active" ? "Monitored by Stackurity" : "Monitoring status could not be confirmed."}</p>
          {t.last_evaluated_at && <p className="small">Last evaluated {new Date(t.last_evaluated_at).toUTCString()}</p>}
          {t.kinds && t.kinds.length > 0 && <p className="small">Checks: {t.kinds.join(", ")}</p>}
          {t.state === "active" && (
            <p className="small muted">
              Monitoring scope: selected systems and software repositories that {t.name} has connected to Stackurity. Some software
              components may not currently be covered by available vulnerability data{unsupported}.
            </p>
          )}
          {t.show_marketing && <p className="small">Button: “Monitor yours, free”</p>}
        </div>
      </SettingRow>
    </div>
  );
}

function BadgeForm({
  list,
  initial,
  submitLabel,
  onSave,
  onCancel,
  hasLogo,
  badgeID,
}: {
  list: TrustList;
  initial: Draft;
  submitLabel: string;
  onSave: (d: Draft) => Promise<void>;
  onCancel: () => void;
  hasLogo?: boolean;
  badgeID?: number;
}) {
  const [d, setD] = useState<Draft>({ ...emptyDraft, ...initial });
  const act = useAction();
  const projects = useLoad(() => api.getAll<{ items: Project[] | null }>("/projects"), []);
  const assets = useLoad(() => api.getAll<List<Asset>>("/assets", { limit: 500 }), []);
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD((x) => ({ ...x, [k]: v }));
  const toggle = (k: "project_ids" | "asset_ids", id: number, on: boolean) =>
    set(k, on ? [...d[k], id] : d[k].filter((x) => x !== id));
  const scopeCount = d.scope_kind === "projects" ? d.project_ids.length : d.asset_ids.length;
  return (
    <Card title="Badge settings" description="What the badge covers and what the public trust page may show. Nothing changes publicly until you save.">
      <ErrorBox error={act.error} title="Could not save the badge" />
      <SettingRow title="Address" description={`The trust page will be at ${list.trust_base}/${d.slug || "your-name"}. Lower-case letters, digits and hyphens, usually your brand name.`}>
        <input value={d.slug} onChange={(e) => set("slug", e.target.value.toLowerCase())} maxLength={50} aria-label="Address" />
      </SettingRow>
      <SettingRow title="Name on the trust page" description="Leave empty to use your organisation’s name.">
        <input value={d.display_name} onChange={(e) => set("display_name", e.target.value)} maxLength={80} aria-label="Name on the trust page" />
      </SettingRow>
      <SettingRow title="What the badge covers" description="Choose projects or individual assets. There is no organisation-wide badge: only what you pick here feeds it.">
        <ChoiceCards
          name="scope"
          legend="What the badge covers"
          value={d.scope_kind}
          onChange={(v) => setD((x) => ({ ...x, scope_kind: v, project_ids: [], asset_ids: [] }))}
          options={[
            { value: "projects", label: "Projects", description: "Every asset in the chosen projects, including ones added later." },
            { value: "assets", label: "Assets", description: "Only the servers, repositories, images or applications you tick." },
          ]}
        />
        <div className="trust-scope-list">
          {d.scope_kind === "projects" &&
            (projects.data?.items ?? [])
              .filter((p) => !p.archived_at)
              .map((p) => (
                <label key={p.id} className="check">
                  <input type="checkbox" checked={d.project_ids.includes(p.id)} onChange={(e) => toggle("project_ids", p.id, e.target.checked)} />
                  {p.name} <span className="muted small">({p.asset_count} assets)</span>
                </label>
              ))}
          {d.scope_kind === "assets" &&
            (assets.data?.items ?? []).map((a) => (
              <label key={a.id} className="check">
                <input type="checkbox" checked={d.asset_ids.includes(a.id)} onChange={(e) => toggle("asset_ids", a.id, e.target.checked)} />
                {a.name} <span className="muted small">({a.kind})</span>
              </label>
            ))}
        </div>
      </SettingRow>
      <SettingRow title="What the public may see" description="Findings, package names, host names and counts are never shown, whatever you choose here.">
        <CheckCard
          checked={d.show_marketing || !list.plan.hide_marketing}
          disabled={!list.plan.hide_marketing}
          onChange={(v) => set("show_marketing", v)}
          label="“Monitor yours, free →” line and sign-up button"
          description={list.plan.hide_marketing ? "A small line under the badge and a button on the trust page." : "Always shown on the Free plan; paid plans can switch it off."}
        />
        <CheckCard
          checked={d.show_checked_time}
          onChange={(v) => set("show_checked_time", v)}
          label="Evaluation time on the badge"
          description="Lets the badge show when the scope was last evaluated (?time=1). The trust page always shows it."
        />
        <CheckCard
          checked={d.show_kinds}
          onChange={(v) => set("show_kinds", v)}
          label="Kinds of systems checked"
          description="Servers, repositories, images, applications: no counts or names."
        />
        <CheckCard
          checked={d.show_logo}
          onChange={(v) => set("show_logo", v)}
          label="Website link and logo"
          description={list.plan.logo ? "Your website link and logo on the trust page." : "Your website link on the trust page. A logo needs a paid plan."}
        />
        <CheckCard
          checked={d.listed}
          onChange={(v) => set("listed", v)}
          label="Listed in search engines"
          description="Off adds noindex and keeps the trust page out of the sitemap."
        />
      </SettingRow>
      {d.show_logo && (
        <SettingRow title="Website" description="Linked from the trust page. Must start with https://.">
          <input value={d.website_url} onChange={(e) => set("website_url", e.target.value)} placeholder="https://example.com" aria-label="Website" />
        </SettingRow>
      )}
      {badgeID && list.plan.logo && <LogoRow id={badgeID} hasLogo={Boolean(hasLogo)} />}
      <CardFooter status={scopeCount === 0 ? "Pick at least one project or asset." : `Covers ${scopeCount} ${d.scope_kind === "projects" ? "project" : "asset"}${scopeCount === 1 ? "" : "s"}.`}>
        <button className="btn" onClick={onCancel}>
          Cancel
        </button>
        <button className="btn primary" disabled={act.pending || scopeCount === 0 || !d.slug} onClick={() => void act.run(() => onSave(d))}>
          {submitLabel}
        </button>
      </CardFooter>
    </Card>
  );
}

function LogoRow({ id, hasLogo }: { id: number; hasLogo: boolean }) {
  const act = useAction();
  const [done, setDone] = useState("");
  const upload = async (f: File) => {
    const r = await act.run(async () => {
      const res = await fetch(`/api/v1/trust-badges/${id}/logo`, {
        method: "PUT",
        credentials: "same-origin",
        headers: { "X-Stackurity-CSRF": "1", "Content-Type": "application/octet-stream" },
        body: f,
      });
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { error?: { message?: string } } | null;
        throw new Error(body?.error?.message ?? `Upload failed (${res.status})`);
      }
      return true;
    });
    if (r) setDone("Logo saved.");
  };
  return (
    <SettingRow title="Logo" description="PNG, JPEG or WebP, at most 256 KiB. Shown on the trust page when “Website link and logo” is on.">
      <ErrorBox error={act.error as never} title="Could not save the logo" />
      <input type="file" accept="image/png,image/jpeg,image/webp" aria-label="Logo" onChange={(e) => e.target.files?.[0] && void upload(e.target.files[0])} />
      {hasLogo && (
        <button className="btn" onClick={() => void act.run(() => api.del(`/trust-badges/${id}/logo`)).then(() => setDone("Logo removed."))}>
          Remove logo
        </button>
      )}
      {done && <span className="small">{done}</span>}
    </SettingRow>
  );
}
