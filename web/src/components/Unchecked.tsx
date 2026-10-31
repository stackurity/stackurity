import { useState } from "react";
import { Link } from "react-router";
import { api, type InventoryRow, type List, type Unchecked, type UncheckedGroup } from "../api";
import { useAuth } from "../auth";
import { useLoad } from "../hooks";
import { plural } from "../format";
import {
  group,
  uncheckedBanner,
  unreadableFilesSentence,
  unreadableSentence,
  unsupportedSentence,
  waitingSentence,
  type BannerPart,
} from "../unchecked";
import { ErrorBox } from "./ui";

/** Loads the breakdown for one asset, or every asset the viewer may see. */
export function useUnchecked(assetId?: number) {
  return useLoad(() => api.get<Unchecked>("/coverage/unchecked", { asset_id: assetId || undefined }), [assetId]);
}

/** Where the components behind a reason are listed. */
function componentsLink(reason: string, assetId?: number): string | undefined {
  return assetId ? `/assets/${assetId}?tab=inventory&unchecked=${reason}` : undefined;
}

/**
 * "Not every component was checked": a headline that leads with what needs
 * the user ("2 need you · 5 Stackurity doesn't support yet · 1 resolves on
 * its own"), each part opening its detail. Warning tone only when something
 * needs the user or vulnerability data is overdue. Nothing when everything
 * was checked.
 */
export function UncheckedBanner({ u, assetId }: { u: Unchecked | null | undefined; assetId?: number }) {
  const [open, setOpen] = useState<BannerPart["key"] | null>(null);
  const b = uncheckedBanner(u);
  if (!b || !u) return null;
  const id = (k: string) => `unchecked-${assetId ?? "all"}-${k}`;
  return (
    <div className={`alert alert-${b.tone} unchecked`} role={b.tone === "warn" ? "alert" : "status"}>
      <p className="unchecked-head">
        <strong>Not every component was checked:</strong>{" "}
        {b.parts.map((p, i) => (
          <span key={p.key}>
            {i > 0 && <span aria-hidden="true"> · </span>}
            <button
              type="button"
              className={`unchecked-part unchecked-part-${p.key}`}
              aria-expanded={open === p.key}
              aria-controls={id(p.key)}
              onClick={() => setOpen(open === p.key ? null : p.key)}
            >
              {p.text}
            </button>
          </span>
        ))}
      </p>
      {open === "need_you" && <NeedYou u={u} assetId={assetId} id={id("need_you")} />}
      {open === "not_supported" && <NotSupported g={group(u, "unsupported")} id={id("not_supported")} />}
      {open === "waiting" && <Waiting g={group(u, "waiting_for_data")} id={id("waiting")} />}
      {b.noAdvisories > 0 && (
        <p className="small unchecked-foot">
          {plural(b.noAdvisories, "component")} {b.noAdvisories === 1 ? "is a release" : "are releases"} with no published advisories: nothing is known against{" "}
          {b.noAdvisories === 1 ? "it" : "them"}, so {b.noAdvisories === 1 ? "it isn't" : "they aren't"} counted here.
        </p>
      )}
    </div>
  );
}

function NeedYou({ u, assetId, id }: { u: Unchecked; assetId?: number; id: string }) {
  const versions = group(u, "unreadable_version");
  const files = group(u, "unreadable_files");
  return (
    <div id={id} className="unchecked-detail">
      {versions && (
        <>
          <p>
            <strong>{unreadableSentence(versions)}</strong>, so Stackurity can't tell which advisories apply.
          </p>
          <ul className="banner-list">
            {versions.items.map((it) => (
              <li key={it.key}>
                {plural(it.components, "component")}: {it.label}. {it.fix}{" "}
                {it.docs && (
                  <a href={it.docs} target="_blank" rel="noopener noreferrer">
                    How
                  </a>
                )}
              </li>
            ))}
          </ul>
          {assetId ? (
            <p>
              <Link to={componentsLink("unreadable_version", assetId)!}>Show the {plural(versions.components, "component")}</Link>
            </p>
          ) : (
            <UnreadableRows />
          )}
        </>
      )}
      {files && (
        <>
          <p>
            <strong>{unreadableFilesSentence(files)}</strong>, so what they run may be missing. {files.items[0]?.fix}{" "}
            {files.items[0]?.docs && (
              <a href={files.items[0].docs} target="_blank" rel="noopener noreferrer">
                How to grant read access
              </a>
            )}
          </p>
          <p>
            <Link to={assetId ? `/assets/${assetId}?tab=coverage` : "/coverage"}>See what could not be read</Link>
          </p>
        </>
      )}
    </div>
  );
}

const ROWS = 20;

/** Across assets: the components themselves, each with its asset and fix. */
function UnreadableRows() {
  const res = useLoad(() => api.get<List<InventoryRow>>("/inventory", { unchecked: "unreadable_version", limit: ROWS }), []);
  return (
    <>
      <ErrorBox error={res.error} title="Could not load the components" />
      {res.data && (
        <ul className="banner-list unchecked-rows">
          {res.data.items.map((r) => (
            <li key={r.id}>
              <span className="mono">{r.name}</span> on <Link to={`/assets/${r.asset_id}?tab=inventory&unchecked=unreadable_version`}>{r.asset_name}</Link>
              {r.location && <span className="small mono break"> {r.location}</span>}
              {r.unchecked_fix && <div className="small">{r.unchecked_fix}</div>}
            </li>
          ))}
          {res.data.total > res.data.items.length && <li className="small">and {plural(res.data.total - res.data.items.length, "more")}, on their assets' Inventory tabs</li>}
        </ul>
      )}
    </>
  );
}

function NotSupported({ g, id }: { g?: UncheckedGroup; id: string }) {
  if (!g) return null;
  return (
    <div id={id} className="unchecked-detail">
      <ul className="banner-list">
        {g.items.map((it) => (
          <li key={it.key}>{unsupportedSentence(it)}</li>
        ))}
      </ul>
      <p className="small">Nothing for you to do; this is on our list.</p>
    </div>
  );
}

function Waiting({ g, id }: { g?: UncheckedGroup; id: string }) {
  const { me } = useAuth();
  if (!g) return null;
  return (
    <div id={id} className="unchecked-detail">
      <ul className="banner-list">
        {g.items.map((it) => (
          <li key={it.key}>{waitingSentence(it)}</li>
        ))}
      </ul>
      {g.overdue &&
        (me?.user?.instance_admin ? (
          <p className="small">
            <Link to="/admin/health">Check Platform health</Link> to see why the data stopped updating.
          </p>
        ) : (
          <p className="small">If this doesn't clear within a day, tell whoever runs Stackurity for you.</p>
        ))}
    </div>
  );
}

/**
 * The breakdown as a card body for the Coverage page: every reason with
 * who acts, or what is good when nothing is left out.
 */
export function UncheckedBreakdown({ u }: { u: Unchecked }) {
  const b = uncheckedBanner(u);
  if (!b && u.no_advisories === 0) return <p className="coverage-ok">Every component was checked against current vulnerability data.</p>;
  const versions = group(u, "unreadable_version");
  const files = group(u, "unreadable_files");
  const unsupported = group(u, "unsupported");
  const waiting = group(u, "waiting_for_data");
  const none = group(u, "no_advisories");
  return (
    <dl className="coverage-states unchecked-breakdown">
      <div>
        <dt>
          Needs you <span className="mono">{u.need_you.toLocaleString()}</span>
        </dt>
        <dd className="small">
          {u.need_you === 0 ? (
            "Every version and application file could be read."
          ) : (
            <>
              {versions && <>{unreadableSentence(versions)}: {versions.items.map((it) => it.label).join(", ")}. </>}
              {files && (
                <>
                  {unreadableFilesSentence(files)}. {files.items[0]?.fix}{" "}
                </>
              )}
              {versions && <UnreadableRows />}
            </>
          )}
        </dd>
      </div>
      <div>
        <dt>
          Stackurity doesn't support yet <span className="mono">{u.not_supported.toLocaleString()}</span>
        </dt>
        <dd className="small">
          {unsupported ? unsupported.items.slice(0, 4).map((it) => unsupportedSentence(it)).join(" ") + " Nothing for you to do; this is on our list." : "Every ecosystem found is supported."}
        </dd>
      </div>
      <div>
        <dt>
          Resolves on its own <span className="mono">{u.waiting.toLocaleString()}</span>
        </dt>
        <dd className="small">{waiting ? waiting.items.map((it) => waitingSentence(it)).join(" ") : "All vulnerability data is up to date."}</dd>
      </div>
      <div>
        <dt>
          No published advisories <span className="mono">{u.no_advisories.toLocaleString()}</span>
        </dt>
        <dd className="small">
          {none
            ? `Releases nobody has published advisories for (${none.items.map((it) => it.label).join(", ")}). Nothing is known against them; not counted as a gap.`
            : "Every release has published advisories."}
        </dd>
      </div>
    </dl>
  );
}
