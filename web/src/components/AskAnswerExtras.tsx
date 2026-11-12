import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { api, type FindingDetail, type FixGroupDetail } from "../api";
import { answerRefs } from "../askRefs";
import { readMoreLinks, type ReadMoreLink } from "../advisoryLinks";
import { ActionInstruction, isCommand } from "./FixGroups";

/*
 * Under an Ask Stackurity answer: what the fix groups it links to say to
 * do, and public pages about the issues it links to. Everything here comes
 * from Stackurity's stored data, read through the same API as the Fixes and
 * issue pages, never from the model's words: the command is the fix group's
 * stored action, and the pages are the osv.dev and NVD pages for the
 * advisory ids plus the stored references on well-known advisory sites
 * (advisoryLinks.ts). A group or issue the person cannot see, or that is
 * gone, is left out.
 */

// Answers render again whenever the panel is opened; read each page once a
// minute at most.
const CACHE_MS = 60_000;
const cache = new Map<string, { at: number; p: Promise<unknown> }>();

function cachedGet<T>(path: string, q?: Record<string, number>): Promise<T | null> {
  const key = path + JSON.stringify(q ?? {});
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.p as Promise<T | null>;
  const p = api.get<T>(path, q).catch(() => null);
  cache.set(key, { at: Date.now(), p });
  return p;
}

interface FixCard {
  id: string;
  title: string;
  action: string;
  asset: string;
  others: number;
  reboot: boolean;
}

interface ReadMore {
  id: string;
  name: string;
  links: ReadMoreLink[];
}

export function AskAnswerExtras({ text, onNavigate }: { text: string; onNavigate?: () => void }) {
  const refs = useMemo(() => answerRefs(text), [text]);
  const key = `${refs.fixes.join(",")}|${refs.findings.join(",")}`;
  const [fixes, setFixes] = useState<FixCard[]>([]);
  const [reads, setReads] = useState<ReadMore[]>([]);

  useEffect(() => {
    let live = true;
    void Promise.all(refs.fixes.map((id) => cachedGet<FixGroupDetail>(`/fix-groups/${encodeURIComponent(id)}`, { limit: 1, offset: 0 }))).then((rs) => {
      if (!live) return;
      setFixes(
        rs.flatMap((r, i) => {
          const g = r?.group;
          if (!g || !g.action) return [];
          return [{ id: refs.fixes[i], title: g.title, action: g.action, asset: g.asset_name, others: Math.max(0, (g.places?.length ?? 0) - 1), reboot: Boolean(g.reboot) }];
        }),
      );
    });
    void Promise.all(refs.findings.map((id) => cachedGet<FindingDetail>(`/findings/${id}`))).then((rs) => {
      if (!live) return;
      setReads(
        rs.flatMap((r, i) => {
          if (!r) return [];
          const links = readMoreLinks(r.advisories ?? []);
          return links.length ? [{ id: refs.findings[i], name: r.finding.key, links }] : [];
        }),
      );
    });
    return () => {
      live = false;
    };
  }, [key]); // eslint-disable-line react-hooks/exhaustive-deps

  if (fixes.length === 0 && reads.length === 0) return null;
  const linkCount = reads.reduce((n, r) => n + r.links.length, 0);
  return (
    <div className="ask-extras">
      {fixes.map((f) => {
        const cmd = isCommand(f.action);
        const where = f.asset + (f.others > 0 ? ` and ${f.others} other ${f.others === 1 ? "place" : "places"}` : "");
        return (
          <section key={f.id} className="ask-cmd" aria-label={`Fix: ${f.title}`}>
            <p className="ask-cmd-head small">
              <strong>{cmd ? `Run this on ${where}` : `What to do on ${where}`}</strong>
              {" · "}
              <Link to={`/fixes/${f.id}`} onClick={onNavigate}>
                {f.title || "Open the fix"}
              </Link>
            </p>
            <ActionInstruction action={f.action} />
            {f.reboot && <p className="small ask-cmd-note">Restart {f.asset} afterwards: the update only takes effect after a restart.</p>}
          </section>
        );
      })}
      {reads.length > 0 && (
        <details className="ask-sec ask-readmore">
          <summary>Read more ({linkCount})</summary>
          <p className="small muted">Public pages about these issues, from the advisory data Stackurity keeps. They open in a new tab.</p>
          {reads.map((r) => (
            <div key={r.id} className="ask-readmore-item">
              <p className="small">
                <Link to={`/findings/${r.id}`} onClick={onNavigate}>
                  Issue #{r.id}
                </Link>{" "}
                <span className="mono">{r.name}</span>
              </p>
              <ul className="ref-list small">
                {r.links.map((l) => (
                  <li key={l.href}>
                    <a href={l.href} target="_blank" rel="noopener noreferrer">
                      {l.label}
                      <span className="sr-only"> (opens in a new tab)</span>
                    </a>{" "}
                    <span className="muted">{l.domain}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </details>
      )}
    </div>
  );
}
