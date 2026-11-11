/**
 * The overview at the top of the search results page: what is installed that
 * matches, where, and how many open issues need attention. Every figure comes
 * from the server's summary, which counts all matches rather than the capped
 * result lists, and links to the list that shows the same set. No imports but
 * types, so node --test can load it.
 */
import type { SearchResults } from "./api";

export interface OverviewFigure {
  key: "components" | "affected" | "critical" | "urgent";
  label: string;
  value: string;
  sub: string;
  /** The filtered list behind the figure; null when there is nothing to list. */
  href: string | null;
  /** Red only for real urgency: critical or P1 issues that are open. */
  urgent: boolean;
}

function link(path: string, params: Record<string, string>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) p.set(k, v);
  const s = p.toString();
  return s ? `${path}?${s}` : path;
}

function plural(n: number, word: string): string {
  return `${n.toLocaleString("en-GB")} ${word}${n === 1 ? "" : "s"}`;
}

/** The overview figures, or none when the server sent no summary or nothing installed or open matches. */
export function searchOverview(r: SearchResults): OverviewFigure[] {
  const s = r.summary;
  if (!s || (s.components === 0 && s.open_findings === 0)) return [];
  const issues = (extra: Record<string, string>) => link("/fixes/issues", { q: s.findings_query, ...extra });
  // One component: its own page has the installed versions and every asset.
  const only = s.components === 1 && r.components.length === 1 ? r.components[0] : null;
  return [
    {
      key: "components",
      label: "Components",
      value: s.components.toLocaleString("en-GB"),
      sub:
        s.components === 0
          ? "none installed"
          : s.installed_assets === 0
            ? "none installed at the version searched for"
            : `${plural(s.versions, "version")} on ${plural(s.installed_assets, "asset")}`,
      href: s.components === 0 ? null : only ? `/components/${only.id}` : link("/components", { q: s.component_query }),
      urgent: false,
    },
    {
      key: "affected",
      label: "Affected assets",
      value: s.affected_assets.toLocaleString("en-GB"),
      sub: s.open_findings > 0 ? `with ${plural(s.open_findings, "open issue")}` : "no open issues",
      href: s.open_findings > 0 ? issues({ sort: "asset" }) : null,
      urgent: false,
    },
    {
      key: "critical",
      label: "Critical",
      value: s.critical.toLocaleString("en-GB"),
      sub: s.critical > 0 ? "open issues of critical severity" : "none open",
      href: s.critical > 0 ? issues({ severity: "critical" }) : null,
      urgent: s.critical > 0,
    },
    {
      key: "urgent",
      label: "Urgent (P1)",
      value: s.urgent.toLocaleString("en-GB"),
      sub: s.urgent > 0 ? "open issues at priority P1" : "none open",
      href: s.urgent > 0 ? issues({ priority: "P1" }) : null,
      urgent: s.urgent > 0,
    },
  ];
}

/**
 * Narrower or broader searches to offer when nothing matched: the package
 * name without its version (name@1.2.3, "name 1.2.3", a purl), or each word
 * of a several-word query on its own.
 */
export function searchSuggestions(q: string): string[] {
  const t = q.trim();
  const out: string[] = [];
  const add = (x: string) => {
    const v = x.trim();
    if (v.length >= 2 && v !== t && !out.includes(v)) out.push(v);
  };
  const purl = /^pkg:[^/]+\/(.+)$/i.exec(t);
  if (purl) {
    const path = purl[1].split(/[@?#]/)[0];
    const name = path.slice(path.lastIndexOf("/") + 1);
    try {
      add(decodeURIComponent(name));
    } catch {
      add(name);
    }
    return out;
  }
  const words = t.split(/\s+/);
  if (words.length === 2 && /^v?\d/i.test(words[1])) {
    add(words[0]);
    return out;
  }
  const at = t.lastIndexOf("@");
  if (words.length === 1 && at > 0 && at < t.length - 1) {
    add(t.slice(0, at));
    return out;
  }
  if (words.length > 1) for (const w of words.slice(0, 3)) add(w);
  return out;
}
