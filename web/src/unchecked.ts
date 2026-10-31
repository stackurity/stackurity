/**
 * Components that were not checked, split by who acts (GET
 * /coverage/unchecked). One sentence used to mix four causes and send
 * everyone to the Intelligence settings; now each part says whose move it
 * is, and the banner leads with what needs the user. No imports but types,
 * so node --test can load it.
 */
import type { Unchecked, UncheckedGroup, UncheckedItem, UncheckedReason } from "./api";

function plural(n: number, word: string, pluralWord = word + "s"): string {
  return `${n.toLocaleString()} ${n === 1 ? word : pluralWord}`;
}

/** One part of the banner's headline: a count and who it is for. */
export interface BannerPart {
  key: "need_you" | "not_supported" | "waiting";
  count: number;
  text: string;
}

export interface Banner {
  /** warn only when something needs the user, or data is overdue. */
  tone: "warn" | "info";
  parts: BannerPart[];
  /** Components whose release has no published advisories: shown, never counted. */
  noAdvisories: number;
}

/**
 * The banner for a breakdown, or null when every component was checked (or
 * the only gap is releases with no published advisories, which the rows
 * themselves say).
 */
export function uncheckedBanner(u: Unchecked | null | undefined): Banner | null {
  if (!u) return null;
  const parts: BannerPart[] = [];
  if (u.need_you > 0) parts.push({ key: "need_you", count: u.need_you, text: needYouText(u) });
  if (u.not_supported > 0)
    parts.push({ key: "not_supported", count: u.not_supported, text: `${u.not_supported.toLocaleString()} Stackurity doesn't support yet` });
  if (u.waiting > 0)
    parts.push({
      key: "waiting",
      count: u.waiting,
      text: u.overdue ? `${u.waiting.toLocaleString()} waiting on out-of-date data` : `${u.waiting.toLocaleString()} ${u.waiting === 1 ? "resolves" : "resolve"} on ${u.waiting === 1 ? "its" : "their"} own`,
    });
  if (parts.length === 0) return null;
  return { tone: u.need_you > 0 || u.overdue ? "warn" : "info", parts, noAdvisories: u.no_advisories };
}

/**
 * "2 components and 1 application need you": components and applications
 * are counted apart, so the number reads as what it is.
 */
export function needYouText(u: Unchecked): string {
  const comps = u.need_you_components ?? u.need_you;
  const apps = u.need_you_applications ?? 0;
  const parts = [comps > 0 && plural(comps, "component"), apps > 0 && plural(apps, "application")].filter(Boolean);
  return `${parts.join(" and ")} need${comps + apps === 1 ? "s" : ""} you`;
}

/**
 * Rows of components grouped by what to do: "Commit package-lock.json next
 * to web/package.json: chalk, left-pad". Each component is named once; one
 * found on several assets says so.
 */
export function groupByFix<T extends { name: string; asset_id: number; unchecked_fix?: string; unchecked_docs?: string }>(
  rows: T[],
): { fix: string; docs?: string; components: { name: string; assets: number; first: T }[] }[] {
  const out: { fix: string; docs?: string; components: { name: string; assets: number; first: T }[] }[] = [];
  const seen = new Map<string, Set<number>>();
  for (const r of rows) {
    const fix = r.unchecked_fix ?? "";
    let g = out.find((x) => x.fix === fix);
    if (!g) {
      g = { fix, docs: r.unchecked_docs, components: [] };
      out.push(g);
    }
    const key = fix + "\u0000" + r.name;
    const assets = seen.get(key) ?? new Set<number>();
    if (!seen.has(key)) {
      seen.set(key, assets);
      g.components.push({ name: r.name, assets: 0, first: r });
    }
    assets.add(r.asset_id);
    g.components.find((c) => c.name === r.name)!.assets = assets.size;
  }
  return out;
}

export function group(u: Unchecked | null | undefined, reason: UncheckedReason): UncheckedGroup | undefined {
  return u?.groups.find((g) => g.reason === reason);
}

/** "3 components use CocoaPods packages, which Stackurity doesn't check yet." */
export function unsupportedSentence(it: UncheckedItem): string {
  return `${plural(it.components, "component")} ${it.components === 1 ? "uses" : "use"} ${it.label}, which Stackurity doesn't check yet.`;
}

/** Waiting for a vulnerability source: on its own, or out of date. */
export function waitingSentence(it: UncheckedItem): string {
  if (it.overdue)
    return `Vulnerability data for ${it.label} is out of date, so ${plural(it.components, "component")} ${it.components === 1 ? "was" : "were"} not fully checked.`;
  return `Waiting for vulnerability data for ${it.label}; this resolves on its own.`;
}

/** "2 components have no readable version: no version recorded." */
export function unreadableSentence(g: UncheckedGroup): string {
  return `${plural(g.components, "component")} ${g.components === 1 ? "has" : "have"} no readable version`;
}

export function unreadableFilesSentence(g: UncheckedGroup): string {
  return `${plural(g.assets, "application")} ${g.assets === 1 ? "has" : "have"} files the agent can't read`;
}

/** The note on a component row whose release has no published advisories. */
export const NO_ADVISORIES_NOTE = "no published advisories for this release";

/**
 * Coverage health in one line: how much of the inventory was checked and
 * what is left, for the Dashboard's coverage block.
 */
export function uncheckedSummaryLine(u: Unchecked | null | undefined): string {
  const b = uncheckedBanner(u);
  if (!b) {
    const n = u?.no_advisories ?? 0;
    return n > 0 ? `Every component was checked; ${plural(n, "release")} ${n === 1 ? "has" : "have"} no published advisories.` : "Every component was checked.";
  }
  return b.parts.map((p) => p.text).join(" · ");
}
