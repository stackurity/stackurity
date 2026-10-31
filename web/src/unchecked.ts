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
  if (u.need_you > 0) parts.push({ key: "need_you", count: u.need_you, text: `${u.need_you.toLocaleString()} need you` });
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
  if (!b) return "Every component was checked.";
  return b.parts.map((p) => p.text).join(" · ");
}
