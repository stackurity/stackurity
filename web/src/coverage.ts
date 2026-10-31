/**
 * The Coverage page in words and numbers: the headline bar, the "fix these"
 * cards, the ecosystem chips and the asset table. No imports but types, so
 * node --test can load it; the components in components/CoverageParts.tsx
 * only lay these out.
 */
import type {
  AssetCoverageGroup,
  AssetCoverageRow,
  CoverageOverview,
  CoverageRow,
  CoverageSegment,
  EcosystemCoverage,
  InventoryRow,
  SecondCheckSummary,
  Unchecked,
} from "./api";

function n(x: number): string {
  return x.toLocaleString("en");
}

function plural(x: number, word: string, many = word + "s"): string {
  return `${n(x)} ${x === 1 ? word : many}`;
}

/** The headline's segments in bar order, in the words used everywhere. */
export const SEGMENTS: { key: CoverageSegment; label: string; hint: string }[] = [
  { key: "checked", label: "Checked", hint: "checked against current vulnerability data" },
  { key: "needs_you", label: "Needs you", hint: "you can fix what stops these being checked" },
  { key: "not_supported", label: "Not supported yet", hint: "Stackurity has no vulnerability data for these yet" },
  { key: "waiting", label: "Waiting for data", hint: "resolves on its own" },
  { key: "no_advisories", label: "No published advisories", hint: "nothing is known against these releases" },
];

/** The component list behind a segment: its total is the segment's count. */
export function segmentLink(seg: CoverageSegment): string {
  return `/components?segment=${seg}`;
}

/** A share as a whole percent, rounded down so "100%" means every one. */
export function percent(part: number, whole: number): number {
  if (whole <= 0) return 0;
  return Math.floor((part * 100) / whole);
}

export interface HeadlineSegment {
  key: CoverageSegment;
  label: string;
  hint: string;
  count: number;
  /** Share of the total, 0 to 100, for the bar's widths. */
  share: number;
  to: string;
}

export interface Headline {
  total: number;
  checked: number;
  /** Whole percent checked; null with no components. */
  pct: number | null;
  text: string;
  /** Every segment, in bar order (the bar draws those with a count). */
  segments: HeadlineSegment[];
}

export function headline(ov: CoverageOverview | null | undefined): Headline {
  const total = ov?.total ?? 0;
  const segments = SEGMENTS.map((s) => {
    const count = ov?.segments?.[s.key] ?? 0;
    return { ...s, count, share: total > 0 ? (count * 100) / total : 0, to: segmentLink(s.key) };
  });
  const checked = ov?.segments?.checked ?? 0;
  if (total === 0) return { total, checked, pct: null, text: "No components reported yet", segments };
  const pct = percent(checked, total);
  return { total, checked, pct, text: `${pct}% of your components were checked`, segments };
}

/** "5 of 6 assets reporting", from the overview's collection statuses. */
export function reportingLine(status: Record<string, number> | null | undefined): { reporting: number; total: number; stale: number; text: string } {
  const s = status ?? {};
  const total = Object.entries(s)
    .filter(([k]) => k !== "removed")
    .reduce((a, [, v]) => a + v, 0);
  const stale = s.stale ?? 0;
  const reporting = total - stale;
  return { reporting, total, stale, text: `${n(reporting)} of ${plural(total, "asset")} reporting` };
}

// --- "Fix these to see everything"

export type CardIcon = "version" | "files" | "other";

export interface ActionCard {
  key: string;
  icon: CardIcon;
  title: string;
  /** What to do, in one line. */
  fix: string;
  assets: { id: number; name: string; to: string }[];
  /** Assets beyond the chips shown. */
  moreAssets: number;
  /** A command to copy, when the fix is one. */
  command?: string;
  /** Where "How to fix" goes: the docs, or the components themselves. */
  docs?: string;
  to: string;
}

/** Asset chips per card before "+N". */
export const CARD_ASSETS = 4;
/** Cards shown before "See all N". */
export const CARDS_SHOWN = 3;

/** Titles and one-line fixes per cause of an unreadable version (store unreadableCauses). */
const CAUSES: Record<string, { title: (c: number) => string; fix: string }> = {
  no_version: {
    title: (c) => `${plural(c, "component")} ${c === 1 ? "has" : "have"} no readable version`,
    fix: "Commit the lockfile, or include versions in the SBOM, then check again.",
  },
  unparseable_version: {
    title: (c) => `${plural(c, "component")} ${c === 1 ? "has a version" : "have versions"} in an odd form`,
    fix: "Install a released version, or tag your own build with one (1.2.3).",
  },
  unknown_release: {
    title: (c) => `${plural(c, "component")} on a server that doesn't say its OS release`,
    fix: "Let the agent read /etc/os-release, then check again.",
  },
  unreadable_package: {
    title: (c) => `${plural(c, "component")} with an unreadable package name`,
    fix: "Fix the package identifier (purl) in the SBOM, then import it again.",
  },
  program_no_version: {
    title: (c) => `${plural(c, "Windows program")} registered without a version`,
    fix: "Repair or reinstall with the vendor's installer, then check again.",
  },
  program_version_form: {
    title: (c) => `${plural(c, "Windows program")} with a version in an odd form`,
    fix: "Install the vendor's own release, then check again.",
  },
  windows_no_ubr: { title: () => "Windows update level not reported", fix: "Update the Stackurity agent on the host, then check again." },
  windows_no_build: { title: () => "Windows build not reported", fix: "Update the Stackurity agent on the host, then check again." },
  windows_no_product: { title: () => "Windows edition not reported", fix: "Update the Stackurity agent on the host, then check again." },
  windows_mismatch: { title: () => "Windows version and build disagree", fix: "Finish or repair the Windows update, then restart." },
};

function assetChips(rows: { asset_id: number; asset_name: string; to: string }[]): { assets: ActionCard["assets"]; moreAssets: number } {
  const seen = new Map<number, { id: number; name: string; to: string }>();
  for (const r of rows) if (!seen.has(r.asset_id)) seen.set(r.asset_id, { id: r.asset_id, name: r.asset_name, to: r.to });
  const all = [...seen.values()].sort((a, b) => a.name.localeCompare(b.name));
  return { assets: all.slice(0, CARD_ASSETS), moreAssets: Math.max(all.length - CARD_ASSETS, 0) };
}

/** The agent's user on Linux hosts (docs/install.md, "Applications deployed on the host"). */
const AGENT_USER = "stackurity";

/** "sudo setfacl …" for every unreadable application directory. */
export function aclCommand(paths: string[]): string {
  const q = (p: string) => (/^[\w./-]+$/.test(p) ? p : `'${p.replace(/'/g, `'\\''`)}'`);
  return paths
    .map((p) => `sudo setfacl -R -m u:${AGENT_USER}:rX ${q(p)} && sudo setfacl -R -d -m u:${AGENT_USER}:rX ${q(p)}`)
    .join("\n");
}

/**
 * One card per thing the user can fix: each cause of unreadable versions,
 * other reasons, and application files the agent may not read. rows are the
 * inventory rows that need the user (unchecked=unreadable_version and
 * other); scopes the problem collector scopes (for the applications).
 * Most components first.
 */
export function actionCards(u: Unchecked | null | undefined, rows: InventoryRow[], scopes: CoverageRow[]): ActionCard[] {
  if (!u) return [];
  const cards: (ActionCard & { weight: number })[] = [];
  const rowLink = (r: InventoryRow) => `/assets/${r.asset_id}?tab=inventory&unchecked=${r.unchecked_reason ?? "unreadable_version"}`;
  for (const g of u.groups) {
    if (g.actor !== "user") continue;
    if (g.reason === "unreadable_version") {
      for (const it of g.items) {
        const c = CAUSES[it.key] ?? { title: (x: number) => `${plural(x, "component")}: ${it.label}`, fix: it.fix ?? "" };
        const mine = rows.filter((r) => r.unchecked_reason === "unreadable_version" && r.unchecked_cause === it.key);
        // A single fix shared by every row ("Commit package-lock.json next to web/package.json") says more than the summary.
        const fixes = [...new Set(mine.map((r) => r.unchecked_fix).filter(Boolean))];
        const fix = fixes.length === 1 && fixes[0]!.length <= 110 ? fixes[0]! : c.fix;
        cards.push({
          key: `version:${it.key}`,
          icon: "version",
          title: c.title(it.components),
          fix,
          ...assetChips(mine.map((r) => ({ ...r, to: rowLink(r) }))),
          docs: it.docs || undefined,
          to: "/components?segment=needs_you",
          weight: it.components,
        });
      }
    } else if (g.reason === "other") {
      const mine = rows.filter((r) => r.unchecked_reason === "other");
      cards.push({
        key: "other",
        icon: "other",
        title: `${plural(g.components, "component")} could not be checked`,
        fix: "Each component's row says why; fix what it names and check again.",
        ...assetChips(mine.map((r) => ({ ...r, to: rowLink(r) }))),
        to: "/components?segment=needs_you",
        weight: g.components,
      });
    } else if (g.reason === "unreadable_files") {
      const denied = scopes.filter((s) => s.scope.startsWith("app-permissions:") && (s.status === "unsupported" || s.status === "partial"));
      const paths = [...new Set(denied.map((s) => s.scope.slice("app-permissions:".length)).filter(Boolean))];
      const it = g.items[0];
      cards.push({
        key: "files",
        icon: "files",
        title: `${plural(g.assets, "application")} ${g.assets === 1 ? "has" : "have"} files the agent can't read`,
        fix: "Grant the agent's user read access with an ACL, then check again.",
        ...assetChips(denied.map((s) => ({ asset_id: s.asset_id, asset_name: s.asset_name, to: `/assets/${s.asset_id}?tab=coverage` }))),
        command: paths.length > 0 ? aclCommand(paths) : undefined,
        docs: it?.docs || undefined,
        to: "/coverage",
        weight: g.assets,
      });
    }
  }
  return cards.sort((a, b) => b.weight - a.weight).map(({ weight: _w, ...c }) => c);
}

// --- "What Stackurity checks on your estate"

export const ECOSYSTEM_STATUS: Record<EcosystemCoverage["status"], { label: string; tone: "good" | "warn" | "muted" }> = {
  checked: { label: "Checked", tone: "good" },
  partly: { label: "Partly", tone: "warn" },
  not_supported: { label: "Not supported yet", tone: "muted" },
};

/** Where an ecosystem chip leads: its components, when it is a package type of its own. */
export function ecosystemLink(e: EcosystemCoverage): string | null {
  if (e.key.includes(":") || e.key === "windows" || e.key === "wordpress") return null;
  return `/components?type=${encodeURIComponent(e.type)}`;
}

// --- "Coverage by asset"

/** The filter chips, in the order shown. */
export const ASSET_GROUPS: { key: AssetCoverageGroup; label: string; tone: "good" | "warn" | "bad" | "muted" | "info" }[] = [
  { key: "healthy", label: "Healthy", tone: "good" },
  { key: "partly_checked", label: "Partly checked", tone: "warn" },
  { key: "failed_collection", label: "Failed collection", tone: "bad" },
  { key: "not_reporting", label: "Not reporting", tone: "bad" },
  { key: "awaiting_first_check", label: "Awaiting first check", tone: "info" },
];

export function groupLabel(g: AssetCoverageGroup): string {
  return ASSET_GROUPS.find((x) => x.key === g)?.label ?? g;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** "26 Oct", with the year when it is not this one's (UTC). */
export function shortDay(iso: string | null | undefined, now = new Date()): string {
  if (!iso) return "never";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const s = `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`;
  return d.getUTCFullYear() === now.getUTCFullYear() ? s : `${s} ${d.getUTCFullYear()}`;
}

function every(seconds: number): string {
  const h = seconds / 3600;
  if (h >= 20 && h <= 28) return "daily";
  if (h < 2) return "hourly";
  if (h < 36) return `every ${Math.round(h)} hours`;
  const d = Math.round(h / 24);
  return d === 7 ? "weekly" : `every ${d} days`;
}

/** How an asset reports, calmly: "Reporting daily", "Scanned once (26 Oct)", "Quiet since 26 Oct". */
export function reportingText(a: AssetCoverageRow, now = new Date()): { text: string; tone: "good" | "muted" | "warn" } {
  const r = a.reporting;
  if (a.collection_status === "stale") return { text: `Quiet since ${shortDay(a.last_report, now)}`, tone: "warn" };
  if (r?.mode === "one_off") return { text: `Scanned once (${shortDay(r.as_of ?? a.last_report, now)})`, tone: "muted" };
  if (!r || r.mode === "unknown" || !a.last_report) return { text: "No report yet", tone: "muted" };
  if (a.collection_status === "partial") return { text: "Reporting; last report incomplete", tone: "warn" };
  return { text: r.usual_seconds ? `Reporting ${every(r.usual_seconds)}` : "Reporting", tone: "good" };
}

/** Not-checked counts by who acts, in the headline's words, zero ones left out. */
export function notCheckedParts(a: AssetCoverageRow): { key: string; text: string; tone: "warn" | "muted" | "info" }[] {
  const nc = a.not_checked ?? { user: 0, stackurity: 0, automatic: 0, none: 0 };
  const out: { key: string; text: string; tone: "warn" | "muted" | "info" }[] = [];
  if (nc.user > 0) out.push({ key: "user", text: `${n(nc.user)} need${nc.user === 1 ? "s" : ""} you`, tone: "warn" });
  if (nc.stackurity > 0) out.push({ key: "stackurity", text: `${n(nc.stackurity)} not supported`, tone: "muted" });
  if (nc.automatic > 0) out.push({ key: "automatic", text: `${n(nc.automatic)} waiting`, tone: "info" });
  if (nc.none > 0) out.push({ key: "none", text: `${n(nc.none)} no advisories`, tone: "muted" });
  return out;
}

/** The share of an asset's components checked; null when it has none. */
export function assetPercent(a: AssetCoverageRow): number | null {
  return a.components > 0 ? percent(a.checked, a.components) : null;
}

// --- "How we verify findings"

export function secondCheckNumbers(c: SecondCheckSummary | null | undefined): {
  items: { key: string; label: string; value: number; to?: string }[];
  disagreed: number;
  empty: boolean;
} {
  const items = [
    { key: "agreed", label: "Agreed", value: c?.agreed ?? 0, to: "/fixes/issues?second_check=agreed" },
    { key: "disagreed", label: "Disagreed", value: c?.disagreed ?? 0, to: "/fixes/issues?second_check=disagreed" },
    { key: "could_not_check", label: "Couldn't check", value: c?.could_not_check ?? 0, to: "/fixes/issues?second_check=could_not_check" },
    { key: "pending", label: "Waiting", value: c?.pending ?? 0 },
  ];
  return { items, disagreed: c?.disagreed ?? 0, empty: items.every((i) => i.value === 0) };
}
