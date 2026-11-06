/**
 * The first check in words and numbers: the Get started steps, the progress
 * while the first asset reports and is checked, and the milestone once it is
 * done. No imports but types, so node --test can load it; the components in
 * components/FirstCheck.tsx only lay these out.
 *
 * Every number comes from the API: GET /onboarding/results (what reported,
 * components, issues, whether the first check is done), GET /coverage/assets
 * (components checked, and those waiting for vulnerability data) and
 * GET /fix-groups/summary and /fix-groups (fixes, the top one).
 */
import type { AssetCoverageRow, FirstResult, FixGroup } from "./api";

function n(x: number): string {
  return x.toLocaleString("en");
}

function plural(x: number, word: string, many = word + "s"): string {
  return `${n(x)} ${x === 1 ? word : many}`;
}

export type SetupStep = "project" | "asset" | "waiting" | "result" | "notify" | "invite";

/** The Get started steps, in what happens rather than what is configured. */
export const SETUP_STEPS: { key: SetupStep; label: string; text: string }[] = [
  { key: "project", label: "Create a project", text: "Group what you check together." },
  { key: "asset", label: "Add a server or repo", text: "An agent, a CI step or an SBOM." },
  { key: "waiting", label: "First check", text: "We list its software and check it." },
  { key: "result", label: "Review fixes", text: "See what to fix first." },
  { key: "notify", label: "Choose alerts", text: "Pick where new issues go." },
  { key: "invite", label: "Invite your team", text: "Give others access." },
];

export type Source = "server" | "repo" | "sbom";

/**
 * Where the first check is:
 *   waiting   nothing has reported yet
 *   checking  something reported; its first check is not finished
 *   feeds     checked, but some components wait for vulnerability data
 *             (feeds are set up for what was found, then synced; the
 *             components are checked again when that is done)
 *   done      checked against current data
 */
export type FirstCheckPhase = "waiting" | "checking" | "feeds" | "done";

/** What the first check adds up to, for the assets that reported. */
export interface FirstCheckNumbers {
  assets: number;
  /** Assets whose first check is done. */
  checked: number;
  components: number;
  issues: number;
  /** Components checked against current data (Coverage's "Checked"); null before the coverage is known. */
  componentsChecked: number | null;
  /** Components waiting for vulnerability data; null before the coverage is known. */
  componentsWaiting: number | null;
  /** Whole percent of components checked; null with no components or no coverage yet. */
  coverage: number | null;
  /** Fixes recommended (fix groups); null before they are known. */
  fixes: number | null;
}

/** The coverage rows of these assets only (GET /coverage/assets lists the project's). */
export function coverageFor(rows: AssetCoverageRow[] | null | undefined, results: FirstResult[]): AssetCoverageRow[] | null {
  if (!rows) return null;
  const ids = new Set(results.map((r) => r.id));
  return rows.filter((r) => ids.has(r.id));
}

export function firstCheckNumbers(
  results: FirstResult[] | null | undefined,
  coverage: AssetCoverageRow[] | null | undefined,
  fixes: number | null | undefined,
): FirstCheckNumbers {
  const list = results ?? [];
  const rows = coverageFor(coverage, list);
  // Coverage counts only once every asset has its row.
  const known = rows !== null && list.length > 0 && rows.length === list.length;
  const total = known ? rows.reduce((a, r) => a + r.components, 0) : 0;
  const checked = known ? rows.reduce((a, r) => a + r.checked, 0) : null;
  const waiting = known ? rows.reduce((a, r) => a + (r.not_checked?.automatic ?? 0), 0) : null;
  return {
    assets: list.length,
    checked: list.filter((r) => r.checked).length,
    components: list.reduce((a, r) => a + r.packages, 0),
    issues: list.reduce((a, r) => a + r.issues, 0),
    componentsChecked: checked,
    componentsWaiting: waiting,
    coverage: checked !== null && total > 0 ? Math.floor((checked * 100) / total) : null,
    fixes: fixes ?? null,
  };
}

export function firstCheckPhase(x: FirstCheckNumbers): FirstCheckPhase {
  if (x.assets === 0) return "waiting";
  if (x.checked < x.assets) return "checking";
  // Without coverage rows (an asset removed meanwhile) nothing is known to wait.
  if ((x.componentsWaiting ?? 0) > 0) return "feeds";
  return "done";
}

export interface ProgressRow {
  key: "reported" | "components" | "issues" | "fixes";
  label: string;
  /** The number so far, in words ("1 server", "214"); empty before there is one. */
  value: string;
  state: "done" | "active" | "pending";
}

function reportedLabel(source: Source | undefined): string {
  if (!source) return "Report received";
  return source === "server" ? "Agent connected" : source === "repo" ? "CI report received" : "SBOM received";
}

/** The four lines of progress, filled in as the numbers arrive. */
export function progressRows(x: FirstCheckNumbers, phase: FirstCheckPhase, source: Source | undefined): ProgressRow[] {
  const reported = x.assets > 0;
  const checked = phase === "feeds" || phase === "done";
  return [
    { key: "reported", label: reportedLabel(source), value: reported ? plural(x.assets, "asset") : "", state: reported ? "done" : "active" },
    { key: "components", label: "Components found", value: reported ? n(x.components) : "", state: reported ? "done" : "pending" },
    {
      key: "issues",
      label: "Issues found",
      value: reported ? n(x.issues) : "",
      // Not final while it checks, nor while data is still syncing.
      state: phase === "done" ? "done" : reported ? "active" : "pending",
    },
    {
      key: "fixes",
      label: "Fixes recommended",
      value: checked && x.fixes !== null ? n(x.fixes) : "",
      state: phase === "done" && x.fixes !== null ? "done" : checked ? "active" : "pending",
    },
  ];
}

/** What is happening now and what to expect, in a sentence or two. */
export function phaseText(
  phase: FirstCheckPhase,
  x: FirstCheckNumbers,
  source: Source | undefined,
  what: string,
  overdue = false,
): { title: string; text: string } {
  switch (phase) {
    case "waiting":
      return {
        title: `Waiting for ${what} to report`,
        text:
          source === "repo"
            ? "It reports on the next CI run. Push a commit, or run the pipeline by hand."
            : source === "sbom"
              ? "This usually takes under a minute."
              : "This usually takes under 2 minutes once the command has finished.",
      };
    case "checking":
      return {
        title: "Checking what it found",
        text: "Each component is compared with vulnerability and end-of-life data. The numbers above update as it goes.",
      };
    case "feeds":
      if (overdue)
        return {
          title: "Vulnerability data is missing",
          text: `${plural(x.componentsWaiting ?? 0, "component")} cannot be checked yet: their vulnerability data is overdue or switched off. Assets → Data sources shows each feed.`,
        };
      return {
        title: "Waiting for vulnerability data",
        text: `${plural(x.componentsWaiting ?? 0, "component")} ${x.componentsWaiting === 1 ? "waits" : "wait"} for vulnerability data, which is still being downloaded for the software found. They are checked as soon as it has synced, usually within a few minutes, and more issues may appear. You can carry on meanwhile.`,
      };
    case "done":
      return { title: "Your first check is done", text: "" };
  }
}

/** The milestone's numbers, in the order shown. */
export function milestoneTiles(x: FirstCheckNumbers): { key: string; label: string; value: string }[] {
  return [
    { key: "assets", label: x.assets === 1 ? "Asset" : "Assets", value: n(x.assets) },
    { key: "components", label: x.components === 1 ? "Component" : "Components", value: n(x.components) },
    { key: "issues", label: x.issues === 1 ? "Issue" : "Issues", value: n(x.issues) },
    { key: "coverage", label: "Coverage", value: x.coverage !== null ? `${x.coverage}%` : x.components === 0 ? "None" : "–" },
  ];
}

/** The milestone's sentence under the numbers. */
export function milestoneText(x: FirstCheckNumbers): string {
  const cov =
    x.coverage !== null
      ? `${x.coverage}% of the components were checked against current vulnerability data. `
      : x.components === 0
        ? "No components were found. "
        : "";
  if (x.issues === 0) return x.components === 0 ? cov.trim() : `${cov}No known vulnerabilities or end-of-life software.`;
  const fixes = x.fixes ? `The ${plural(x.issues, "issue")} ${x.issues === 1 ? "is" : "are"} grouped into ${plural(x.fixes, "fix", "fixes")}, most urgent first.` : "";
  return `${cov}${fixes}`.trim();
}

/**
 * Fixes recommended for these assets: the fixes (GET /fix-groups?group_by=fix)
 * with a place on one of them, each counted once. The same fix on two assets
 * is one fix, also when the list is grouped by asset (same fix_key).
 */
export function countFixes(groups: Pick<FixGroup, "id" | "asset_id" | "fix_key" | "places">[], assetIds: number[]): number {
  const ids = new Set(assetIds);
  const keys = new Set<string>();
  for (const g of groups) {
    const on = g.places && g.places.length > 0 ? g.places.map((p) => p.asset_id) : [g.asset_id];
    if (on.some((id) => ids.has(id))) keys.add(g.fix_key || g.id);
  }
  return keys.size;
}

/** The link to a fix's page. */
export function fixLink(g: Pick<FixGroup, "id">): string {
  return `/fixes/${encodeURIComponent(g.id)}`;
}
