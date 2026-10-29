import { Link } from "react-router";
import type { CoverageSummary, InventoryRow, LifecycleNote, RowCoverage } from "../api";
import { Badge, type Tone } from "./Badge";

// One vocabulary for coverage, shared with the API and docs/compatibility.md
// ("Coverage states"). Asset states say how far an asset's findings can be
// trusted; row coverage says whether one inventoried component was checked.

export const ASSET_STATE_LABELS: Record<string, string> = {
  healthy: "Healthy and recently evaluated",
  stale_intelligence: "Stale intelligence",
  failed_collection: "Failed collection",
  unsupported: "Unsupported",
  partially_evaluated: "Partially evaluated",
  awaiting_verification: "Awaiting verification",
};

const ASSET_STATE_TONES: Record<string, Tone> = {
  healthy: "good",
  stale_intelligence: "bad",
  failed_collection: "bad",
  unsupported: "muted",
  partially_evaluated: "warn",
  awaiting_verification: "warn",
};

export const ROW_COVERAGE_LABELS: Record<RowCoverage, string> = {
  evaluated: "Checked",
  stale_intelligence: "Stale intelligence",
  not_evaluated: "Not checked",
  unsupported: "Unsupported",
  awaiting: "Awaiting verification",
};

const ROW_COVERAGE_TONES: Record<RowCoverage, Tone> = {
  evaluated: "good",
  stale_intelligence: "bad",
  not_evaluated: "warn",
  unsupported: "muted",
  awaiting: "warn",
};

/** Options for filtering inventory by coverage; "gaps" is not_evaluated and unsupported together. */
export const COVERAGE_FILTERS: [string, string][] = [
  ["", "Any coverage"],
  ["gaps", "Not checked or unsupported"],
  ["stale_intelligence", "Stale intelligence"],
  ["awaiting", "Awaiting verification"],
  ["evaluated", "Checked"],
];

export function AssetStateBadge({ state, label }: { state: string; label?: string }) {
  return (
    <Badge
      status={state}
      tone={ASSET_STATE_TONES[state] ?? "info"}
      label={label ?? ASSET_STATE_LABELS[state] ?? state}
      title="Coverage: how far this asset's findings can be trusted"
    />
  );
}

/** Why a row was not checked, in the words used everywhere else. */
export function coverageText(r: InventoryRow): string {
  switch (r.coverage) {
    case "not_evaluated":
    case "unsupported":
      return `not checked: ${r.coverage_reason || "no reason recorded"}`;
    case "stale_intelligence":
      return `checked against stale intelligence${r.coverage_feed ? ` (${r.coverage_feed})` : ""}: newer advisories are missing`;
    case "awaiting":
      return "not evaluated yet";
  }
  return "";
}

/**
 * Inline coverage for an inventory row: nothing when it was checked against
 * current intelligence, otherwise a badge and the reason, so a component with
 * no findings is never mistaken for a clean one.
 */
export function RowCoverageNote({ row }: { row: InventoryRow }) {
  const c = row.coverage;
  const life = row.lifecycle_note?.text ? <LifecycleNoteLine note={row.lifecycle_note} /> : null;
  if (!c || c === "evaluated")
    return (
      <>
        {/* How an evaluated row is reported, e.g. a kernel package whose findings are on the kernel image. */}
        {row.coverage_reason && (
          <div className="coverage-note">
            <span className="small muted">{row.coverage_reason}</span>
          </div>
        )}
        {life}
      </>
    );
  return (
    <>
      <div className="coverage-note">
        <Badge status={c} tone={ROW_COVERAGE_TONES[c]} label={ROW_COVERAGE_LABELS[c]} />{" "}
        <span className="small">{coverageText(row)}</span>
      </div>
      {life}
    </>
  );
}

const LIFECYCLE_NOTE_BADGES: Record<string, { tone: Tone; label: string }> = {
  distribution_supported: { tone: "info", label: "maintained by the distribution" },
  distribution_ended: { tone: "warn", label: "release end of life" },
  third_party_build: { tone: "warn", label: "upstream end of life" },
  follows_upstream: { tone: "warn", label: "upstream end of life" },
};

/**
 * Upstream end of life on a distribution package: why it raised no finding
 * (the distribution still provides security updates) or what stands.
 */
export function LifecycleNoteLine({ note }: { note: LifecycleNote }) {
  const b = LIFECYCLE_NOTE_BADGES[note.status ?? ""] ?? { tone: "muted" as Tone, label: "lifecycle" };
  return (
    <div className="coverage-note">
      <Badge status={note.status ?? "lifecycle"} tone={b.tone} label={b.label} /> <span className="small">{note.text}</span>
    </div>
  );
}

function plural(n: number, noun: string) {
  return `${n.toLocaleString()} ${noun}${n === 1 ? "" : "s"}`;
}

/** Components on the asset that intelligence did not check, as one sentence. */
export function uncheckedCount(s: CoverageSummary): number {
  return s.components.not_evaluated + s.components.unsupported;
}

/**
 * The asset's coverage where the user looks at findings: its states with
 * reasons, the components that could not be checked and a link to them.
 * Healthy assets get a single quiet line.
 */
export function AssetCoverageNotice({ summary, inventoryLink }: { summary: CoverageSummary; inventoryLink: string }) {
  if (summary.state === "healthy")
    return (
      <p className="coverage-ok">
        <AssetStateBadge state="healthy" label={summary.label} /> <span className="muted small">{summary.states[0]?.detail}</span>
      </p>
    );
  const unchecked = uncheckedCount(summary);
  return (
    <div className="alert alert-warn" role="alert">
      <strong>Findings for this asset are incomplete.</strong> No finding does not mean a component is safe:
      <ul className="banner-list">
        {summary.states.map((s) => (
          <li key={s.state}>
            <AssetStateBadge state={s.state} label={s.label} /> {s.detail}.
          </li>
        ))}
      </ul>
      {unchecked > 0 && (
        <p>
          <Link to={inventoryLink}>{plural(unchecked, "component")} could not be checked</Link>
          {summary.gap_reasons.length > 0 && <>: {summary.gap_reasons.slice(0, 3).map((g) => `${g.reason} (${g.components})`).join("; ")}</>}
          .
        </p>
      )}
    </div>
  );
}

/** A short line for the Findings tab: how many components the findings do not cover. */
export function FindingsCoverageLine({ summary, inventoryLink }: { summary: CoverageSummary; inventoryLink: string }) {
  const unchecked = uncheckedCount(summary);
  const stale = summary.components.stale_intelligence;
  const awaiting = summary.components.awaiting;
  if (unchecked + stale + awaiting === 0) return null;
  return (
    <div className="alert alert-warn" role="alert">
      {unchecked > 0 && (
        <>
          <Link to={inventoryLink}>{plural(unchecked, "component")} could not be checked</Link> and may be vulnerable.{" "}
        </>
      )}
      {stale > 0 && <>{plural(stale, "component")} {stale === 1 ? "was" : "were"} checked against stale intelligence. </>}
      {awaiting > 0 && <>{plural(awaiting, "component")} {awaiting === 1 ? "is" : "are"} awaiting verification. </>}
      These findings do not cover them.
    </div>
  );
}

/** What each asset state means; the same text is in docs/compatibility.md. */
export const ASSET_STATE_MEANINGS: [string, string][] = [
  ["healthy", "Every scope was collected, every component was checked against current intelligence within the last 48 hours."],
  ["stale_intelligence", "Components were checked against a feed that is past its staleness window or whose last sync failed."],
  ["failed_collection", "A collector reported a failed scope, or the asset stopped reporting, so the inventory may be incomplete."],
  ["partially_evaluated", "Some components could not be checked (feed not synced, release without advisories, unreadable version), or the collection was incomplete."],
  ["unsupported", "Some components or scopes have no vulnerability source (unsupported ecosystem or distribution, runtime outside a package manager)."],
  ["awaiting_verification", "Inventory arrived and has not been evaluated yet, or not within the last 48 hours."],
];
