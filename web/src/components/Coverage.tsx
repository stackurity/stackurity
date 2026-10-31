import { Link } from "react-router";
import type { CoverageSummary, InventoryRow, LifecycleNote, RowCoverage, Unchecked } from "../api";
import { NO_ADVISORIES_NOTE, uncheckedBanner } from "../unchecked";
import { UncheckedBanner } from "./Unchecked";
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

/** A row that was not checked, badged by who acts: only "needs you" is a warning. */
const UNCHECKED_ROW_BADGES: Record<string, { tone: Tone; label: string }> = {
  unreadable_version: { tone: "warn", label: "Needs you" },
  unsupported: { tone: "muted", label: "Not supported yet" },
  waiting_for_data: { tone: "info", label: "Waiting for data" },
  no_advisories: { tone: "muted", label: "No advisories" },
};

/** Options for filtering inventory by why it was not checked (the unchecked parameter). */
export const UNCHECKED_FILTERS: [string, string][] = [
  ["", "Any"],
  ["unreadable_version", "Needs you: no readable version"],
  ["unsupported", "Stackurity doesn't support yet"],
  ["waiting_for_data", "Waiting for vulnerability data"],
  ["no_advisories", "No published advisories"],
];

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
  if (r.unchecked_reason === "no_advisories") return NO_ADVISORIES_NOTE;
  if (r.unchecked_reason === "unreadable_version" && r.unchecked_fix) return `no readable version: ${r.unchecked_fix}`;
  if (r.unchecked_reason === "unsupported") return `Stackurity doesn't check this yet: ${r.coverage_reason || "no vulnerability source"}`;
  if (r.unchecked_reason === "waiting_for_data" && r.coverage !== "stale_intelligence") return "waiting for vulnerability data; this resolves on its own";
  switch (r.coverage) {
    case "not_evaluated":
    case "unsupported":
      return `not checked: ${r.coverage_reason || "no reason recorded"}`;
    case "stale_intelligence":
      return `checked against out-of-date vulnerability data${r.coverage_feed ? ` for ${r.coverage_feed.replace(/^[^:]*:/, "")}` : ""}: newer advisories are missing`;
    case "awaiting":
      return "not checked yet; this resolves on its own";
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
  const actor = row.unchecked_reason ? UNCHECKED_ROW_BADGES[row.unchecked_reason] : undefined;
  return (
    <>
      <div className="coverage-note">
        {actor ? (
          <Badge status={row.unchecked_reason!} tone={actor.tone} label={actor.label} />
        ) : (
          <Badge status={c} tone={ROW_COVERAGE_TONES[c]} label={ROW_COVERAGE_LABELS[c]} />
        )}{" "}
        <span className="small">{coverageText(row)}</span>
        {row.unchecked_docs && (
          <>
            {" "}
            <a className="small" href={row.unchecked_docs} target="_blank" rel="noopener noreferrer">
              How
            </a>
          </>
        )}
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

/** Problems with how the asset reported, as opposed to components that were not checked. */
export function collectionProblems(summary: CoverageSummary): string[] {
  const cl = summary.collection;
  const out: string[] = [];
  if (cl.failed_scopes > 0) out.push(`${plural(cl.failed_scopes, "part")} of the scan failed; components there are not in the inventory`);
  if (cl.status === "stale") out.push(`no report since ${new Date(cl.last_seen).toLocaleString()}; the inventory may be out of date`);
  if (cl.status === "partial") out.push("the last report was incomplete, so components may be missing");
  if (cl.partial_scopes > 0) out.push(`${plural(cl.partial_scopes, "part")} of the scan ${cl.partial_scopes === 1 ? "was" : "were"} only partly read`);
  if (summary.components.total === 0 && !cl.last_collection) out.push("nothing has been reported yet");
  return out;
}

/**
 * The asset's coverage where the user looks at findings: problems with how
 * it reported, then the components that were not checked split by who acts
 * (UncheckedBanner). An asset with neither gets a single quiet line.
 */
export function AssetCoverageNotice({ summary, unchecked, assetId }: { summary: CoverageSummary; unchecked?: Unchecked | null; assetId: number }) {
  const problems = collectionProblems(summary);
  const banner = uncheckedBanner(unchecked);
  return (
    <>
      {problems.length > 0 && (
        <div className="alert alert-warn" role="alert">
          <strong>This asset's last report was incomplete:</strong>
          <ul className="banner-list">
            {problems.map((p) => (
              <li key={p}>{p}.</li>
            ))}
          </ul>
          <Link to={`/assets/${assetId}?tab=coverage`}>See what the scan read</Link>
        </div>
      )}
      <UncheckedBanner u={unchecked} assetId={assetId} />
      {problems.length === 0 && !banner && (
        <p className="coverage-ok">
          <AssetStateBadge state={summary.state} label={summary.label} /> <span className="muted small">{summary.states[0]?.detail}</span>
        </p>
      )}
    </>
  );
}

/** What each asset state means; the same text is in docs/compatibility.md. */
export const ASSET_STATE_MEANINGS: [string, string][] = [
  ["healthy", "Every scope was collected, every component was checked against current intelligence within the last 48 hours."],
  ["stale_intelligence", "Components were checked against vulnerability data that is out of date or failing to update."],
  ["failed_collection", "A collector reported a failed scope, or the asset stopped reporting, so the inventory may be incomplete."],
  ["partially_evaluated", "Some components were not checked (vulnerability data not synced yet, a release with no published advisories, a version that could not be read), or the last report was incomplete."],
  ["unsupported", "Some components or scopes have no vulnerability source (unsupported ecosystem or distribution, runtime outside a package manager)."],
  ["awaiting_verification", "Inventory arrived and has not been evaluated yet, or not within the last 48 hours."],
];
