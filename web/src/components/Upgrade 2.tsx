import type { ReactNode } from "react";
import { safeHttpUrl, type UpgradeLine, type UpgradeRecommendation } from "../api";
import { Badge, UpdateBadge } from "./Badge";
import { Card, KeyValues, RelativeTime } from "./ui";

const BASIS_LABEL: Record<string, string> = {
  distro_fixed: "the distribution's fixed build",
  latest_in_line: "newest stable release in the major line",
  minimum_fixed: "minimum fixed version",
  supported_line: "newest release of a supported line",
  none: "nothing to recommend",
};

const RELEASE_DATA_LABEL: Record<string, string> = {
  available: "available",
  none: "no release data",
  failed: "the last registry lookup failed",
  not_applicable: "not used for OS packages",
};

const LINE_STATUS: Record<string, { label: string; tone: "good" | "warn" | "bad" }> = {
  supported: { label: "supported", tone: "good" },
  security_only: { label: "security fixes only", tone: "warn" },
  end_of_life: { label: "end of life", tone: "bad" },
};

export function LineStatus({ line }: { line: UpgradeLine | null | undefined }) {
  if (!line) return <span className="muted">no lifecycle data</span>;
  const s = LINE_STATUS[line.status] ?? { label: line.status, tone: "warn" as const };
  const link = safeHttpUrl(line.link ?? null);
  return (
    <span>
      <span className="mono">
        {line.product} {line.cycle}
      </span>{" "}
      <Badge status={line.status} tone={s.tone} label={s.label} />
      {line.eol_date && <span className="muted small"> (end of life {line.eol_date.slice(0, 10)})</span>}
      {link && (
        <>
          {" "}
          <a href={link} target="_blank" rel="noopener noreferrer" className="small">
            endoflife.date<span className="sr-only"> (opens in a new tab)</span>
          </a>
        </>
      )}
    </span>
  );
}

/** The recommended version with its change type and warnings. */
export function RecommendedVersion({ rec }: { rec: UpgradeRecommendation }) {
  if (!rec.recommended_version) return <span className="muted">none</span>;
  return (
    <span className="badges">
      <span className="mono">{rec.recommended_version}</span>
      {rec.change_type === "distro" ? <Badge status="distro" tone="muted" label="distro update" /> : <UpdateBadge type={rec.change_type} />}
      {rec.recommended_yanked && <Badge status="withdrawn" tone="bad" label="withdrawn" title={rec.yanked_reason || "withdrawn by the registry"} />}
      {rec.requires_subscription && <Badge status="subscription" tone="warn" label={rec.requires_subscription} />}
    </span>
  );
}

function keyList(keys: string[] | null | undefined): ReactNode {
  if (!keys || keys.length === 0) return <span className="muted">none</span>;
  return <span className="mono small break">{keys.join(", ")}</span>;
}

/** Facts and reasons behind an upgrade recommendation. */
export function UpgradeDetails({ rec }: { rec: UpgradeRecommendation }) {
  const entries: [string, ReactNode][] = [
    ["installed", <span className="mono">{rec.installed_version || "unknown"}</span>],
    [
      "minimum fixed",
      rec.minimum_fixed_version ? (
        <span className="badges">
          <span className="mono">{rec.minimum_fixed_version}</span>
          {rec.minimum_fixed_yanked && <Badge status="withdrawn" tone="bad" label="withdrawn" />}
        </span>
      ) : (
        <span className="muted">no fixed version listed</span>
      ),
    ],
    ["recommended", <RecommendedVersion rec={rec} />],
    ["based on", BASIS_LABEL[rec.basis] ?? rec.basis],
  ];
  if (rec.latest_stable) entries.push(["latest stable", <span className="mono">{rec.latest_stable}</span>]);
  entries.push([
    "release data",
    <>
      {RELEASE_DATA_LABEL[rec.release_data] ?? rec.release_data}
      {rec.release_source && <span className="muted small"> ({rec.release_source}</span>}
      {rec.release_source && rec.release_checked_at && (
        <span className="muted small">
          , checked <RelativeTime iso={rec.release_checked_at} />
        </span>
      )}
      {rec.release_source && <span className="muted small">)</span>}
    </>,
  ]);
  entries.push(["installed line", <LineStatus line={rec.lifecycle} />]);
  if (rec.target_lifecycle) entries.push(["recommended line", <LineStatus line={rec.target_lifecycle} />]);
  if (rec.supported_line && rec.supported_line.cycle !== rec.target_lifecycle?.cycle)
    entries.push(["oldest supported line after it", <LineStatus line={rec.supported_line} />]);
  entries.push(["resolves", keyList(rec.fixes)]);
  if (rec.unfixed && rec.unfixed.length > 0) entries.push(["does not resolve", keyList(rec.unfixed)]);
  return (
    <>
      {rec.requires_major && (
        <div className="alert alert-warn" role="alert">
          <strong>Major upgrade:</strong> the fix is only in a new major version; expect breaking changes and test before rolling out.
        </div>
      )}
      {rec.deprecated && (
        <div className="alert alert-warn" role="alert">
          <strong>Deprecated by its maintainers:</strong> {rec.deprecated}
        </div>
      )}
      <KeyValues entries={entries} />
      {rec.rationale && rec.rationale.length > 0 && (
        <>
          <h4 className="small">Why</h4>
          <ul className="small">
            {rec.rationale.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </>
      )}
    </>
  );
}

export function UpgradeCard({ rec }: { rec: UpgradeRecommendation }) {
  return (
    <Card title="Upgrade recommendation">
      <p className="hint">
        Built only from stored advisory, registry release and end-of-life data. Where data is missing it says so rather than guessing.
      </p>
      <UpgradeDetails rec={rec} />
    </Card>
  );
}
