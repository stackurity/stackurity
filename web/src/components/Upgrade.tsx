import type { ReactNode } from "react";
import { safeHttpUrl, type UpgradeLine, type UpgradeRecommendation } from "../api";
import { Badge, UpdateBadge } from "./Badge";
import { Card, KeyValues, RelativeTime } from "./ui";

const BASIS_LABEL: Record<string, string> = {
  distro_fixed: "the distribution's fixed build",
  distro_source_fixed: "the distribution's fixed build of the source package",
  vendor_upstream_fixed: "the upstream release that fixes it, from the vendor's repository",
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
  const src = rec.source;
  if (src && src.fixed_source_version)
    // apt has no such version of the binary package: name the source build.
    return (
      <span className="badges">
        <span>
          <span className="mono">{src.package}</span> built from <span className="mono">{src.source_package} {src.fixed_source_version}</span>{" "}
          or later
        </span>
        <Badge status="distro" tone="muted" label="distro update" />
        {rec.requires_subscription && (
          <Badge
            status="subscription"
            tone="warn"
            label={`${rec.requires_subscription} (paid)`}
            title={`This build is published only in ${rec.requires_subscription}, a paid subscription; without it, upgrade to a supported release or wait for a free fix`}
          />
        )}
      </span>
    );
  if (!rec.recommended_version) return <span className="muted">none</span>;
  return (
    <span className="badges">
      <span className="mono">{rec.recommended_version}</span>
      {rec.change_type === "distro" ? <Badge status="distro" tone="muted" label="distro update" /> : <UpdateBadge type={rec.change_type} />}
      {rec.recommended_yanked && <Badge status="withdrawn" tone="bad" label="withdrawn" title={rec.yanked_reason || "withdrawn by the registry"} />}
      {rec.requires_subscription && (
        <Badge
          status="subscription"
          tone="warn"
          label={`${rec.requires_subscription} (paid)`}
          title={`This build is published only in ${rec.requires_subscription}, a paid subscription; without it, upgrade to a supported release or wait for a free fix`}
        />
      )}
    </span>
  );
}

function keyList(keys: string[] | null | undefined): ReactNode {
  if (!keys || keys.length === 0) return <span className="muted">none</span>;
  return <span className="mono small break">{keys.join(", ")}</span>;
}

/** The first numeric part of a version ("13" of "13.4.0"), for semver-like versions only. */
export function majorOf(v: string | null | undefined): string | null {
  const m = /^v?(\d+)\.\d+/.exec(v ?? "");
  return m ? m[1] : null;
}

/**
 * Facts and reasons behind an upgrade recommendation. The recommendation
 * covers every open issue on the package; `issueFix` is the version that
 * fixes the one issue on screen, so a page about that issue can say when it
 * alone has a smaller fix than the recommendation (a customer must never
 * read a major upgrade as required when a minor one fixes their issue).
 */
export function UpgradeDetails({ rec, issueFix }: { rec: UpgradeRecommendation; issueFix?: string | null }) {
  const issues = (rec.fixes ?? []).length;
  const smallerIssueFix = !!issueFix && !!rec.minimum_fixed_version && issueFix !== rec.minimum_fixed_version;
  const issueInLine = smallerIssueFix && majorOf(issueFix) !== null && majorOf(issueFix) === majorOf(rec.installed_version);
  const entries: [string, ReactNode][] = [
    [
      "installed",
      <span>
        <span className="mono">{rec.installed_version || "unknown"}</span>
        {rec.source && (
          <span className="muted small">
            {" "}
            (built from <span className="mono">{rec.source.source_package} {rec.source.installed_source_version}</span>)
          </span>
        )}
      </span>,
    ],
  ];
  if (smallerIssueFix)
    entries.push([
      "fixes this issue",
      <span className="badges">
        <span className="mono">{issueFix}</span>
        {issueInLine && <Badge status="in_line" tone="good" label="same major line" />}
      </span>,
    ]);
  entries.push(
    [
      // No count here: `fixes` can include an end-of-life entry, which the
      // fix's own "N issues fixed together" does not, and the two must not disagree.
      smallerIssueFix && issues > 1 ? "minimum for everything it resolves" : "minimum fixed",
      rec.minimum_fixed_version ? (
        <span className="badges">
          <span className="mono">
            {rec.source ? `${rec.source.source_package} ` : ""}
            {rec.minimum_fixed_version}
          </span>
          {rec.minimum_fixed_yanked && <Badge status="withdrawn" tone="bad" label="withdrawn" />}
        </span>
      ) : (
        <span className="muted">no fixed version listed</span>
      ),
    ],
    ["recommended", <RecommendedVersion rec={rec} />],
    ["based on", BASIS_LABEL[rec.basis] ?? rec.basis],
  );
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
      {rec.requires_major && issueInLine && (
        <div className="alert alert-warn" role="alert">
          <strong>This issue alone is fixed in {issueFix}</strong>, in the installed {majorOf(rec.installed_version)}.x line. The recommendation goes
          to <span className="mono">{rec.recommended_version || rec.minimum_fixed_version}</span>, a major upgrade, because it is the smallest
          version that also fixes the other open issues on this package
          {rec.lifecycle?.status === "end_of_life" ? `, and the ${rec.lifecycle.product} ${rec.lifecycle.cycle} line is end of life` : ""}.
          Expect breaking changes and test before rolling out; upgrading to {issueFix} first closes this issue sooner.
        </div>
      )}
      {rec.requires_major && !issueInLine && (
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

export function UpgradeCard({ rec, issueFix }: { rec: UpgradeRecommendation; issueFix?: string | null }) {
  return (
    <Card title="Upgrade recommendation">
      <p className="hint">
        Built only from stored advisory, registry release and end-of-life data. Where data is missing it says so rather than guessing.
      </p>
      <UpgradeDetails rec={rec} issueFix={issueFix} />
    </Card>
  );
}
