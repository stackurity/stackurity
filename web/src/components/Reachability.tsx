import type { ReactNode } from "react";
import type { ReachabilityDetail, ReachabilityStatus } from "../api";
import { useAuth } from "../auth";
import { Badge, type Tone } from "./Badge";
import { ProNotice } from "./ProNotice";

const LABELS: Record<ReachabilityStatus, string> = {
  unknown: "Not assessed",
  reachable: "Reachable",
  not_imported: "Not imported",
  not_running: "Not running",
};

const TITLES: Record<ReachabilityStatus, string> = {
  unknown: "No evidence either way, so it counts as reachable",
  reachable: "First-party code imports it, or a running process uses it",
  not_imported: "No first-party source file imports it",
  not_running: "No running process executes it or has it loaded",
};

// Not reached is information, not an all-clear: never shown as "good".
const TONES: Record<ReachabilityStatus, Tone> = {
  unknown: "muted",
  reachable: "warn",
  not_imported: "info",
  not_running: "info",
};

function known(s: string | undefined): ReachabilityStatus {
  return s && s in LABELS ? (s as ReachabilityStatus) : "unknown";
}

/** Whether a finding's package is imported or running on its asset. */
export function ReachabilityBadge({ status }: { status?: string }) {
  const s = known(status);
  return (
    <Badge status={s} tone={TONES[s]} label={LABELS[s]} title={TITLES[s]} />
  );
}

/**
 * Whether to show the paid-plan notice: the package is not reached, the
 * priority was neither lowered nor kept, and the plan lacks the downgrade.
 */
export function showReachabilityNotice(
  d: ReachabilityDetail,
  licensed: boolean,
): boolean {
  return (
    (d.status === "not_imported" || d.status === "not_running") &&
    !d.lowered &&
    !d.kept &&
    !licensed
  );
}

/** The reachability part of "why this priority": status, evidence and what it did to the priority. */
export function ReachabilityWhy({ d }: { d: ReachabilityDetail }) {
  const { has } = useAuth();
  return (
    <ReachabilityWhyView d={d}>
      {showReachabilityNotice(d, has("reachability")) && (
        <ProNotice feature="reachability">
          On a paid plan this finding would be one priority level lower; it
          stays listed, and known exploited issues on internet-facing assets are
          never lowered.{" "}
        </ProNotice>
      )}
    </ReachabilityWhyView>
  );
}

/** ReachabilityWhy without the auth context; children follow the evidence. */
export function ReachabilityWhyView({
  d,
  children,
}: {
  d: ReachabilityDetail;
  children?: ReactNode;
}) {
  return (
    <div className="reachability-why">
      <p className="small">
        <ReachabilityBadge status={d.status} /> {d.text}
      </p>
      {d.evidence.length > 0 && (
        <ul className="small">
          {d.evidence.map((e, i) => (
            <li key={i} className="break">
              {e}
            </li>
          ))}
        </ul>
      )}
      {children}
    </div>
  );
}
