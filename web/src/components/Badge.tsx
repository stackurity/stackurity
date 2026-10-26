import type { ReactNode } from "react";
import { humanize } from "../format";

export type Tone = "good" | "warn" | "bad" | "muted" | "info" | "crit" | "orange";

// Status words used across assets, coverage, inventory confidence and jobs.
const TONES: Record<string, Tone> = {
  ok: "good",
  checked: "good",
  confirmed: "good",
  done: "good",
  enabled: "good",
  active: "good",
  partial: "warn",
  inferred: "warn",
  pending: "warn",
  stale: "bad",
  failed: "bad",
  unknown: "bad",
  error: "bad",
  revoked: "bad",
  disabled: "muted",
  unsupported: "muted",
  skipped: "muted",
  low: "muted",
  expired: "muted",
  needs_validation: "warn",
  never_synced: "warn",
  resolved: "good",
  open: "bad",
};

export function toneFor(status: string): Tone {
  return TONES[status] ?? "info";
}

/** A status label. The text is always shown; colour is only a secondary cue. */
export function Badge({ status, tone, label, title }: { status: string; tone?: Tone; label?: string; title?: string }) {
  const t = tone ?? toneFor(status);
  return (
    <span className={`badge badge-${t}`} title={title}>
      <span className="badge-dot" aria-hidden="true" />
      {label ?? humanize(status)}
    </span>
  );
}

export function Chip({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <span className="chip" title={title}>
      {children}
    </span>
  );
}

const SEVERITY_TONES: Record<string, Tone> = {
  critical: "crit",
  high: "bad",
  medium: "warn",
  low: "muted",
  none: "muted",
  unknown: "info",
};

export const SEVERITY_EXPLAINED: Record<string, string> = {
  none: "Scored with no impact (CVSS 0.0) by its source.",
  unknown: "No definitive severity: either no source rated it, or the installed version is not confirmed.",
};

/** Severity with optional CVSS-style score, e.g. "high 7.5", or a count, e.g. "3 high". */
export function SeverityBadge({ severity, score, count }: { severity: string; score?: number | null; count?: number }) {
  const sev = severity || "unknown";
  return (
    <span className={`badge badge-${SEVERITY_TONES[sev] ?? "info"} sev`} title={SEVERITY_EXPLAINED[sev]}>
      <span className="badge-dot" aria-hidden="true" />
      {count !== undefined && `${count.toLocaleString()} `}
      {sev}
      {score !== null && score !== undefined && <span className="sev-score">{score.toFixed(1)}</span>}
    </span>
  );
}

export function KevBadge() {
  return (
    <span className="badge badge-crit kev" title="Listed in the CISA Known Exploited Vulnerabilities catalog">
      Known exploited
    </span>
  );
}

export const VERIFICATION_EXPLAINED: Record<string, string> = {
  confirmed: "The installed version was read from an authoritative source (package database or lockfile) and falls in an affected range.",
  needs_validation:
    "The installed version is not confirmed (inferred or low-confidence inventory), so there is no definitive severity. Check the real version on the asset.",
  stale: "The asset's inventory is stale: the component was affected when last seen, but nothing has reported the asset recently.",
  unknown: "The evidence could not be classified: no confirmed version and no recorded source.",
  rejected: "Someone reviewed the evidence and rejected this finding.",
};

export function VerificationBadge({ verification }: { verification: string }) {
  return <Badge status={verification} title={VERIFICATION_EXPLAINED[verification]} label={verification.replace(/_/g, " ")} />;
}

const UPDATE_TONES: Record<string, Tone> = { patch: "muted", minor: "info", major: "warn" };

export function UpdateBadge({ type }: { type: string | undefined }) {
  if (!type) return null;
  return <Badge status={type} tone={UPDATE_TONES[type] ?? "info"} label={`${type} update`} title={`A newer ${type} release is available`} />;
}

// --- Stage 3: priority, SOS, workflow state

const PRIORITY_TONES: Record<string, Tone> = { P1: "crit", P2: "orange", P3: "warn", P4: "muted" };
const PRIORITY_TITLES: Record<string, string> = {
  P1: "P1: act immediately",
  P2: "P2: high priority",
  P3: "P3: medium priority",
  P4: "P4: low priority",
};

export function PriorityBadge({ priority, score }: { priority: string | undefined | null; score?: number | null }) {
  if (!priority) return <span className="muted small">no priority</span>;
  return (
    <span className={`badge badge-${PRIORITY_TONES[priority] ?? "info"} prio`} title={PRIORITY_TITLES[priority]}>
      {priority}
      {score !== undefined && score !== null && <span className="sev-score">{score.toFixed(1)}</span>}
    </span>
  );
}

export function SosBadge({ rule }: { rule?: string }) {
  return (
    <span className="badge badge-crit sos" title={rule ? `SOS rule: ${rule}` : "Matches an SOS rule: needs urgent attention"}>
      SOS
      {rule && <span className="sr-only">: {rule}</span>}
    </span>
  );
}

const STATE_TONES: Record<string, Tone> = {
  new: "bad",
  acknowledged: "warn",
  in_progress: "info",
  suppressed: "muted",
  risk_accepted: "muted",
  resolved: "good",
  mixed: "info",
};

export const STATE_EXPLAINED: Record<string, string> = {
  new: "Nobody has acknowledged it yet",
  acknowledged: "Someone has seen it; the fix deadline still applies",
  in_progress: "A fix is being worked on",
  suppressed: "Hidden until the expiry date (security decision)",
  risk_accepted: "Risk formally accepted until the expiry date (security decision)",
};

export function StateBadge({ state }: { state: string | undefined | null }) {
  const s = state || "new";
  return <Badge status={s} tone={STATE_TONES[s] ?? "info"} label={s === "suppressed" ? "snoozed" : s.replace(/_/g, " ")} title={STATE_EXPLAINED[s]} />;
}

export function EscalationBadge({ level }: { level: number | undefined | null }) {
  if (!level) return null;
  if (level >= 2) return <Badge status="fix_overdue" tone="crit" label="Fix overdue" title="The fix deadline has passed" />;
  return <Badge status="ack_overdue" tone="bad" label="Ack overdue" title="The acknowledgement deadline has passed" />;
}

const ASSET_KIND_TEXT: Record<string, string> = {
  host: "host",
  repository: "repository",
  image: "image",
  application: "application",
  managed_service: "managed service",
  sbom: "SBOM",
  cluster: "cluster",
  workload: "workload",
};

export function AssetKindBadge({ kind }: { kind: string }) {
  return (
    <Badge
      status={kind}
      tone={kind === "managed_service" || kind === "cluster" ? "info" : "muted"}
      label={ASSET_KIND_TEXT[kind] ?? kind.replace(/_/g, " ")}
    />
  );
}

/** Whether an asset is reachable from outside: set by hand, reported by a
 * collector (Kubernetes Services, Ingresses, host ports), or inherited by an
 * image from the workloads running it. Nothing is shown when unknown. */
export function ExposureBadge({ asset }: { asset: { exposed: boolean | null; internet_exposed: boolean | null; kind: string; attributes: Record<string, string> | null } }) {
  const at = asset.attributes ?? {};
  if (asset.exposed === null) {
    if (at.exposure === "unknown")
      return <Badge status="exposure_unknown" tone="muted" label="exposure unknown" title="Services or Ingresses could not be read" />;
    return null;
  }
  if (!asset.exposed) return <Badge status="internal" tone="muted" label="internal" title={asset.internet_exposed === false ? "Set by hand" : "Not reachable from outside the cluster"} />;
  const title =
    asset.internet_exposed === true
      ? "Set by hand"
      : at.exposed_via
        ? `Reachable from outside the cluster: ${at.exposed_via}`
        : asset.kind === "image"
          ? "Run by a workload that is reachable from outside its cluster"
          : "Reachable from outside";
  return <Badge status="exposed" tone="warn" label="exposed" title={title} />;
}

// --- Stage 6: operational signals

/** A Linux host running older code (kernel or libraries) than is installed. */
export function RebootBadge({ reason }: { reason?: string }) {
  return (
    <Badge
      status="reboot_required"
      tone="warn"
      label="Reboot pending"
      title={reason ? `Reboot needed: ${reason}` : "Running older code than is installed; a reboot is needed to load the updates"}
    />
  );
}

/** Software found outside the package manager (binary on disk). */
export function UnmanagedBadge({ title }: { title?: string }) {
  return <Badge status="unmanaged" tone="info" label="outside package manager" title={title} />;
}

// --- Stage 7: applications discovered on hosts

/** Where an application's library was read from: its installed files or only a lockfile. */
export function AppSourceBadge({ source }: { source: string | undefined }) {
  if (source === "installed")
    return <Badge status="installed" tone="muted" label="installed" title="Read from the application's installed files" />;
  if (source === "lockfile")
    return (
      <Badge
        status="lockfile"
        tone="muted"
        label="from lockfile"
        title="Read from a lockfile only; the installed files were not found, so the deployed version may differ"
      />
    );
  return null;
}

/** A library installed host-wide rather than in one application's directory. */
export function GlobalBadge() {
  return <Badge status="global" tone="muted" label="global" title="Installed host-wide, shared by every application on the host" />;
}

const DRIFT_TONES: Record<string, Tone> = { behind: "warn", only_there: "warn", differs: "info", ahead: "muted", only_here: "muted" };

export function DriftBadge({ status, label, title }: { status: string; label: string; title?: string }) {
  return <Badge status={status} tone={DRIFT_TONES[status] ?? "info"} label={label} title={title} />;
}
