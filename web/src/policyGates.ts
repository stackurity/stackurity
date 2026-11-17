/**
 * Policy gates as the dashboard says them (docs/policy-gates.md): what each
 * rule means in words, where a policy applies, its draft in the form, and
 * the violation counts the pages and the Dashboard show. Kept free of React
 * and of imports other than types so node --test can load it
 * (policyGates.test.ts).
 */
import type { GateFilters, GateKind, GateMode, GatePolicy, GatePolicyItem, GatePolicyRequest, GateViolation } from "./api";

// format.ts's, repeated: node --test loads this file without a bundler.
function plural(n: number, word: string, many = word + "s"): string {
  return `${n.toLocaleString()} ${n === 1 ? word : many}`;
}

function joinAnd(parts: string[], last = "and"): string {
  if (parts.length <= 1) return parts.join("");
  return `${parts.slice(0, -1).join(", ")} ${last} ${parts[parts.length - 1]}`;
}

// --- rules

export interface KindOption {
  value: GateKind;
  label: string;
  description: string;
}

/** The rule kinds, in the order the server lists them (store.GateKinds). */
export const GATE_KINDS: KindOption[] = [
  {
    value: "known_exploited",
    label: "Known exploited vulnerabilities",
    description: "Fails when an open vulnerability on an asset is on the CISA list of vulnerabilities attackers are known to use.",
  },
  {
    value: "end_of_life",
    label: "End-of-life components",
    description: "Fails when a component, such as a runtime or an operating system, is past its end of life and gets no more security fixes.",
  },
  {
    value: "finding_age",
    label: "Vulnerabilities left open too long",
    description: "Fails when an open vulnerability of the severity you choose has been open longer than the number of days you allow.",
  },
  {
    value: "leaked_key",
    label: "Leaked keys",
    description: "Fails when a key or password found written in an asset's files is still open.",
  },
];

export function kindLabel(k: string): string {
  return GATE_KINDS.find((o) => o.value === k)?.label ?? k.replace(/_/g, " ");
}

export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

/** "critical", "high or critical", "medium or higher", "any severity". */
export function severityAtLeast(min: string): string {
  switch (min) {
    case "critical":
      return "critical";
    case "high":
      return "high or critical";
    case "medium":
      return "medium or higher";
    default:
      return "any severity";
  }
}

const str = (v: unknown, d = ""): string => (typeof v === "string" ? v : d);
const num = (v: unknown, d: number): number => (typeof v === "number" && Number.isFinite(v) ? v : d);
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

/** What the rule fails on, in one line: "Critical vulnerabilities open more than 14 days, with a fix". */
export function ruleSummary(kind: string, params: Record<string, unknown> | null | undefined): string {
  const p = params ?? {};
  switch (kind) {
    case "known_exploited":
      return "Known exploited vulnerabilities";
    case "end_of_life": {
      const products = strs(p.products);
      return products.length ? `Components past end of life: ${products.join(", ")}` : "Components past end of life";
    }
    case "finding_age": {
      const sev = severityAtLeast(str(p.min_severity, "critical"));
      const days = num(p.max_days, 0);
      const what = sev === "any severity" ? "Vulnerabilities" : `${sev[0].toUpperCase()}${sev.slice(1)} vulnerabilities`;
      return `${what} open more than ${plural(days, "day")}${p.only_fixable ? ", when a fix exists" : ""}`;
    }
    case "leaked_key": {
      const min = str(p.min_severity, "low");
      const sev = min === "low" ? "" : ` (${severityAtLeast(min)})`;
      return `Open leaked keys${sev}${p.served_only ? ", in files served to the network" : ""}`;
    }
  }
  return kindLabel(kind);
}

const KIND_WORDS: Record<string, string> = {
  host: "servers",
  repository: "repositories",
  image: "images",
  application: "applications",
  managed_service: "managed services",
  sbom: "SBOMs",
  cluster: "clusters",
  workload: "workloads",
};

/** The assets a policy looks at: "Every asset", or "Repositories in production, internet-facing, tagged pci". */
export function filterSummary(f: Partial<GateFilters> | null | undefined): string {
  const kinds = (f?.asset_kinds ?? []).map((k) => KIND_WORDS[k] ?? k.replace(/_/g, " "));
  const envs = f?.environments ?? [];
  const tags = f?.tags ?? [];
  const parts: string[] = [];
  let head = kinds.length ? joinAnd(kinds, "or") : "Every asset";
  head = head[0].toUpperCase() + head.slice(1);
  if (envs.length) head += ` in ${joinAnd(envs, "or")}`;
  parts.push(head);
  if (f?.exposure === "exposed") parts.push("internet-facing");
  if (tags.length) parts.push(`tagged ${joinAnd(tags, "or")}`);
  return parts.join(", ");
}

/** Where an organisation policy is turned off: the design's "off for 2 projects". */
export function scopeSummary(p: Pick<GatePolicyItem, "off_projects" | "off_assets">): string {
  const parts: string[] = [];
  if (p.off_projects?.length) parts.push(plural(p.off_projects.length, "project"));
  if (p.off_assets?.length) parts.push(plural(p.off_assets.length, "asset"));
  return parts.length ? `Off for ${parts.join(" and ")}` : "Applies everywhere";
}

// --- modes

export const MODE_LABELS: Record<GateMode, string> = { off: "Off", warn: "Warn", enforce: "Enforce" };

/** The mode badge's tone: a mode is a setting, not urgency, so never red. */
export function modeTone(mode: GateMode): "muted" | "info" | "warn" {
  return mode === "off" ? "muted" : mode === "enforce" ? "warn" : "info";
}

export interface ModeOption {
  value: GateMode;
  label: string;
  description: string;
  /** Enforce: failing builds needs a paid plan this workspace does not have. */
  needsPlan?: boolean;
}

/**
 * The three modes for ChoiceCards. enforceAvailable: the workspace's plan
 * lets enforce fail a build (the gate_enforce feature). Without it,
 * enforce can still be picked: checks then report its violations as
 * warnings, and the option says so.
 */
export function modeOptions(enforceAvailable: boolean): ModeOption[] {
  return [
    { value: "off", label: "Off", description: "Not checked anywhere. Its violations are not counted." },
    {
      value: "warn",
      label: "Warn",
      description: "CI and deploy checks print its violations and pass. New policies start here, so turning one on never breaks a build by surprise.",
    },
    {
      value: "enforce",
      label: "Enforce",
      description: enforceAvailable
        ? "A violation fails the CI job or the deploy check."
        : "A violation fails the CI job or the deploy check on a paid plan. On this plan checks still pass and report it as a warning (\"not enforced on this plan\").",
      needsPlan: !enforceAvailable,
    },
  ];
}

// --- violations

export interface ViolationCount {
  violations: number;
  assets: number;
}

/** Violations per policy, with how many assets they are on. */
export function violationCounts(vs: GateViolation[] | null | undefined): Map<number, ViolationCount> {
  const assets = new Map<number, Set<number>>();
  const out = new Map<number, ViolationCount>();
  for (const v of vs ?? []) {
    const c = out.get(v.policy_id) ?? { violations: 0, assets: 0 };
    c.violations++;
    const set = assets.get(v.policy_id) ?? new Set<number>();
    set.add(v.asset_id);
    assets.set(v.policy_id, set);
    c.assets = set.size;
    out.set(v.policy_id, c);
  }
  return out;
}

export interface ViolationTotals {
  violations: number;
  assets: number;
  policies: number;
  /** Violations of policies in enforce mode. */
  enforced: number;
}

export function violationTotals(vs: GateViolation[] | null | undefined): ViolationTotals {
  const list = vs ?? [];
  return {
    violations: list.length,
    assets: new Set(list.map((v) => v.asset_id)).size,
    policies: new Set(list.map((v) => v.policy_id)).size,
    enforced: list.filter((v) => v.mode === "enforce").length,
  };
}

/** "3 violations on 2 assets", or "No violations". */
export function violationText(c: ViolationCount | undefined): string {
  if (!c || c.violations === 0) return "No violations";
  return `${plural(c.violations, "violation")} on ${plural(c.assets, "asset")}`;
}

/** The Violations page, narrowed: "/fixes/policy-violations?policy_id=3". */
export const VIOLATIONS_PATH = "/fixes/policy-violations";
export function violationsLink(q: { policy_id?: number; asset_id?: number; project_id?: number } = {}): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) if (v) p.set(k, String(v));
  const s = p.toString();
  return s ? `${VIOLATIONS_PATH}?${s}` : VIOLATIONS_PATH;
}

/** Narrows the violations by the page's filters that the server does not apply (mode, kind). */
export function filterViolations(vs: GateViolation[], f: { mode?: string | null; kind?: string | null }): GateViolation[] {
  return vs.filter((v) => (!f.mode || v.mode === f.mode) && (!f.kind || v.kind === f.kind));
}

// --- the form

/** A policy as the form edits it: lists as comma-separated text, numbers as typed. */
export interface PolicyDraft {
  name: string;
  description: string;
  kind: GateKind;
  mode: GateMode;
  /** end_of_life */
  products: string;
  after: string;
  /** finding_age */
  minSeverity: Severity;
  maxDays: string;
  onlyFixable: boolean;
  /** leaked_key */
  leakMinSeverity: Severity;
  servedOnly: boolean;
  /** filters */
  assetKinds: string[];
  environments: string;
  exposure: "any" | "exposed";
  tags: string;
}

/** A new policy: warn mode, so it never fails a build the moment it is saved. */
export function newDraft(kind: GateKind = "known_exploited"): PolicyDraft {
  return {
    name: "",
    description: "",
    kind,
    mode: "warn",
    products: "",
    after: "",
    minSeverity: "critical",
    maxDays: "14",
    onlyFixable: true,
    leakMinSeverity: "low",
    servedOnly: false,
    assetKinds: [],
    environments: "",
    exposure: "any",
    tags: "",
  };
}

const asSeverity = (v: unknown, d: Severity): Severity => ((SEVERITIES as readonly string[]).includes(str(v)) ? (str(v) as Severity) : d);

export function draftFrom(p: GatePolicy): PolicyDraft {
  const d = newDraft(p.kind);
  const q = p.params ?? {};
  return {
    ...d,
    name: p.name,
    description: p.description ?? "",
    mode: p.mode,
    products: strs(q.products).join(", "),
    after: str(q.after),
    minSeverity: asSeverity(q.min_severity, "critical"),
    maxDays: p.kind === "finding_age" ? String(num(q.max_days, 14)) : d.maxDays,
    onlyFixable: p.kind === "finding_age" ? Boolean(q.only_fixable) : d.onlyFixable,
    leakMinSeverity: asSeverity(q.min_severity, "low"),
    servedOnly: Boolean(q.served_only),
    assetKinds: p.filters?.asset_kinds ?? [],
    environments: (p.filters?.environments ?? []).join(", "),
    exposure: p.filters?.exposure === "exposed" ? "exposed" : "any",
    tags: (p.filters?.tags ?? []).join(", "),
  };
}

/** "python, nodejs ,, " to ["python", "nodejs"]. */
export function splitList(text: string): string[] {
  const out: string[] = [];
  for (const v of text.split(/[,\n]/)) {
    const t = v.trim();
    if (t && !out.includes(t)) out.push(t);
  }
  return out;
}

/** The request the form sends, or what to fix first, in words. */
export function draftToRequest(d: PolicyDraft): { request?: GatePolicyRequest; error?: string } {
  const name = d.name.trim();
  if (!name) return { error: "Give the policy a name." };
  if (name.length > 200) return { error: "Keep the name to 200 characters." };
  let params: Record<string, unknown> = {};
  switch (d.kind) {
    case "end_of_life": {
      const after = d.after.trim();
      if (after && !/^\d{4}-\d{2}-\d{2}$/.test(after)) return { error: "The date must look like 2027-03-31." };
      params = { products: splitList(d.products).map((x) => x.toLowerCase()), ...(after ? { after } : {}) };
      break;
    }
    case "finding_age": {
      const days = Number(d.maxDays);
      if (!Number.isInteger(days) || days < 1 || days > 3650) return { error: "The number of days must be a whole number from 1 to 3650." };
      params = { min_severity: d.minSeverity, max_days: days, only_fixable: d.onlyFixable };
      break;
    }
    case "leaked_key":
      params = { min_severity: d.leakMinSeverity, served_only: d.servedOnly };
      break;
  }
  return {
    request: {
      name,
      description: d.description.trim(),
      kind: d.kind,
      params,
      filters: { asset_kinds: d.assetKinds, environments: splitList(d.environments), exposure: d.exposure, tags: splitList(d.tags) },
      mode: d.mode,
    },
  };
}

/** What the mode means for checks right now, for the form's footer. */
export function modeStatus(mode: GateMode, enforceAvailable: boolean, isNew: boolean): string {
  switch (mode) {
    case "off":
      return "Off: CI and deploy checks ignore this policy and it has no violations.";
    case "warn":
      return isNew
        ? "New policies start in warn: CI and deploy checks print violations and pass. Switch to enforce once the list is clean."
        : "Warn: CI and deploy checks print violations and pass.";
    case "enforce":
      return enforceAvailable
        ? "Enforce: a violation fails the CI job or the deploy check."
        : "Enforce on this plan: checks report violations as warnings and pass. A paid plan makes them fail.";
  }
}
