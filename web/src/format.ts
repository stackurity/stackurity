export function absTime(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short",
  });
}

export function relTime(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "never";
  const t = new Date(iso).getTime();
  if (isNaN(t)) return iso;
  const s = Math.round((now - t) / 1000);
  const future = s < 0;
  const a = Math.abs(s);
  let out: string;
  if (a < 45) out = "just now";
  else if (a < 90) out = "1 min";
  else if (a < 3600) out = `${Math.round(a / 60)} min`;
  else if (a < 5400) out = "1 hour";
  else if (a < 86400) out = `${Math.round(a / 3600)} hours`;
  else if (a < 172800) out = "1 day";
  else if (a < 86400 * 45) out = `${Math.round(a / 86400)} days`;
  else if (a < 86400 * 365) out = `${Math.round(a / (86400 * 30))} months`;
  else out = `${(a / (86400 * 365)).toFixed(1)} years`;
  if (out === "just now") return out;
  return future ? `in ${out}` : `${out} ago`;
}

export function componentName(namespace: string, name: string): string {
  return namespace ? `${namespace}/${name}` : name;
}

export function plural(n: number, word: string, pluralWord = word + "s"): string {
  return `${n.toLocaleString()} ${n === 1 ? word : pluralWord}`;
}

/** A duration given in days, pluralised and without false precision:
 * "under a minute", "1 minute", "1 hour", "5 hours", "1 day", "2.5 days", "12 days". */
export function durationDays(v: number): string {
  const minutes = v * 1440;
  if (minutes < 1) return "under a minute";
  if (minutes < 59.5) return plural(Math.round(minutes), "minute");
  if (v * 24 < 23.5) return plural(Math.round(v * 24), "hour");
  if (v < 9.95) {
    const d = Math.round(v * 10) / 10;
    return `${d.toLocaleString()} ${d === 1 ? "day" : "days"}`;
  }
  return plural(Math.round(v), "day");
}

/** "1 day", "30 days": a whole number of days. */
export function dayCount(n: number): string {
  return plural(n, "day");
}

export function humanize(s: string): string {
  return s.replace(/_/g, " ");
}

export function minutesLabel(m: number): string {
  if (m % 1440 === 0) return plural(m / 1440, "day");
  if (m % 60 === 0) return plural(m / 60, "hour");
  return plural(m, "minute");
}

/** Human-readable purl: percent-decoding makes generic purls such as
 * pkg:generic/7-Zip%2023.01%20%28x64%29 legible. Display only. */
export function displayPurl(purl: string): string {
  try {
    return decodeURIComponent(purl);
  } catch {
    return purl;
  }
}

export const ASSET_KIND_LABEL: Record<string, string> = {
  host: "Server",
  repository: "Repository",
  image: "Container image",
  application: "Application",
  managed_service: "Managed service",
  sbom: "SBOM",
  cluster: "Kubernetes cluster",
  workload: "Workload",
};

export function assetKindLabel(kind: string): string {
  return ASSET_KIND_LABEL[kind] ?? humanize(kind);
}

/** Plural kind headings for grouped asset lists ("Hosts", "Repositories"). */
export const ASSET_KIND_GROUP: Record<string, string> = {
  host: "Servers",
  application: "Applications",
  repository: "Repositories",
  image: "Container images",
  managed_service: "Managed services",
  sbom: "SBOMs",
  cluster: "Kubernetes clusters",
  workload: "Workloads",
};

/** Lower-case kind words for telling assets apart: "commmerceblog (server)". */
export const ASSET_KIND_SHORT: Record<string, string> = {
  host: "server",
  application: "app",
  repository: "repository",
  image: "image",
  managed_service: "managed service",
  sbom: "SBOM",
  cluster: "cluster",
  workload: "workload",
};

/** The order kinds are grouped in: servers, then what runs on them, then the rest. */
const KIND_ORDER = ["host", "application", "repository", "image", "workload", "cluster", "managed_service", "sbom"];

interface NamedAsset {
  id: number;
  name: string;
  kind: string;
  environment?: string;
  collection_status?: string;
  attributes?: Record<string, string> | null;
}

/**
 * What tells an asset apart from others with the same name in a list:
 * nothing when its name is unique; the kind when the others are of another
 * kind (a server and a repository both called "commmerceblog"); otherwise
 * an application's path, the environment or the id. "removed" is added for
 * an application that is gone from its host.
 */
export function assetDistinctions<T extends NamedAsset>(list: T[]): Map<number, string> {
  const byName = new Map<string, T[]>();
  for (const a of list) byName.set(a.name, [...(byName.get(a.name) ?? []), a]);
  const out = new Map<number, string>();
  for (const a of list) {
    const same = byName.get(a.name) ?? [];
    const parts: string[] = [];
    if (same.length > 1) {
      const sameKind = same.filter((x) => x.kind === a.kind);
      if (sameKind.length < same.length) parts.push(ASSET_KIND_SHORT[a.kind] ?? humanize(a.kind));
      if (sameKind.length > 1) {
        const dir = a.kind === "application" ? a.attributes?.app_dir : "";
        const envs = new Set(sameKind.map((x) => x.environment ?? ""));
        parts.push(dir || (envs.size === sameKind.length && a.environment ? a.environment : `#${a.id}`));
      }
    }
    if (a.collection_status === "removed") parts.push("removed");
    if (parts.length) out.set(a.id, parts.join(", "));
  }
  return out;
}

/** "commmerceblog (Repository)": the name with what tells it apart, if anything does. */
export function assetLabel(a: NamedAsset, distinctions: Map<number, string>): string {
  const d = distinctions.get(a.id);
  return d ? `${a.name} (${d})` : a.name;
}

/** Assets grouped by kind, in a stable kind order, names sorted within each. */
export function groupAssetsByKind<T extends NamedAsset>(list: T[]): { kind: string; label: string; items: T[] }[] {
  const groups = new Map<string, T[]>();
  for (const a of list) groups.set(a.kind, [...(groups.get(a.kind) ?? []), a]);
  const kinds = [...groups.keys()].sort((x, y) => {
    const ix = KIND_ORDER.indexOf(x), iy = KIND_ORDER.indexOf(y);
    return (ix < 0 ? 99 : ix) - (iy < 0 ? 99 : iy) || x.localeCompare(y);
  });
  return kinds.map((k) => ({
    kind: k,
    label: ASSET_KIND_GROUP[k] ?? humanize(k),
    items: [...groups.get(k)!].sort((x, y) => x.name.localeCompare(y.name) || x.id - y.id),
  }));
}
