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
  host: "Host",
  repository: "Repository",
  image: "Container image",
  application: "Application",
  managed_service: "Managed service",
  sbom: "SBOM",
};

export function assetKindLabel(kind: string): string {
  return ASSET_KIND_LABEL[kind] ?? humanize(kind);
}
