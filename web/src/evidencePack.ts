// The compliance evidence pack (GET /reports/evidence-pack): the frameworks
// and controls it covers, which plan includes each, the audit quarters and
// the download links. The server's mapping (internal/evidence in the
// licensed build) is the source of truth; this list only lets the page show
// frameworks the plan does not include yet.

export type PackFramework = "soc2" | "iso27001_2022" | "pci_dss_4_0" | "eu_cra";
export type PackFormat = "pdf" | "zip" | "json";

export interface FrameworkInfo {
  id: PackFramework;
  name: string;
  /** team: Team and up. addon: the Compliance add-on (Enterprise includes it). */
  tier: "team" | "addon";
  controls: string[];
}

export const PACK_FRAMEWORKS: FrameworkInfo[] = [
  { id: "soc2", name: "SOC 2", tier: "team", controls: ["CC7.1", "CC8.1"] },
  { id: "iso27001_2022", name: "ISO 27001:2022", tier: "team", controls: ["A.8.8", "A.8.9"] },
  { id: "pci_dss_4_0", name: "PCI DSS 4.0", tier: "addon", controls: ["6.3.1", "6.3.3", "11.3"] },
  { id: "eu_cra", name: "EU Cyber Resilience Act", tier: "addon", controls: ["I-II(1)", "I-II(2)", "I-II(3)", "I-II(4)"] },
];

/** Frameworks a workspace may include: all of them with the add-on. */
export function allowedFrameworks(addon: boolean): PackFramework[] {
  return PACK_FRAMEWORKS.filter((f) => addon || f.tier === "team").map((f) => f.id);
}

export interface PackPeriod {
  from: string; // YYYY-MM-DD
  to: string; // YYYY-MM-DD, inclusive
  label: string; // 2026-Q3
}

const pad = (n: number) => String(n).padStart(2, "0");

/** The calendar quarter `offset` quarters from the one holding `day` (UTC). */
export function quarter(day: Date, offset = 0): PackPeriod {
  const q = Math.floor(day.getUTCMonth() / 3) + offset;
  const year = day.getUTCFullYear() + Math.floor(q / 4);
  const qi = ((q % 4) + 4) % 4;
  const start = new Date(Date.UTC(year, qi * 3, 1));
  const end = new Date(Date.UTC(year, qi * 3 + 3, 0));
  const iso = (d: Date) => `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
  return { from: iso(start), to: iso(end), label: `${year}-Q${qi + 1}` };
}

/** The download link; project scoping follows the switcher (projectID > 0). */
export function packURL(format: PackFormat, p: PackPeriod, frameworks: PackFramework[], projectID = 0): string {
  const q = new URLSearchParams({ format, from: p.from, to: p.to });
  if (p.label) q.set("label", p.label);
  if (frameworks.length) q.set("frameworks", frameworks.join(","));
  if (projectID > 0) q.set("project_id", String(projectID));
  return `/api/v1/reports/evidence-pack?${q}`;
}
