import type { SiteCheckGrade, SiteCheckSoftware } from "./api";

/** "Web server or runtime", "Website platform", "Library". */
export function kindLabel(kind: SiteCheckSoftware["kind"]): string {
  switch (kind) {
    case "server":
      return "Web server or runtime";
    case "cms":
      return "Website platform";
    case "plugin":
      return "WordPress plugin";
    default:
      return "JavaScript or CSS library";
  }
}

/** One line on what the stored data says about a piece of software. */
export function softwareSummary(sw: SiteCheckSoftware): string {
  const parts: string[] = [];
  const kev = sw.issues.filter((i) => i.known_exploited).length;
  if (sw.issues.length > 0) {
    parts.push(`${sw.issues.length} known ${sw.issues.length === 1 ? "vulnerability" : "vulnerabilities"}${kev ? `, ${kev} exploited in the wild` : ""}`);
    const fixes = sw.issues.map((i) => i.fixed_in).filter((v): v is string => !!v);
    if (fixes.length === sw.issues.length) parts.push(`upgrading fixes ${sw.issues.length === 1 ? "it" : "them all"}`);
  } else if (!sw.coverage) {
    parts.push("No known vulnerabilities in this version");
  }
  if (sw.end_of_life?.ended) parts.push("its release line no longer gets security fixes");
  if (parts.length === 0) return "";
  const s = parts.join("; ");
  return s.charAt(0).toUpperCase() + s.slice(1) + ".";
}

/** Where to read about an issue: the CVE record, or the GitHub advisory. */
export function advisoryURL(id: string): string {
  if (id.startsWith("CVE-")) return `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`;
  if (id.startsWith("GHSA-")) return `https://github.com/advisories/${encodeURIComponent(id)}`;
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

/** The colour of a grade: A and B good, C and D a warning, F bad. */
export function gradeTone(letter: SiteCheckGrade["letter"]): "good" | "warn" | "bad" {
  if (letter === "A" || letter === "B") return "good";
  if (letter === "C" || letter === "D") return "warn";
  return "bad";
}

/** One sentence on what a grade means. */
export function gradeMeaning(g: SiteCheckGrade): string {
  if (g.deductions.length === 0) return "Nothing a visitor can see costs this site points.";
  const n = g.deductions.length;
  return `${g.score} out of 100: ${n} ${n === 1 ? "problem costs" : "problems cost"} points. Fix the ones at the top first.`;
}
