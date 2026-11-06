// What to do about a vulnerability incident, per component. An incident
// groups one advisory across every asset, so it can hold ubuntu/curl (fixed
// in an Ubuntu version) next to debian/curl (no fix yet): a version
// published for one distribution must never be offered for another.
// detail.component_fixes (store.CorrelateIncidents) says which fix belongs
// to which component; internal/notify/incident_fix.go words the same lines
// for Slack, Teams, email and Jira.
import { plural } from "./format.ts";

export interface ComponentFix {
  component: string;
  /** purl type: deb, rpm and apk namespaces name the distribution. */
  type?: string;
  fixed_versions?: string[];
  assets: number;
  /** Assets where the component has no fixed version. */
  unfixed: number;
}

export type FixLineKind = "fix" | "per_release" | "partial" | "none";

export interface FixLine {
  kind: FixLineKind;
  /** The components the line is about, each with its asset count. */
  components: { name: string; assets: number }[];
  versions: string[];
  /** What to do, after "<components>: ". */
  text: string;
}

const DISTROS: Record<string, string> = {
  ubuntu: "Ubuntu", debian: "Debian", alpine: "Alpine", rhel: "RHEL", redhat: "RHEL", centos: "CentOS",
  rocky: "Rocky Linux", almalinux: "AlmaLinux", alma: "AlmaLinux", amzn: "Amazon Linux", amazon: "Amazon Linux",
  sles: "SLES", "opensuse-leap": "openSUSE Leap", opensuse: "openSUSE", fedora: "Fedora", ol: "Oracle Linux",
  oracle: "Oracle Linux", wolfi: "Wolfi", chainguard: "Chainguard", photon: "Photon OS", mariner: "CBL-Mariner",
  azurelinux: "Azure Linux",
};

/** The distribution an OS package comes from ("Debian"), or "". */
export function distroOf(c: ComponentFix): string {
  if (!c.type || !["deb", "rpm", "apk"].includes(c.type)) return "";
  const i = c.component.indexOf("/");
  return i > 0 ? (DISTROS[c.component.slice(0, i).toLowerCase()] ?? "") : "";
}

/** Lines of advice, components with the same fix together. Null when the
 * detail has no component_fixes (an incident not correlated since they
 * were added): the caller falls back to the flat fixed_versions. */
export function fixLines(fixes: ComponentFix[] | undefined | null): FixLine[] | null {
  if (!Array.isArray(fixes) || fixes.length === 0) return null;
  const lines: FixLine[] = [];
  const byKey = new Map<string, FixLine>();
  const add = (key: string, c: ComponentFix, line: Omit<FixLine, "components">) => {
    const l = key ? byKey.get(key) : undefined;
    if (l) {
      l.components.push({ name: c.component, assets: c.assets });
      return;
    }
    const n: FixLine = { ...line, components: [{ name: c.component, assets: c.assets }] };
    lines.push(n);
    if (key) byKey.set(key, n);
  };
  for (const c of fixes) {
    const vs = c.fixed_versions ?? [];
    const fixed = c.assets - c.unfixed;
    if (vs.length === 0 || fixed <= 0) {
      const d = distroOf(c);
      add(`none|${d}`, c, {
        kind: "none",
        versions: [],
        text: `no fixed version is published yet${d ? ` for ${d}` : ""}. Watch the advisory and consider mitigations.`,
      });
    } else if (c.unfixed > 0) {
      const to = vs.length === 1 ? `${vs[0]} or later` : `the version for each asset's release (${vs.join(" / ")} or later)`;
      add("", c, {
        kind: "partial",
        versions: vs,
        text: `upgrade to ${to} on the ${plural(fixed, "asset")} where it is published. No fixed version is published yet for the other ${plural(c.unfixed, "asset")}: watch the advisory.`,
      });
    } else if (vs.length > 1) {
      add("", c, {
        kind: "per_release",
        versions: vs,
        text: `upgrade to the version for each asset's release: ${vs.join(" / ")} or later. See the Fix column for each asset's version.`,
      });
    } else {
      add(`fix|${vs[0]}`, c, { kind: "fix", versions: vs, text: `upgrade to ${vs[0]} or later.` });
    }
  }
  return lines;
}

/** "ubuntu/curl (2 assets), ubuntu/libcurl4 (1 asset)". */
export function lineComponents(l: FixLine): string {
  return l.components.map((c) => `${c.name} (${plural(c.assets, "asset")})`).join(", ");
}

/** The summary's "fixed versions" row: "ubuntu/curl, ubuntu/libcurl4:
 * 7.81.0-1ubuntu1.29", "debian/curl: none yet". */
export function fixedVersionRows(lines: FixLine[]): { components: string; versions: string }[] {
  return lines.map((l) => ({
    components: l.components.map((c) => c.name).join(", "),
    versions:
      l.kind === "none"
        ? "none yet"
        : l.kind === "partial"
          ? `${l.versions.join(" / ")} (not for every asset)`
          : l.kind === "per_release"
            ? `${l.versions.join(" / ")} (per release)`
            : l.versions.join(" / "),
  }));
}
