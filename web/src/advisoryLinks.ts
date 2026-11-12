// Links out to an advisory's public pages: the osv.dev and NVD pages built
// from its id, and the reference addresses stored with it. Used by the issue
// page (pages/FindingDetail.tsx) and by Ask Stackurity's "Read more" list,
// which shows only addresses on well-known advisory sites. Plain logic,
// tested in advisoryLinks.test.ts.
import type { Advisory } from "./api.ts";

export const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

/** The osv.dev page for an advisory id. */
export function osvUrl(id: string): string {
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

/** NVD's page for a CVE id. */
export function nvdUrl(cve: string): string {
  return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.toUpperCase())}`;
}

/** The CVE ids an advisory goes by: its own id and its aliases. */
export function advisoryCves(a: Pick<Advisory, "id" | "aliases">): string[] {
  return [a.id, ...(a.aliases ?? [])].filter((x) => CVE_RE.test(x));
}

// Advisory sites Ask may link to. A path prefix limits a site to its
// advisory pages.
const READ_MORE_HOSTS: Record<string, string | null> = {
  "nvd.nist.gov": null,
  "osv.dev": null,
  "github.com": "/advisories/",
  "www.cve.org": null,
  "cve.org": null,
  "ubuntu.com": "/security/",
  "security-tracker.debian.org": null,
  "access.redhat.com": null,
};

/**
 * The address and its domain when it is an https page on one of the
 * advisory sites above, otherwise null. No other port, no user name or
 * password in it.
 */
export function readMoreUrl(raw: string | null | undefined): { href: string; domain: string } | null {
  if (!raw) return null;
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    return null;
  }
  if (u.protocol !== "https:" || u.username || u.password || u.port) return null;
  const host = u.hostname.toLowerCase();
  if (!Object.hasOwn(READ_MORE_HOSTS, host)) return null;
  const prefix = READ_MORE_HOSTS[host];
  if (prefix && !(u.pathname.startsWith(prefix) && u.pathname.length > prefix.length)) return null;
  return { href: u.href, domain: host };
}

export interface ReadMoreLink {
  href: string;
  domain: string;
  /** What the page is about, from the advisory id or the address's last part. */
  label: string;
}

/** Last part of an address's path, for a link's words ("CVE-2024-3094"). */
function lastPart(href: string): string {
  const parts = new URL(href).pathname.split("/").filter(Boolean);
  let last = parts[parts.length - 1] ?? "";
  try {
    last = decodeURIComponent(last);
  } catch {
    // keep it as written
  }
  return last.length > 60 ? `${last.slice(0, 59)}…` : last;
}

/**
 * The "Read more" links for some advisories: osv.dev and NVD pages built
 * from their ids, then each stored reference on an allowed site. No
 * address twice, at most `max`.
 */
export function readMoreLinks(advisories: Advisory[], max = 8): ReadMoreLink[] {
  const out: ReadMoreLink[] = [];
  const seen = new Set<string>();
  const add = (raw: string, label?: string) => {
    const ok = readMoreUrl(raw);
    if (!ok || seen.has(ok.href) || out.length >= max) return;
    seen.add(ok.href);
    out.push({ ...ok, label: label ?? (lastPart(ok.href) || ok.domain) });
  };
  for (const a of advisories) {
    add(osvUrl(a.id), a.id);
    for (const c of advisoryCves(a)) add(nvdUrl(c), c.toUpperCase());
  }
  for (const a of advisories) for (const r of a.references ?? []) if (r.url) add(r.url);
  return out;
}
