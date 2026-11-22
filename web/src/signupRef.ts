/*
 * Where a sign-up came from (signup_ref, counted by the sales funnel): the
 * sign-up page's ?ref= (badge-<slug> from a trust page, blog-<post> from the
 * blog), or, without one, <utm_source>-<utm_campaign> from a tagged link,
 * or, without either, web-<host> from the website that linked to the page
 * (document.referrer, outside stackurity.ai and stackurity.dev; with the
 * usual referrer policy only the origin arrives, never the path).
 *
 * A sign-up with Google, Microsoft or GitHub sends the ref in the
 * provider's start URL (socialStartURL); the server keeps it with the
 * sign-in in progress until the account is created. The browser stores
 * nothing for it (no cookie, localStorage or sessionStorage).
 *
 * Kept free of React and of value imports so `npm test` runs it with Node.
 */

const REF_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;

/** A short slug-like tag (as the server's cleanSignupRef); undefined otherwise. */
export function cleanRef(ref: string | null | undefined): string | undefined {
  const r = (ref ?? "").trim().toLowerCase();
  return REF_PATTERN.test(r) ? r : undefined;
}

/**
 * The page's ?ref= when it is a short slug-like tag. Without a ref, a link
 * tagged with utm_source counts as <utm_source>-<utm_campaign> (or just the
 * source), lower-cased, other characters as '-', at most 64 characters.
 * Without either, the referring website counts as web-<host> (refFromReferrer).
 * undefined when none gives a valid tag.
 */
export function signupRef(
  search = typeof window === "undefined" ? "" : window.location.search,
  referrer = typeof document === "undefined" ? "" : document.referrer,
): string | undefined {
  const q = new URLSearchParams(search);
  const ref = q.get("ref");
  if (ref !== null && ref.trim() !== "") return cleanRef(ref);
  const source = (q.get("utm_source") ?? "").trim();
  if (!source) return refFromReferrer(referrer);
  const campaign = (q.get("utm_campaign") ?? "").trim();
  return cleanRef(slug(campaign ? `${source}-${campaign}` : source));
}

/** Lower-cased, other characters as '-', at most 64 characters. */
function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 64);
}

/** Our own sites: a referrer from them says nothing about where a person came from. */
const OWN_HOSTS = ["stackurity.ai", "stackurity.dev"];

/**
 * web-<host> for an http(s) referrer outside stackurity.ai and stackurity.dev
 * (and their subdomains), without a leading "www."; undefined for our own
 * sites, other schemes (android-app://) and no referrer.
 */
export function refFromReferrer(referrer: string | null | undefined): string | undefined {
  let url: URL;
  try {
    url = new URL((referrer ?? "").trim());
  } catch {
    return undefined;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!host || OWN_HOSTS.some((h) => host === h || host.endsWith("." + h))) return undefined;
  return cleanRef(slug("web-" + host.replace(/^www\./, "")));
}

/**
 * The address of a "Continue with <provider>" button: the provider's
 * start_url with ?return_to= (where a sign-in continues; not for "/") and,
 * on the sign-up page, ?ref= (where the person came from, cleaned).
 */
export function socialStartURL(startURL: string, returnTo?: string, ref?: string): string {
  const cut = startURL.indexOf("?");
  const path = cut < 0 ? startURL : startURL.slice(0, cut);
  const query = cut < 0 ? "" : startURL.slice(cut + 1);
  const q = new URLSearchParams(query);
  if (returnTo && returnTo !== "/") q.set("return_to", returnTo);
  const r = cleanRef(ref);
  if (r) q.set("ref", r);
  const qs = q.toString();
  return qs ? `${path}?${qs}` : path;
}
