/*
 * Where a sign-up came from (signup_ref, counted by the sales funnel): the
 * sign-up page's ?ref= (badge-<slug> from a trust page, blog-<post> from the
 * blog), or, without one, <utm_source>-<utm_campaign> from a tagged link.
 *
 * A sign-up with Google, Microsoft or GitHub leaves for the provider and
 * comes back to /signup/social, so the ref is kept in sessionStorage for
 * that tab in between (SIGNUP_REF_KEY) and sent with the completion form.
 *
 * Kept free of React and of value imports so `npm test` runs it with Node.
 */

const REF_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;

/** sessionStorage key for the ref during a sign-up through a provider. */
export const SIGNUP_REF_KEY = "stackurity.signupRef";

/** How long a kept ref counts: a provider sign-up takes minutes, not hours. */
export const SIGNUP_REF_TTL_MS = 60 * 60 * 1000;

/** A short slug-like tag (as the server's cleanSignupRef); undefined otherwise. */
export function cleanRef(ref: string | null | undefined): string | undefined {
  const r = (ref ?? "").trim().toLowerCase();
  return REF_PATTERN.test(r) ? r : undefined;
}

/**
 * The page's ?ref= when it is a short slug-like tag. Without a ref, a link
 * tagged with utm_source counts as <utm_source>-<utm_campaign> (or just the
 * source), lower-cased, other characters as '-', at most 64 characters.
 * undefined when neither gives a valid tag.
 */
export function signupRef(search = typeof window === "undefined" ? "" : window.location.search): string | undefined {
  const q = new URLSearchParams(search);
  const ref = q.get("ref");
  if (ref !== null && ref.trim() !== "") return cleanRef(ref);
  const source = (q.get("utm_source") ?? "").trim();
  if (!source) return undefined;
  const campaign = (q.get("utm_campaign") ?? "").trim();
  const derived = (campaign ? `${source}-${campaign}` : source)
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .slice(0, 64);
  return cleanRef(derived);
}

/** What to keep in sessionStorage for ref at now. */
export function keptRefValue(ref: string, now: number): string {
  return JSON.stringify({ ref, at: now });
}

/** The kept ref when it is valid and less than an hour old; undefined otherwise. */
export function keptRef(value: string | null, now: number): string | undefined {
  if (!value) return undefined;
  try {
    const v = JSON.parse(value) as { ref?: unknown; at?: unknown };
    if (typeof v.ref !== "string" || typeof v.at !== "number" || now - v.at > SIGNUP_REF_TTL_MS || v.at > now + 60_000) return undefined;
    return cleanRef(v.ref);
  } catch {
    return undefined;
  }
}
