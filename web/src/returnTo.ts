/**
 * Where to go back to after a detour (?return=): a path on this site only,
 * so a link can never send someone elsewhere (an open redirect). Anything
 * else is null.
 *
 * The value is normalised first and checked after: "/..//evil.com" and
 * "/./\evil.com" pass a prefix check but become "//evil.com", which a
 * router treats as another host. Percent-encoded slashes ("/%2F%2Fevil.com")
 * stay encoded and so stay a path here.
 */
export function safeReturn(value: string | null | undefined): string | null {
  const v = (value ?? "").trim();
  if (!v.startsWith("/") || /[\u0000-\u001f\\]/.test(v)) return null;
  let path: string;
  try {
    const base = "https://stackurity.invalid";
    const u = new URL(v, base);
    if (u.origin !== base) return null;
    path = u.pathname + u.search + u.hash;
  } catch {
    return null;
  }
  // After dot segments are resolved: one leading slash and no backslash.
  if (!path.startsWith("/") || path.startsWith("//") || path.startsWith("/\\")) return null;
  return path;
}
