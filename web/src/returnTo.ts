/**
 * Where to go back to after a detour (?return=): a path on this site only,
 * so a link can never send someone elsewhere (an open redirect). Anything
 * else is null.
 */
export function safeReturn(value: string | null | undefined): string | null {
  const v = (value ?? "").trim();
  // A relative path: one leading slash, not "//host" or "/\\host", no scheme.
  if (!v.startsWith("/") || v.startsWith("//") || v.startsWith("/\\") || /[\u0000-\u001f]/.test(v)) return null;
  try {
    const base = "https://stackurity.invalid";
    const u = new URL(v, base);
    if (u.origin !== base) return null;
    return u.pathname + u.search + u.hash;
  } catch {
    return null;
  }
}
