/**
 * Long names in narrow table cells (components/Truncate.tsx). The start of a
 * name can give way to an ellipsis, but the end that tells two rows apart
 * stays: a package's version (pkg:npm/lodash@4.17.21), a file's name, the
 * last characters of a host name. Kept free of React so node --test can load
 * it (truncate.test.ts).
 */

export interface TruncateParts {
  /** May be cut with an ellipsis. */
  head: string;
  /** Always shown. */
  tail: string;
}

/** Shorter than this, a value is never split. */
const SHORT = 24;
/** The most kept visible at the end. */
const MAX_TAIL = 28;
/** The fewest kept when there is no natural break. */
const MIN_TAIL = 8;

/**
 * Splits a value so the part that matters stays visible. A version after the
 * last "@" (not a "@scope") stays whole, with short purl qualifiers after it;
 * otherwise the last path segment, or the last few characters.
 */
export function truncateParts(value: string): TruncateParts {
  if (value.length <= SHORT) return { head: value, tail: "" };
  // A purl's version, with any short qualifiers after it ("@3.0.11?arch=amd64").
  const q = value.search(/[?#]/);
  const main = q > 0 ? value.slice(0, q) : value;
  const at = main.lastIndexOf("@");
  if (at > 0 && main[at - 1] !== "/" && value.length - at <= MAX_TAIL) {
    return { head: value.slice(0, at), tail: value.slice(at) };
  }
  const slash = value.lastIndexOf("/");
  if (slash > 0 && slash < value.length - 1 && value.length - slash <= MAX_TAIL) {
    return { head: value.slice(0, slash), tail: value.slice(slash) };
  }
  const n = Math.min(MAX_TAIL, Math.max(MIN_TAIL, Math.floor(value.length / 3)));
  return { head: value.slice(0, value.length - n), tail: value.slice(value.length - n) };
}

/**
 * A plain-text middle ellipsis, for places that cannot use CSS (a title, an
 * aria label, a chip): at most `max` characters, keeping the same end as
 * truncateParts.
 */
export function middleTruncate(value: string, max: number): string {
  if (value.length <= max) return value;
  if (max < 3) return value.slice(0, max);
  const { tail } = truncateParts(value);
  const keep = Math.min(tail.length || Math.floor((max - 1) / 2), max - 2);
  const end = value.slice(value.length - keep);
  return `${value.slice(0, max - 1 - keep)}…${end}`;
}
