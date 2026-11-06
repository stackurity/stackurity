/**
 * A one-line summary of a JSON value for a table cell ("asset_id 12,
 * reason manual, +3 more"), so a payload or audit detail never wraps
 * character by character. The whole value stays available, formatted, behind
 * a toggle (components/JsonDetail.tsx). No imports, so node --test can load it.
 */

function scalar(v: unknown, max: number): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return v.length === 0 ? "[]" : `[${v.length} ${v.length === 1 ? "item" : "items"}]`;
  if (typeof v === "object") return "{…}";
  const s = String(v);
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** Up to `keys` top-level fields as "key value", then "+N more". */
export function jsonSummary(value: unknown, keys = 3): string {
  if (value === null || value === undefined) return "";
  if (typeof value !== "object") return scalar(value, 60);
  if (Array.isArray(value)) return scalar(value, 60);
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length === 0) return "";
  const shown = entries.slice(0, keys).map(([k, v]) => `${k} ${scalar(v, 32)}`);
  const rest = entries.length - shown.length;
  return shown.join(", ") + (rest > 0 ? `, +${rest} more` : "");
}

/** True when the value has nothing to show (null, an empty object or array). */
export function jsonEmpty(value: unknown): boolean {
  if (value === null || value === undefined || value === "") return true;
  if (typeof value === "object") return Object.keys(value as object).length === 0;
  return false;
}
