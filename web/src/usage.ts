/**
 * Usage counts (POST /api/v1/usage-counts): what only the browser sees,
 * reported so the operator can learn which paid features people look at
 * and what they export. Only an event and a fixed key are sent; the server
 * keeps them as per-organisation daily counts, with nothing about the
 * person or the page. Best effort: failures are ignored and never shown.
 */
export type UsageEvent = "teaser_view" | "teaser_click" | "export";

/** Exports made in the browser (the server counts its own downloads). */
export type ClientExport = "evidence_json" | "evidence_print" | "outcomes_print";

// One view per feature per page per page load, however often it renders.
const seen = new Set<string>();

export function usageKeyOnce(event: UsageEvent, key: string, page: string): boolean {
  const k = `${event}|${key}|${page}`;
  if (seen.has(k)) return false;
  seen.add(k);
  return true;
}

export function countUsage(event: UsageEvent, key: string): void {
  if (typeof fetch !== "function") return;
  fetch("/api/v1/usage-counts", {
    method: "POST",
    credentials: "same-origin",
    keepalive: true,
    headers: { "Content-Type": "application/json", "X-Stackurity-CSRF": "1" },
    body: JSON.stringify({ event, key }),
  }).catch(() => {});
}

/** A locked paid-plan notice was shown on this page (once per page load). */
export function countTeaserView(feature: string): void {
  const page = typeof location !== "undefined" ? location.pathname : "";
  if (usageKeyOnce("teaser_view", feature, page)) countUsage("teaser_view", feature);
}

export function countExport(kind: ClientExport): void {
  countUsage("export", kind);
}
