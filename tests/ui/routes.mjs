// Which routes the browser checks visit, and which extra checks apply to
// which. Routes come from web/src/App.tsx, so a new page is checked without
// touching this file; add here only what a route needs to be reached (a
// real id) or an extra check for a set of routes.
import { readFileSync } from "node:fs";

/** Every path the router declares, except the catch-all. */
export function appRoutes(appTsx) {
  const src = readFileSync(appTsx, "utf8");
  return [...src.matchAll(/path="([^"]+)"/g)].map((m) => m[1]).filter((p) => p !== "*");
}

/**
 * Fills route parameters with real values, from the API: a route whose
 * parameter has no value here is skipped (and reported).
 */
export async function fillParams(path, get) {
  const first = async (list) => (await get(list)).items?.[0];
  const fills = {
    "help/:topic": async () => "help/daily-workflow",
    "assets/:id": async () => `assets/${(await first("/assets?limit=1"))?.id ?? ""}`,
    "findings/:id": async () => `findings/${(await first("/findings?status=all&limit=1"))?.id ?? ""}`,
    "fixes/:id": async () => `fixes/${encodeURIComponent((await first("/fix-groups?limit=1"))?.id ?? "")}`,
    "action-plan/:id": async () => `action-plan/${encodeURIComponent((await first("/fix-groups?limit=1"))?.id ?? "")}`,
    "incidents/:id": async () => `incidents/${(await first("/incidents?status=all&limit=1"))?.id ?? ""}`,
    "components/:id": async () => `components/${(await first("/components?limit=1"))?.id ?? ""}`,
    "settings/integrations/new/:kind": async () => "settings/integrations/new/slack",
  };
  if (!path.includes(":")) return "/" + path;
  const f = fills[path];
  if (!f) return null;
  const filled = await f();
  return /\/$|:\w/.test(filled) ? null : "/" + filled;
}

/**
 * Checks beyond the ones every route gets (the sidebar covers the screen,
 * no empty band at the bottom): [route prefix, widths, check names].
 * "no-horizontal-scroll": the page is not wider than the screen.
 */
export const EXTRA_CHECKS = [
  ["/settings", [1280], ["no-horizontal-scroll"]],
  ["/", [390], ["no-horizontal-scroll"]],
];

export const WIDTHS = [
  [1280, 800],
  [390, 844],
];
