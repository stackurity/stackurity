// Words and choices for the Compliance evidence card (Integrations): what a
// Vanta or Drata connection does, its schedule, its last sync, and the
// notice after Vanta sends the browser back. Kept apart from the component
// so node --test can check them without a browser.
import type { EvidenceConnection, EvidenceInterval, EvidenceRegion, EvidenceVendor } from "./api.ts";

export const VENDOR_NAME: Record<EvidenceVendor, string> = { vanta: "Vanta", drata: "Drata" };

export const INTERVALS: { value: EvidenceInterval; label: string }[] = [
  { value: 6, label: "Every 6 hours" },
  { value: 12, label: "Every 12 hours" },
  { value: 24, label: "Every day" },
  { value: 168, label: "Every week" },
];

/** The regions each vendor runs in, as their sign-in and API hosts are split. */
export const REGIONS: Record<EvidenceVendor, { value: EvidenceRegion; label: string }[]> = {
  vanta: [
    { value: "us", label: "United States (app.vanta.com)" },
    { value: "eu", label: "Europe (app.eu.vanta.com)" },
    { value: "aus", label: "Australia (app.aus.vanta.com)" },
  ],
  drata: [
    { value: "us", label: "United States" },
    { value: "eu", label: "Europe" },
    { value: "apac", label: "Asia Pacific" },
  ],
};

export const EVIDENCE_DOCS = "https://github.com/stackurity/stackurity/blob/main/docs/evidence-connectors.md";
export const VANTA_SETUP_DOCS = `${EVIDENCE_DOCS}#setting-up-the-vanta-app-operators`;
export const DRATA_API_KEYS_HELP = "https://developers.drata.com/openapi/reference/v2/overview/";

/** "every day", "every 6 hours", "every week". */
export function scheduleWords(hours: number | undefined): string {
  const found = INTERVALS.find((i) => i.value === hours);
  return (found?.label ?? "Every day").replace(/^Every/, "every");
}

/** The one sentence under a vendor's row: what is sent, and how often. */
export function rowPurpose(vendor: EvidenceVendor, c: EvidenceConnection | null): string {
  return `Sends your asset inventory, open vulnerabilities and an evidence pack with SLA status to ${VENDOR_NAME[vendor]} ${scheduleWords(c?.interval_hours ?? 24)}.`;
}

/** What the connection is doing now, as a status word and a badge tone. */
export function connectionState(c: EvidenceConnection | null): { label: string; tone: "good" | "warn" | "bad" | "muted" } {
  if (!c) return { label: "Not connected", tone: "muted" };
  if (c.status === "reconnect_needed") return { label: "Reconnect needed", tone: "bad" };
  if (c.status === "paused") return { label: "Paused", tone: "muted" };
  return { label: "Connected", tone: "good" };
}

/** The last sync in words: what was sent, or why it was not. Never "0 sent" for a sync that did not run. */
export function lastSyncText(c: EvidenceConnection): string {
  if (!c.last_sync_at || !c.last_sync_status) return "Not synced yet. The first sync starts within a few minutes of connecting.";
  const s = c.last_sync_summary ?? {};
  const parts: string[] = [];
  if (typeof s.assets === "number") parts.push(`${s.assets} ${s.assets === 1 ? "asset" : "assets"}`);
  if (typeof s.vulnerabilities === "number") parts.push(`${s.vulnerabilities} open ${s.vulnerabilities === 1 ? "vulnerability" : "vulnerabilities"}`);
  if (s.evidence_uploaded === true) parts.push("the evidence file");
  const sent = parts.length ? `Sent ${joinWords(parts)}.` : "";
  const message = (s.message ?? "").trim();
  switch (c.last_sync_status) {
    case "ok":
      return [sent || "Sent.", message].filter(Boolean).join(" ");
    case "partial":
      return [sent, message || "Part of the sync did not go through."].filter(Boolean).join(" ");
    default:
      return message ? `Failed: ${message}` : "Failed. Nothing was replaced in the vendor.";
  }
}

function joinWords(xs: string[]): string {
  return xs.length <= 1 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`;
}

/**
 * Why Connect Vanta did not finish, in plain words: the error codes of
 * POST /integrations/evidence/vanta/oauth (and the older ?reason= values).
 */
const VANTA_REASONS: Record<string, string> = {
  access_denied: "the approval was cancelled on Vanta's page.",
  state: "the connect link expired or was already used. Start again with Connect Vanta.",
  exchange_failed: "Vanta did not accept the approval code. Start again with Connect Vanta; codes expire after 30 seconds.",
  not_configured: "Vanta is not set up on this server.",
  plan_required: "this workspace's plan does not include the Compliance add-on.",
  forbidden: "only an administrator of this organisation, signed in to the dashboard, can connect Vanta.",
};

/** The sentence for an error code of POST /integrations/evidence/vanta/oauth; null for a code it does not know. */
export function vantaErrorText(code: string | undefined): string | null {
  const known = code && Object.hasOwn(VANTA_REASONS, code) ? VANTA_REASONS[code] : undefined;
  return known ? `Vanta was not connected: ${known}` : null;
}

/** Where the callback page sends the browser after a connect: the Integrations card shows the notice. */
export const VANTA_CONNECTED_PATH = "/integrations?evidence=vanta-connected";

/**
 * The notice after Vanta's consent page sends the browser back
 * (?evidence=vanta-connected, or ?evidence=vanta-error&reason=...). null for
 * any other address. An unknown reason is shown as given, shortened, never
 * as markup (React escapes it).
 */
export function evidenceReturnNotice(params: URLSearchParams): { kind: "success" | "warn"; text: string } | null {
  const v = params.get("evidence");
  if (v === "vanta-connected") {
    return { kind: "success", text: "Vanta connected. Choose the Vanta document for the evidence file below; the first sync starts within a few minutes." };
  }
  if (v === "vanta-error") {
    const reason = (params.get("reason") ?? "").trim();
    const said = reason ? `Vanta said: ${reason.replace(/[\r\n\t]+/g, " ").slice(0, 200)}.` : "No reason was given.";
    return { kind: "warn", text: vantaErrorText(reason) ?? `Vanta was not connected: ${said}` };
  }
  return null;
}

/** The address without the callback's evidence and reason parameters. */
export function withoutEvidenceReturn(params: URLSearchParams): URLSearchParams {
  const next = new URLSearchParams(params);
  next.delete("evidence");
  next.delete("reason");
  return next;
}
