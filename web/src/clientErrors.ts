/**
 * Error reports (docs/install.md#error-reports): the errors people hit in
 * the dashboard, sent to this server only (POST /api/v1/client-errors), so
 * the team learns about them without anyone having to report them.
 *
 * What is sent: the route pattern (/assets/:id, never the address with its
 * ids or query string), the API route and method, the status and error
 * code, the error's name and message (scrubbed, at most 300 characters),
 * up to 8 stack frames of our own bundle as file:line (no source text), the
 * version, the browser family and major version, and a random id for the
 * page load. Never names, email addresses, organisation names, request or
 * response bodies, or query strings.
 *
 * Reports are batched (sent 2 s after the last, at most 10 s after the
 * first), at most 20 per page load, sent with navigator.sendBeacon when the
 * page is hidden, retried quietly and never shown to anyone. No imports, so
 * node --test can load it.
 */

export interface ClientErrorReport {
  source: "api" | "error" | "rejection" | "render";
  route: string;
  method?: string;
  api_route?: string;
  status?: number;
  code?: string;
  name?: string;
  message?: string;
  stack?: string[];
  version?: string;
  browser?: string;
  page_id: string;
}

export const MAX_REPORTS = 20;
const MAX_SAME = 3;
const MAX_MESSAGE = 300;
const MAX_FRAMES = 8;
const ENDPOINT = "/api/v1/client-errors";

const SCRUBBERS: [RegExp, string | ((m: string) => string)][] = [
  [/https?:\/\/[^\s"'<>]+/g, "[url]"],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "[email]"],
  [/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "[uuid]"],
  [/\b(?:stk[a-z]*|ghp|gho|ghs|ghu|github_pat|xox[abpr]|sk|pk|rk|whsec)[_-][A-Za-z0-9_-]{8,}|\bAKIA[A-Z0-9]{12,}/g, "[token]"],
  [/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g, "[token]"],
  [/\b(bearer|token|secret|password|passwd|api[_-]?key|authorization)\b(\s*[:=]\s*|\s+)\S+/gi, "$1 [redacted]"],
  [/\b[A-Za-z0-9_-]*[0-9][A-Za-z0-9_-]*\b/g, (m) => (m.length >= 20 ? "[token]" : m)],
  [/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[ip]"],
  [/\)=\([^()]*\)/g, ")=[value]"],
  [/"[^"]*"/g, '"[text]"'],
  [/\d{5,}/g, "[number]"],
];

/**
 * Removes what could identify a person, a customer or a secret: URLs, email
 * addresses, UUIDs, tokens, IP addresses, quoted text, long random strings
 * and runs of five or more digits. Truncates to 300 characters. The server
 * scrubs again.
 */
export function scrub(s: unknown): string {
  let out = String(s ?? "")
    .slice(0, 4 * MAX_MESSAGE)
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000a-\u001f]/g, " ");
  for (const [re, w] of SCRUBBERS) out = typeof w === "string" ? out.replace(re, w) : out.replace(re, w);
  out = out.trim();
  const chars = [...out];
  return chars.length > MAX_MESSAGE ? chars.slice(0, MAX_MESSAGE - 1).join("") + "…" : out;
}

const PLAIN_SEGMENT = /^([a-z][a-z_-]{0,39}[0-9]?|:[A-Za-z_]{1,30}|\{[A-Za-z_]{1,30}\}|\*)$/;

/** A path with its query string, fragment and identifier-like segments removed ("/assets/42?q=x" → "/assets/:id"). */
export function scrubPath(path: string, placeholder = ":id"): string {
  let p = String(path ?? "");
  const q = p.search(/[?#]/);
  if (q >= 0) p = p.slice(0, q);
  if (!p.startsWith("/")) return "";
  return p
    .split("/")
    .map((s) => (s === "" || PLAIN_SEGMENT.test(s) ? s : placeholder))
    .join("/")
    .slice(0, 200);
}

/**
 * The route pattern from react-router's matches ("/settings/billing",
 * "/assets/:id"), or, outside the app's routes (sign-in pages, a crash
 * before routing), the address with its identifiers removed.
 */
export function routePattern(matchPaths: (string | undefined)[], pathname: string): string {
  const parts = matchPaths.filter((p): p is string => !!p && p !== "/").map((p) => p.replace(/^\/+|\/+$/g, ""));
  if (matchPaths.length > 0) return scrubPath("/" + parts.filter(Boolean).join("/"));
  return scrubPath(pathname);
}

/** Frames of our own bundle, as static/file.js:line:col (no origin, no source text). */
export function stackFrames(stack: unknown): string[] {
  const out: string[] = [];
  for (const m of String(stack ?? "").matchAll(/(?:https?:\/\/[^/\s)]+)?\/(static\/[\w.-]{1,100}\.js:\d{1,7}(?::\d{1,7})?)/g)) {
    out.push(m[1]);
    if (out.length === MAX_FRAMES) break;
  }
  return out;
}

/** "Chrome 131", "Firefox 140", "Safari 18", "Edge 131", or "". */
export function browserFamily(ua: string): string {
  const tests: [string, RegExp][] = [
    ["Edge", /Edg\/(\d+)/],
    ["Opera", /OPR\/(\d+)/],
    ["Firefox", /Firefox\/(\d+)/],
    ["Chrome", /Chrome\/(\d+)/],
    ["Safari", /Version\/(\d+)[\d.]* .*Safari\//],
  ];
  for (const [name, re] of tests) {
    const m = re.exec(ua);
    if (m) return `${name} ${m[1]}`;
  }
  return "";
}

/** Error codes for mistakes the form itself explains: not faults. */
const EXPECTED_CODES = new Set([
  "invalid",
  "bad_password",
  "mfa_invalid",
  "mfa_expired",
  "rate_limited",
  "too_soon",
  "invitation_invalid",
  "invitation_stale",
  "link_expired",
  "link_invalid",
  "reset_invalid",
  "wrong_account",
  "password_change_required",
  "mfa_required",
  "mfa_enrolment_required",
  "sign_in_required",
  "asset_limit",
  "project_limit",
  "plan_required",
  "read_only",
  "license_required",
  "network",
]);

/**
 * Whether an API error shown to someone is reported: every 5xx; a 4xx
 * shown as an error, except 401 outside the signed-in app (sign-in pages),
 * validation the form handles (400 with details or a known code), limits
 * of the plan (402) and rate limits (429). Status 0 (the server could not
 * be reached) is not: the report would not arrive either.
 */
export function shouldReport(e: { status: number; code: string; message?: string; details?: string[] }, inApp: boolean): boolean {
  if (e.status >= 500) return true;
  if (e.status < 400) return false;
  if (e.status === 401) return inApp;
  if (e.status === 402 || e.status === 429) return false;
  if (EXPECTED_CODES.has(e.code)) return false;
  if (e.status === 400) return /^invalid JSON body/.test(e.message ?? "");
  return true;
}

export type Transport = (body: string, beacon: boolean) => Promise<boolean>;

const defaultTransport: Transport = async (body, beacon) => {
  if (beacon && typeof navigator !== "undefined" && typeof navigator.sendBeacon === "function") {
    // No custom header with a beacon: the server accepts Sec-Fetch-Site: same-origin instead.
    return navigator.sendBeacon(ENDPOINT, new Blob([body], { type: "text/plain" }));
  }
  const res = await fetch(ENDPOINT, {
    method: "POST",
    credentials: "same-origin",
    keepalive: true,
    headers: { "Content-Type": "application/json", "X-Stackurity-CSRF": "1" },
    body,
  });
  // 4xx (refused, rate limited, too large) is not retried; 5xx is.
  return res.status < 500;
};

function randomId(): string {
  const c = (globalThis as { crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array } }).crypto;
  const b = new Uint8Array(12);
  if (c?.getRandomValues) c.getRandomValues(b);
  else for (let i = 0; i < b.length; i++) b[i] = Math.floor(Math.random() * 256);
  return Array.from(b, (x) => (x % 36).toString(36)).join("") + Date.now().toString(36).slice(-4);
}

/** Collects, batches and sends the reports of one page load. */
export class Reporter {
  enabled = true;
  version = "";
  readonly pageId = randomId();
  private queue: ClientErrorReport[] = [];
  private accepted = 0;
  private same = new Map<string, number>();
  private timer: ReturnType<typeof setTimeout> | null = null;
  private firstQueued = 0;
  private retries = 0;
  private transport: Transport;
  private browser: string;

  constructor(transport: Transport = defaultTransport, ua = typeof navigator !== "undefined" ? navigator.userAgent : "") {
    this.transport = transport;
    this.browser = browserFamily(ua);
  }

  /** Queues a report; false when it was dropped (off, the page's 20 are used, or the same error was sent 3 times). */
  add(r: Omit<ClientErrorReport, "page_id" | "version" | "browser">): boolean {
    try {
      if (!this.enabled || this.accepted >= MAX_REPORTS) return false;
      const key = [r.source, r.route, r.method, r.api_route, r.status, r.code, r.name, r.stack?.[0]].join("|");
      const n = this.same.get(key) ?? 0;
      if (n >= MAX_SAME) return false;
      this.same.set(key, n + 1);
      this.accepted++;
      const report: ClientErrorReport = { ...r, message: r.message ? scrub(r.message) : undefined, page_id: this.pageId };
      if (this.version) report.version = this.version;
      if (this.browser) report.browser = this.browser;
      this.queue.push(report);
      this.schedule();
      return true;
    } catch {
      return false;
    }
  }

  /** Replaces how reports are sent (tests). */
  setTransport(t: Transport) {
    this.transport = t;
  }

  /** Stops reporting for this page load and drops what is queued. */
  disable() {
    this.enabled = false;
    this.queue = [];
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  /** Reports waiting to be sent (tests). */
  pending(): ClientErrorReport[] {
    return [...this.queue];
  }

  private schedule() {
    const now = Date.now();
    if (this.queue.length === 1) this.firstQueued = now;
    if (this.timer) clearTimeout(this.timer);
    const wait = Math.max(0, Math.min(2000, this.firstQueued + 10_000 - now));
    this.timer = setTimeout(() => void this.flush(false), wait);
  }

  /** Sends what is queued. Never throws; a failed send is retried twice, quietly. */
  async flush(beacon: boolean): Promise<void> {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    if (this.queue.length === 0) return;
    const batch = this.queue.splice(0, this.queue.length);
    let ok = false;
    try {
      ok = await this.transport(JSON.stringify({ reports: batch }), beacon);
    } catch {
      ok = false;
    }
    if (!ok && !beacon && this.retries < 2) {
      this.retries++;
      this.queue.unshift(...batch);
      if (this.timer) clearTimeout(this.timer);
      this.timer = setTimeout(() => void this.flush(false), 5000 * this.retries);
    }
  }
}

export const reporter = new Reporter();

/** Called with GET /meta: the version, and whether this server keeps error reports (STACKURITY_CLIENT_ERRORS=off says no). */
export function configureErrorReports(meta: { version?: string; client_errors?: boolean }) {
  reporter.version = meta.version ?? "";
  if (meta.client_errors !== true) reporter.disable();
}

const shown = new WeakSet<object>();

/**
 * Reports an API error an ErrorBox shows, once per error object however
 * often it renders. request is the client's "GET /billing?x=1" (ApiError.request).
 */
export function reportShownError(
  e: { status: number; code: string; message: string; name?: string; details?: string[]; request?: string },
  route: string,
  inApp: boolean,
  to: Reporter = reporter,
  source: "api" | "rejection" = "api",
): boolean {
  if (!e || typeof e !== "object" || shown.has(e)) return false;
  shown.add(e);
  if (!shouldReport(e, inApp)) return false;
  const [method, path] = (e.request ?? "").split(" ", 2);
  return to.add({
    source,
    route,
    method: method || undefined,
    api_route: path ? scrubPath("/api/v1" + path, "{id}") : undefined,
    status: e.status,
    code: e.code,
    name: "ApiError",
    message: e.message,
  });
}

/** Reports an exception: uncaught, an unhandled rejection, or one an error boundary caught. */
export function reportException(source: "error" | "rejection" | "render", err: unknown, route: string, to: Reporter = reporter): boolean {
  if (err && typeof err === "object" && shown.has(err)) return false;
  if (err && typeof err === "object" && typeof (err as { status?: unknown }).status === "number" && typeof (err as { code?: unknown }).code === "string") {
    // An API error nobody caught (a click handler without a catch).
    return reportShownError(err as Parameters<typeof reportShownError>[0], route, true, to, "rejection");
  }
  if (err && typeof err === "object") shown.add(err);
  const e = err as { name?: unknown; message?: unknown; stack?: unknown } | null;
  const name = typeof e?.name === "string" ? e.name : typeof err === "string" ? "Error" : "Unknown";
  const message = typeof e?.message === "string" ? e.message : typeof err === "string" ? err : "";
  return to.add({ source, route, name: name.slice(0, 64), message, stack: stackFrames(e?.stack) });
}

/** The address as a route pattern, for errors caught outside React. */
export function currentRoute(): string {
  return typeof location !== "undefined" ? scrubPath(location.pathname) : "/";
}

let installed = false;

/** Catches uncaught errors and rejections, and sends what is queued when the page is hidden. */
export function installErrorReports() {
  if (installed || typeof window === "undefined") return;
  installed = true;
  window.addEventListener("error", (ev) => {
    // Resource load failures (an image) have no error object: not reported.
    if (ev.error !== undefined || ev.message) reportException("error", ev.error ?? ev.message, currentRoute());
  });
  window.addEventListener("unhandledrejection", (ev) => reportException("rejection", ev.reason, currentRoute()));
  const leave = () => void reporter.flush(true);
  window.addEventListener("pagehide", leave);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") leave();
  });
}
