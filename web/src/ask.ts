// Ask Stackurity, the in-app assistant: the parts of the panel that are
// plain logic (tested in ask.test.ts), and the call that streams an answer.
//
// Answers come from a model that reads text from outside sources (advisory
// descriptions, names collected from servers). Whatever it writes, the
// panel renders only text, bold, code and lists, and links only to
// Stackurity's own pages (askHref). No image, no HTML, no other link: an
// answer cannot send anything anywhere.

export const ASK_NOTICE_VERSION = "2026-11";

export interface AskStatus {
  available: boolean;
  reason: "" | "not_configured" | "ask_disabled" | "plan_required" | "read_only" | "spend_cap";
  message: string;
  provider: string;
  notice_version: string;
  notice_accepted: boolean;
  questions_used: number;
  questions_limit: number | null;
  question_period: "month" | "total";
  resets_at: string;
}

export interface AskConversation {
  id: number;
  title: string;
  model: string;
  created_at: string;
  updated_at: string;
  expires_at: string;
}

export interface AskMessage {
  seq: number;
  role: "user" | "assistant";
  text: string;
  page?: AskPage;
  stop_reason?: string;
  created_at: string;
}

export interface AskPage {
  kind: "finding" | "asset" | "component" | "fix_group";
  id: string;
}

export interface AskSettings {
  enabled: boolean;
  configured: boolean;
  provider: string;
  model: string;
  question_limit: number | null;
  question_period: "month" | "total";
  spend_cap_micros: number | null;
  questions_this_month: number;
  spend_this_month_micros: number;
}

/** Who processes the questions, in words, for the notice. */
export function providerWords(provider: string): string {
  switch (provider) {
    case "bedrock":
      return "Amazon Bedrock, in the AWS account and region this server is set up with";
    case "vertex":
      return "Google Vertex AI, in the Google Cloud project and region this server is set up with";
    default:
      return "Anthropic, in the United States";
  }
}

/** The data notice a person accepts before their first question. */
export function noticeText(provider: string): string[] {
  return [
    `Ask Stackurity uses Claude, an AI model made by Anthropic. When you ask a question, Stackurity sends it to ${providerWords(provider)}, ` +
      "together with the page you have open and the Stackurity data the assistant reads to answer it: your inventory, issues, " +
      "advisory text, and asset, team and package names. Your colleagues' names and email addresses are removed first.",
    "The assistant can read only what you can see in Stackurity, and it cannot change anything.",
    "Stackurity keeps your conversations for 30 days; database backups can keep them for up to about 60 days in all. Only you can read " +
      "them, and you can delete them at any time. Your organisation's admins can delete them but cannot read them.",
    "Answers can be wrong. Check them on the linked pages before you act on them.",
  ];
}

// Stackurity pages an answer may link to. Anything else is shown as text.
const ALLOWED = [/^\/findings\/\d{1,18}$/, /^\/assets\/\d{1,18}$/, /^\/components\/\d{1,18}$/, /^\/fixes\/[A-Za-z0-9:_.-]{1,128}$/, /^\/fixes$/, /^\/fixes\/issues$/, /^\/help\/[a-z0-9-]{1,64}$/];

/** The path to link to, or null when the target is not one of ours. */
export function askHref(href: string): string | null {
  const h = href.trim();
  if (!h.startsWith("/") || h.startsWith("//") || h.includes("\\") || h.includes("..")) return null;
  return ALLOWED.some((re) => re.test(h)) ? h : null;
}

export type Inline =
  | { kind: "text"; text: string }
  | { kind: "bold"; parts: Inline[] }
  | { kind: "code"; text: string }
  | { kind: "link"; text: string; to: string };

const INLINE = /(`[^`\n]+`|\*\*[^*\n]+\*\*|!?\[[^\]\n]*\]\([^)\n]*\))/g;

/**
 * Splits a line into text, bold, code and links. A link whose target is not
 * a Stackurity page, and any image, becomes its text alone; bare web
 * addresses stay text and are never made clickable.
 */
export function parseInline(line: string): Inline[] {
  const out: Inline[] = [];
  for (const p of line.split(INLINE)) {
    if (!p) continue;
    if (p.length > 2 && p.startsWith("`") && p.endsWith("`")) {
      out.push({ kind: "code", text: p.slice(1, -1) });
      continue;
    }
    if (p.length > 4 && p.startsWith("**") && p.endsWith("**")) {
      out.push({ kind: "bold", parts: parseInline(p.slice(2, -2)) });
      continue;
    }
    const m = p.match(/^(!?)\[([^\]\n]*)\]\(([^)\n]*)\)$/);
    if (m) {
      const to = m[1] === "!" ? null : askHref(m[3]);
      if (to && m[2].trim()) out.push({ kind: "link", text: m[2], to });
      else if (m[2].trim()) out.push({ kind: "text", text: m[2] });
      continue;
    }
    out.push({ kind: "text", text: p });
  }
  return out;
}

export type AskBlock = { kind: "p"; lines: string[] } | { kind: "list"; ordered: boolean; items: string[] } | { kind: "code"; text: string };

/** Splits an answer into paragraphs, lists and code blocks. */
export function parseBlocks(src: string): AskBlock[] {
  const out: AskBlock[] = [];
  const lines = src.replace(/\r\n?/g, "\n").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith("```")) {
      const body: string[] = [];
      for (i++; i < lines.length && !lines[i].trim().startsWith("```"); i++) body.push(lines[i]);
      out.push({ kind: "code", text: body.join("\n") });
      continue;
    }
    const item = line.match(/^\s*(?:([-*•])|(\d+)[.)])\s+(.*)$/);
    if (item) {
      const ordered = Boolean(item[2]);
      const last = out[out.length - 1];
      if (last?.kind === "list" && last.ordered === ordered) last.items.push(item[3]);
      else out.push({ kind: "list", ordered, items: [item[3]] });
      continue;
    }
    if (!line.trim()) {
      out.push({ kind: "p", lines: [] });
      continue;
    }
    const text = line.replace(/^#{1,6}\s+/, "");
    const last = out[out.length - 1];
    if (last?.kind === "p" && last.lines.length > 0) last.lines.push(text);
    else out.push({ kind: "p", lines: [text] });
  }
  return out.filter((b) => b.kind !== "p" || b.lines.length > 0);
}

/** The page a path shows, as the assistant's context. */
export function pageOf(pathname: string): AskPage | null {
  let m = pathname.match(/^\/findings\/(\d+)$/);
  if (m) return { kind: "finding", id: m[1] };
  m = pathname.match(/^\/assets\/(\d+)$/);
  if (m) return { kind: "asset", id: m[1] };
  m = pathname.match(/^\/components\/(\d+)$/);
  if (m) return { kind: "component", id: m[1] };
  m = pathname.match(/^\/fixes\/([^/]+)$/);
  if (m && m[1] !== "issues" && m[1] !== "automatic") return { kind: "fix_group", id: decodeURIComponent(m[1]) };
  return null;
}

export const PAGE_LABEL: Record<AskPage["kind"], string> = { finding: "this issue", asset: "this asset", component: "this package", fix_group: "this fix" };

export interface AskEvent {
  event: string;
  data: Record<string, unknown>;
}

/** Reads server-sent events from chunks of text; keeps what is incomplete. */
export class SSEParser {
  private buf = "";
  push(chunk: string): AskEvent[] {
    this.buf += chunk.replace(/\r\n?/g, "\n");
    const out: AskEvent[] = [];
    let at: number;
    while ((at = this.buf.indexOf("\n\n")) >= 0) {
      const block = this.buf.slice(0, at);
      this.buf = this.buf.slice(at + 2);
      let event = "message";
      const data: string[] = [];
      for (const line of block.split("\n")) {
        if (line.startsWith(":")) continue;
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
      }
      if (data.length === 0) continue;
      try {
        out.push({ event, data: JSON.parse(data.join("\n")) as Record<string, unknown> });
      } catch {
        // not ours: ignore
      }
    }
    return out;
  }
}

export class AskHTTPError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/** Asks a question and reports each event as it arrives. */
export async function streamQuestion(
  conv: number,
  text: string,
  page: AskPage | null,
  project: number,
  on: (e: AskEvent) => void,
  signal: AbortSignal,
): Promise<void> {
  const headers: Record<string, string> = { Accept: "text/event-stream", "Content-Type": "application/json", "X-Stackurity-CSRF": "1" };
  if (project > 0) headers["X-Stackurity-Project"] = String(project);
  const res = await fetch(`/api/v1/ask/conversations/${conv}/messages`, {
    method: "POST",
    headers,
    credentials: "same-origin",
    body: JSON.stringify(page ? { text, page } : { text }),
    signal,
  });
  if (!res.ok || !res.body) {
    let code = `http_${res.status}`;
    let message = `Request failed (${res.status})`;
    try {
      const e = (await res.json()) as { error?: { code?: string; message?: string } };
      code = e.error?.code ?? code;
      message = e.error?.message ?? message;
    } catch {
      // keep the defaults
    }
    throw new AskHTTPError(res.status, code, message);
  }
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  const p = new SSEParser();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    for (const e of p.push(dec.decode(value, { stream: true }))) on(e);
  }
}
