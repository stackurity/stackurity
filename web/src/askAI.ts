import type { AssistantConnection, Finding, FixGroup } from "./api";

/*
 * "Ask Claude / ChatGPT about this": the question a page hands to an
 * assistant, and how it opens.
 *
 * The question leaves Stackurity in a URL or the clipboard, so it holds
 * public identifiers only: an advisory id (CVE-..., GHSA-...), a package or
 * product name with its version, the fixed version, the ecosystem. Never an
 * asset name, hostname, IP, path, environment, team or anything else of the
 * organisation's: the builders below read only the whitelisted fields, every
 * value passes publicToken, and the result is checked against the record's
 * own internal values (withoutInternal). An assistant connected to
 * Stackurity looks the rest up itself, signed in, through the MCP server.
 */

export type Assistant = "claude" | "chatgpt";

export interface AskQuestion {
  /** The text handed to the assistant. */
  text: string;
  /** What the question is about, for the button's accessible name. */
  about: string;
}

const MAX_TOKEN = 120;
// Advisory ids by their publishers' prefixes; anything else (an internal
// ticket or host naming scheme) is not sent.
const ADVISORY_ID =
  /^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|(PYSEC|RUSTSEC|GO|OSV|MAL|EUVD|GSD|USN|DSA|DLA|DTSA|RHSA|RHBA|RLSA|ALSA|ALAS|ALAS2|ELSA|SUSE-SU|openSUSE-SU|BIT|SNYK|WS)-[A-Za-z0-9][A-Za-z0-9.:_-]{1,60})$/i;
const IPV4 = /(^|[^\d.])\d{1,3}(\.\d{1,3}){3}([^\d.]|$)/;
const IPV6 = /[0-9a-f]{0,4}:[0-9a-f]{0,4}:[0-9a-f]{0,4}:[0-9a-f]{0,4}/i;
const INTERNAL_SUFFIX = /\.(local|internal|lan|corp|home|intranet|localdomain|private)\b/i;
const EMAIL = /[^\s@]@[^\s@]+\.[a-z]{2,}/i;
// Package names, versions and product names: letters, digits and the
// punctuation ecosystems use (npm scopes, Maven coordinates, Debian epochs).
const TOKEN = /^[A-Za-z0-9@][A-Za-z0-9@._+~:/()^ -]*$/;

/** The value when it is safe to send, otherwise "". */
export function publicToken(v: string | null | undefined): string {
  const s = (v ?? "").trim();
  if (!s || s.length > MAX_TOKEN || !TOKEN.test(s)) return "";
  if (s.includes("://") || s.includes("//") || s.startsWith("/") || s.includes("\\")) return "";
  if (IPV4.test(s) || IPV6.test(s) || INTERNAL_SUFFIX.test(s) || EMAIL.test(s)) return "";
  return s;
}

/** An advisory id (CVE, GHSA, OSV-style ids such as PYSEC-..., RUSTSEC-..., USN-...), or "". */
export function advisoryId(v: string | null | undefined): string {
  const s = publicToken(v);
  if (!ADVISORY_ID.test(s)) return "";
  return /^cve-/i.test(s) ? s.toUpperCase() : s;
}

/**
 * Drops the question when it contains one of the record's internal values
 * (an asset that happens to share a package's name, say): no question is
 * better than one that leaks.
 */
export function withoutInternal(q: AskQuestion | null, internal: (string | null | undefined)[]): AskQuestion | null {
  if (!q) return null;
  const hay = q.text.toLowerCase();
  for (const raw of internal) {
    const v = (raw ?? "").trim().toLowerCase();
    if (v.length < 3) continue;
    const re = new RegExp(`(^|[^a-z0-9])${v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([^a-z0-9]|$)`);
    if (re.test(hay)) return null;
  }
  return q;
}

const CONNECTOR = "If you have the Stackurity connector, use it to see where I run it and what else it affects.";

type FindingFields = Pick<Finding, "kind" | "key" | "component_name" | "component_type" | "version" | "fixed_version"> &
  Partial<Pick<Finding, "asset_name" | "location" | "environment" | "asset_kind">>;

/** The question for one finding: its advisory id, package@version and the fixed version. */
export function askFromFinding(f: FindingFields): AskQuestion | null {
  const pkg = publicToken(f.component_name);
  const version = publicToken(f.version);
  const fixed = publicToken(f.fixed_version);
  const eco = publicToken(f.component_type);
  if (!pkg) return null;
  const what = `${pkg}${version ? ` ${version}` : ""}${eco ? ` (${eco})` : ""}`;
  let text: string;
  let about: string;
  if (f.kind === "end_of_life") {
    text = `${what} has reached end of life. What are the risks of staying on it, and which supported version should I move to? ${CONNECTOR}`;
    about = `${pkg} end of life`;
  } else {
    const id = advisoryId(f.key);
    text =
      `Explain ${id || "this vulnerability"} for my stack: ${what} is affected` +
      (fixed ? `, and it is fixed in ${fixed}` : ", with no fixed version listed") +
      `. How serious is it, and what should I upgrade? ${CONNECTOR}`;
    about = id || pkg;
  }
  return withoutInternal({ text, about }, [f.asset_name, f.location, f.environment]);
}

type FixFields = Pick<FixGroup, "kind" | "component" | "from_version" | "to_version" | "target_version"> &
  Partial<Pick<FixGroup, "asset_name" | "app_dir" | "environment" | "places">>;

/** The question for a fix: the package, the version installed and the version to move to. */
export function askFromFixGroup(g: FixFields): AskQuestion | null {
  const pkg = publicToken(g.component);
  if (!pkg) return null; // OS update bundles name no single package: nothing public to ask about
  const from = publicToken(g.from_version);
  const to = publicToken(g.target_version || g.to_version);
  const move = from && to ? ` from ${from} to ${to}` : to ? ` to ${to}` : "";
  const text =
    `Help me write the upgrade of ${pkg}${move}. What changes between these versions, what could break, and how should I test it? ` +
    `Draft the pull request description. ${CONNECTOR}`;
  const places = (g.places ?? []).flatMap((p) => [p.asset_name, p.app_dir, p.environment]);
  return withoutInternal({ text, about: `upgrading ${pkg}` }, [g.asset_name, g.app_dir, g.environment, ...places]);
}

/**
 * The question for an asset: its operating system and the upgrades waiting
 * on it (at most five), never the asset itself.
 */
export function askFromAsset(
  a: { name?: string; os_name?: string; environment?: string; /** Every other value of the asset's (hostname, addresses, account...). */ internal?: string[] },
  groups: FixFields[],
): AskQuestion | null {
  const os = publicToken(a.os_name);
  const ups = groups
    .map((g) => {
      const pkg = publicToken(g.component);
      if (!pkg) return "";
      const from = publicToken(g.from_version);
      const to = publicToken(g.target_version || g.to_version);
      return `${pkg}${from ? ` ${from}` : ""}${to ? ` → ${to}` : ""}`;
    })
    .filter(Boolean)
    .slice(0, 5);
  if (!os && ups.length === 0) return null;
  let text: string;
  if (os && ups.length) text = `One of my systems runs ${os}. It needs these upgrades: ${ups.join("; ")}. Which should I do first, and why?`;
  else if (ups.length) text = `One of my systems needs these upgrades: ${ups.join("; ")}. Which should I do first, and why?`;
  else text = `One of my systems runs ${os}. Is it still supported, and what should I keep an eye on?`;
  text += ` ${CONNECTOR}`;
  const internal = [a.name, a.environment, ...(a.internal ?? []), ...groups.flatMap((g) => [g.asset_name, g.app_dir, g.environment])];
  return withoutInternal({ text, about: os || "these upgrades" }, internal);
}

/*
 * How each assistant opens with the question, checked on 2026-10-31:
 * - Claude Desktop documents claude://claude.ai/new?q=<url-encoded> as a
 *   prefill that is not sent (truncated at about 14,000 characters):
 *   https://support.claude.com/en/articles/14729294-open-claude-desktop-with-a-link
 * - claude.ai on the web documents no prefill parameter for chats (only
 *   claude.ai/code takes ?prompt=, https://code.claude.com/docs/en/deep-links),
 *   so the question is copied and https://claude.ai/new opens.
 * - ChatGPT documents no prefill parameter (?q= is only described in
 *   community posts, https://community.openai.com/t/query-parameters-in-chatgpt/1027747),
 *   so the question is copied and https://chatgpt.com/ opens.
 */
export const OPEN: Record<Assistant, { label: string; href: string; copies: boolean }> = {
  claude: { label: "Claude", href: "https://claude.ai/new", copies: true },
  chatgpt: { label: "ChatGPT", href: "https://chatgpt.com/", copies: true },
};

export function claudeDesktopLink(q: AskQuestion): string {
  return `claude://claude.ai/new?q=${encodeURIComponent(q.text)}`;
}

/**
 * Which assistants to offer: the ones the person connected (by the client
 * name they registered with), or both when the connections name neither
 * (an editor, say). Empty when nothing is connected.
 */
export function assistantsFor(conns: Pick<AssistantConnection, "client_name" | "redirect_host">[]): Assistant[] {
  if (conns.length === 0) return [];
  const names = conns.map((c) => `${c.client_name} ${c.redirect_host}`.toLowerCase());
  const out: Assistant[] = [];
  if (names.some((n) => n.includes("claude") || n.includes("anthropic"))) out.push("claude");
  if (names.some((n) => n.includes("chatgpt") || n.includes("openai"))) out.push("chatgpt");
  return out.length ? out : ["claude", "chatgpt"];
}

/** Dismissal is per person, in this browser: there is no server-side preferences store. */
export function dismissKey(userId: number | null | undefined): string {
  return `stackurity.askAI.hidden.${userId ?? 0}`;
}

export function readDismissed(userId: number | null | undefined, store: Pick<Storage, "getItem"> | null = safeStorage()): boolean {
  try {
    return store?.getItem(dismissKey(userId)) === "1";
  } catch {
    return false;
  }
}

export function writeDismissed(userId: number | null | undefined, hidden: boolean, store: Pick<Storage, "setItem" | "removeItem"> | null = safeStorage()) {
  try {
    if (hidden) store?.setItem(dismissKey(userId), "1");
    else store?.removeItem(dismissKey(userId));
  } catch {
    // storage unavailable (private mode, blocked): the banner shows again next time
  }
}

function safeStorage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}
