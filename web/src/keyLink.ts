/*
 * "Get a free key" (self-hosted server ↔ Stackurity Cloud). The server's
 * dashboard sends the browser to the Cloud with a one-time state; the
 * Cloud sends it back to /setup/community-key#key=…&state=…, the key in
 * the fragment so it never reaches any server's logs.
 *
 * Kept free of React and of value imports so `npm test` runs it with Node.
 */

/** The dashboard page, under the server's base URL, that takes the key back. */
export const KEY_RETURN_PATH = "/setup/community-key";

/** The Cloud page that issues a key for a server. */
export const KEY_LINK_PATH = "/community-key/new";

/** Where the Cloud remembers that page across sign-up (localStorage key; see resumePath). */
export const KEY_LINK_RESUME = "stackurity.keyLinkResume";

export type KeyReturn =
  /** A key and the state it came with, both well-formed. */
  | { kind: "key"; key: string; state: string }
  /** The Cloud said why no key came (or the fragment was not one of ours). */
  | { kind: "error"; reason: string }
  /** No fragment at all: opened by hand, or the fragment was already dropped. */
  | { kind: "none" };

// A licence key is "payload.signature", both base64url; a state is ours.
const KEY = /^[A-Za-z0-9_-]{16,8192}\.[A-Za-z0-9_-]{16,256}$/;
const STATE = /^cks_[a-z2-7]{16,96}$/;

/** Reads what the Cloud put in the address's fragment (window.location.hash). */
export function parseKeyReturn(hash: string): KeyReturn {
  const raw = hash.replace(/^#/, "");
  if (raw.trim() === "") return { kind: "none" };
  let p: URLSearchParams;
  try {
    p = new URLSearchParams(raw);
  } catch {
    return { kind: "error", reason: "The address was not complete." };
  }
  const error = p.get("error");
  if (error !== null) return { kind: "error", reason: error === "access_denied" ? "No key was issued." : "Stackurity Cloud did not issue a key." };
  const key = (p.get("key") ?? "").trim();
  const state = (p.get("state") ?? "").trim();
  if (p.getAll("key").length !== 1 || p.getAll("state").length !== 1 || !KEY.test(key) || !STATE.test(state)) {
    return { kind: "error", reason: "The address was not complete or not from Stackurity Cloud." };
  }
  return { kind: "key", key, state };
}

/** What a server's "Get a free key" sends: always in the fragment, never a query. */
export type KeyLinkValues = { return: string; state: string; server_id?: string };

/**
 * Reads the values of /community-key/new#return=…&state=…&server_id=… from
 * the fragment (window.location.hash). A query string is never read: it
 * would be in the access logs of every proxy on the way.
 */
export function parseKeyLinkHash(hash: string): KeyLinkValues {
  let p: URLSearchParams;
  try {
    p = new URLSearchParams(hash.replace(/^#/, ""));
  } catch {
    p = new URLSearchParams();
  }
  const r: KeyLinkValues = { return: p.get("return") ?? "", state: p.get("state") ?? "" };
  const id = p.get("server_id");
  if (id) r.server_id = id;
  return r;
}

/**
 * Where to go back to after signing up on the Cloud, from what the Cloud
 * page saved: only its own path with a fragment, never another site.
 */
export function resumePath(saved: string | null, now: number): string | null {
  if (!saved) return null;
  try {
    const v = JSON.parse(saved) as { path?: unknown; at?: unknown };
    if (typeof v.path !== "string" || typeof v.at !== "number" || now - v.at > 60 * 60 * 1000 || now < v.at) return null;
    if (!v.path.startsWith(KEY_LINK_PATH + "#") || /[\\\s?]/.test(v.path) || v.path.includes("//")) return null;
    return v.path;
  } catch {
    return null;
  }
}

/** The Cloud's redirect, as the Cloud API built it: http(s) only, to the confirmed host. */
export function safeRedirect(redirect: string, host: string): string | null {
  let u: URL;
  try {
    u = new URL(redirect);
  } catch {
    return null;
  }
  if ((u.protocol !== "https:" && u.protocol !== "http:") || u.username !== "" || u.password !== "" || u.host !== host) return null;
  if (!u.pathname.endsWith(KEY_RETURN_PATH) || u.search !== "") return null;
  return u.href;
}
