/**
 * Help articles are plain data so they can be searched on the client.
 * Inline text supports **bold**, `code`, [label](/app/path) and [label](help:article-id).
 */
export type Block =
  | { p: string }
  | { h: string }
  | { steps: string[] }
  | { list: string[] }
  | { code: string; lang?: string; label?: string }
  | { note: string }
  | { warn: string }
  | { table: string[][] }; // first row is the header

export interface Article {
  id: string;
  title: string;
  section: string;
  summary: string;
  /** Menu path, e.g. ["Remediation", "Policies"]. */
  where?: string[];
  body: Block[];
  /** Extra search terms. */
  keywords?: string;
}

export const SECTIONS = ["Getting started", "Adding servers and sources", "Daily work", "Remediation", "Settings and administration"] as const;

export function blockText(b: Block): string {
  if ("p" in b) return b.p;
  if ("h" in b) return b.h;
  if ("steps" in b) return b.steps.join(" ");
  if ("list" in b) return b.list.join(" ");
  if ("code" in b) return b.code;
  if ("note" in b) return b.note;
  if ("warn" in b) return b.warn;
  return b.table.map((r) => r.join(" ")).join(" ");
}

export function articleText(a: Article): string {
  return [a.title, a.summary, a.keywords ?? "", (a.where ?? []).join(" "), ...a.body.map(blockText)].join(" ").toLowerCase();
}
