// How an Ask Stackurity answer is laid out in the panel: a short lead (the
// recommendation), then the sections the model wrote under headings it
// knows ("Why", "Evidence", "Alternatives", "Data gaps"), and a footer that
// lists what Ask read to answer. Plain logic, tested in askAnswer.test.ts.
//
// An answer without those headings (every answer written before the prompt
// asked for them, or one where the model ignored it) is not structured:
// structureAnswer returns null and the panel shows it as it always has.

export type SectionKind = "why" | "evidence" | "alternatives" | "gaps";

export const SECTION_TITLE: Record<SectionKind, string> = {
  why: "Why",
  evidence: "Evidence",
  alternatives: "Alternatives and trade-offs",
  gaps: "Data gaps",
};

const SECTION_ORDER: SectionKind[] = ["why", "evidence", "alternatives", "gaps"];

export interface AnswerSection {
  kind: SectionKind;
  /** The section's Markdown, for AskAnswer's usual renderer. */
  body: string;
}

export interface StructuredAnswer {
  /** The recommendation: what comes before the first section. May be "". */
  lead: string;
  /** The sections that have something in them, in a fixed order. */
  sections: AnswerSection[];
}

// Heading words the model may use, folded to the section they belong to.
// "lead" is a heading over the recommendation itself.
const HEADINGS: Record<string, SectionKind | "lead"> = {
  recommendation: "lead",
  "recommended action": "lead",
  answer: "lead",
  "short answer": "lead",
  summary: "lead",
  why: "why",
  reasoning: "why",
  rationale: "why",
  "why this": "why",
  evidence: "evidence",
  "what i found": "evidence",
  sources: "evidence",
  alternatives: "alternatives",
  "alternatives and trade-offs": "alternatives",
  "alternatives and tradeoffs": "alternatives",
  "trade-offs": "alternatives",
  tradeoffs: "alternatives",
  options: "alternatives",
  "other options": "alternatives",
  "data gaps": "gaps",
  gaps: "gaps",
  "missing data": "gaps",
  "what i could not check": "gaps",
  "what i couldn't check": "gaps",
  "not checked": "gaps",
  limitations: "gaps",
};

/**
 * The section a line heads, or null. A heading is a whole line: a Markdown
 * heading ("## Why") or a line that is only bold ("**Why**", "**Why:**").
 */
export function headingOf(line: string): SectionKind | "lead" | null {
  const t = line.trim();
  let m = t.match(/^#{1,4}\s+(.+?)\s*#*$/);
  if (!m) m = t.match(/^\*\*([^*]+?)\*\*\s*:?$/);
  if (!m) return null;
  const word = m[1]
    .replace(/[:.]+$/, "")
    .replace(/\*\*/g, "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ")
    .replace(/[’]/g, "'");
  return HEADINGS[word] ?? null;
}

/** The answer split at the headings it knows, or null when it has none. */
export function structureAnswer(text: string): StructuredAnswer | null {
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const lead: string[] = [];
  const bodies = new Map<SectionKind, string[]>();
  let at: SectionKind | "lead" = "lead";
  let fenced = false;
  let found = false;
  for (const line of lines) {
    if (line.trim().startsWith("```")) fenced = !fenced;
    const h = fenced ? null : headingOf(line);
    if (h) {
      at = h;
      if (h !== "lead") found = true;
      continue;
    }
    if (at === "lead") lead.push(line);
    else {
      const b = bodies.get(at) ?? [];
      b.push(line);
      bodies.set(at, b);
    }
  }
  if (!found) return null;
  const sections = SECTION_ORDER.flatMap((kind) => {
    const body = (bodies.get(kind) ?? []).join("\n").trim();
    return body ? [{ kind, body }] : [];
  });
  if (sections.length === 0) return null;
  return { lead: lead.join("\n").trim(), sections };
}

export interface LookedAt {
  /** What was read, in the words the server sent ("Reading issue #12"). */
  label: string;
  /** How many times it was read. */
  count: number;
  /** The page it was about, when the label names one. */
  to?: string;
}

// Progress notes the server sends on the same "tool" event that are not a
// read of the organisation's data.
const NOT_A_READ = new Set(["Summarising the earlier conversation", "Trying again with a stronger model"]);

/**
 * The reads Ask made for one answer, from the stream's tool events, in
 * order and without repeats. A label naming an issue or an asset by number
 * links to it; the number must be digits only, so nothing else in a label
 * can become a link.
 */
export function lookedAt(labels: string[]): LookedAt[] {
  const out: LookedAt[] = [];
  for (const raw of labels) {
    const label = raw.trim();
    if (!label || NOT_A_READ.has(label) || label.length > 120) continue;
    const seen = out.find((l) => l.label === label);
    if (seen) {
      seen.count++;
      continue;
    }
    const item: LookedAt = { label, count: 1 };
    let m = label.match(/^Reading issue #(\d{1,18})$/);
    if (m) item.to = `/findings/${m[1]}`;
    m = label.match(/^Reading (?:asset|the fixes) #(\d{1,18})$/);
    if (m) item.to = `/assets/${m[1]}`;
    out.push(item);
  }
  return out;
}

export type AutoPart = { kind: "text"; text: string } | { kind: "link"; text: string; to: string };

// Ids that are safe to recognise in running text: advisories by their
// published formats, and issues and assets only when written with "#" (so
// "issue 2 of 3" stays text).
const AUTO = /\b(CVE-\d{4}-\d{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})\b|\b((?:issue|finding|asset)) #(\d{1,18})\b/gi;

/**
 * Splits plain answer text so that advisory ids open Stackurity's search and
 * "issue #12" or "asset #3" open that page. Only these patterns become
 * links, and each link is built from the matched digits or id alone.
 */
export function autoLink(text: string): AutoPart[] {
  const out: AutoPart[] = [];
  let last = 0;
  for (const m of text.matchAll(AUTO)) {
    const at = m.index ?? 0;
    let to: string;
    if (m[1]) to = `/search?q=${encodeURIComponent(m[1])}`;
    else to = `${m[2].toLowerCase() === "asset" ? "/assets/" : "/findings/"}${m[3]}`;
    if (at > last) out.push({ kind: "text", text: text.slice(last, at) });
    out.push({ kind: "link", text: m[0], to });
    last = at + m[0].length;
  }
  if (last < text.length) out.push({ kind: "text", text: text.slice(last) });
  return out;
}
