// The fix groups and issues an Ask Stackurity answer links to, in the order
// they first appear. The panel shows each fix group's stored command and
// each issue's advisory pages under the answer. Only what renders as a link
// counts (the same parsing as the answer itself), and never more than
// MAX_REFS of each. Plain logic, tested in askRefs.test.ts.
import { parseBlocks, parseInline, type Inline } from "./ask.ts";

export const MAX_REFS = 5;

// Pages under /fixes that are not a fix group (App.tsx routes them first).
const NOT_A_GROUP = new Set(["issues", "mine", "leaks", "automatic"]);

export interface AnswerRefs {
  /** Fix group ids, as written in /fixes/GROUP_ID. */
  fixes: string[];
  /** Finding ids, as written in /findings/N. */
  findings: string[];
}

export function answerRefs(text: string): AnswerRefs {
  const fixes: string[] = [];
  const findings: string[] = [];
  const add = (list: string[], id: string) => {
    if (list.length < MAX_REFS && !list.includes(id)) list.push(id);
  };
  const walk = (parts: Inline[]) => {
    for (const p of parts) {
      if (p.kind === "bold") walk(p.parts);
      if (p.kind !== "link") continue;
      let m = p.to.match(/^\/fixes\/([A-Za-z0-9:_.-]{1,128})$/);
      if (m && !NOT_A_GROUP.has(m[1])) add(fixes, m[1]);
      m = p.to.match(/^\/findings\/(\d{1,18})$/);
      if (m) add(findings, m[1]);
    }
  };
  for (const b of parseBlocks(text)) {
    if (b.kind === "list") b.items.forEach((it) => walk(parseInline(it)));
    else if (b.kind === "p") b.lines.forEach((l) => walk(parseInline(l)));
  }
  return { fixes, findings };
}
