import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

// A .filters row lines its fields up by their bottom edge (styles.css), so a
// hint under one field lifts that field's label and control above the
// others (the owner rule form's Team and Project, 2 Nov). Fields that carry
// hints belong in a .form-grid, which lines them up at the top.

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) return files(p);
    return /\.tsx$/.test(n) ? [p] : [];
  });
}

/** The JSX of each element with className="filters", up to its closing tag. */
export function filterRows(src: string): { line: number; body: string }[] {
  const rows: { line: number; body: string }[] = [];
  for (const m of src.matchAll(/<(\w+)\b[^>]*className="filters"[^>]*>/g)) {
    const tag = m[1];
    const open = new RegExp(`<${tag}\\b`, "g");
    const close = new RegExp(`</${tag}>`, "g");
    let depth = 1;
    let at = m.index! + m[0].length;
    while (depth > 0) {
      open.lastIndex = close.lastIndex = at;
      const o = open.exec(src);
      const c = close.exec(src);
      if (!c) break;
      if (o && o.index < c.index) {
        depth++;
        at = o.index + 1;
      } else {
        depth--;
        at = c.index + c[0].length;
      }
    }
    rows.push({ line: src.slice(0, m.index).split("\n").length, body: src.slice(m.index, at) });
  }
  return rows;
}

const hint = /className="hint"|<\w*Hint\b/;

test("no .filters row holds a field hint", () => {
  const src = new URL(".", import.meta.url).pathname;
  const found: string[] = [];
  for (const f of files(src))
    for (const r of filterRows(readFileSync(f, "utf8"))) if (hint.test(r.body)) found.push(`${f.slice(src.length)}:${r.line}`);
  assert.deepEqual(found, [], "put fields with hints in a .form-grid, not a .filters row");
});

test("the check finds a hint inside a nested filters row", () => {
  const bad = `<div className="filters">\n<div className="field"><select /><p className="hint">x</p></div>\n</div>`;
  const nested = `<div className="filters"><div className="field"><div><NoTeamsHint what="x" /></div></div></div>`;
  const ok = `<div className="filters"><div className="field"><select /></div></div>\n<p className="hint">after</p>`;
  assert.ok(hint.test(filterRows(bad)[0].body));
  assert.ok(hint.test(filterRows(nested)[0].body));
  assert.ok(!hint.test(filterRows(ok)[0].body));
});
