import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

// The browser's confirm, alert and prompt are never used: every question
// goes through the app's own dialog (components/ConfirmDialog.tsx), which
// names the action, traps focus and asks for the name of what is destroyed.
// The owner's rule: a UI bug becomes a test over every file.

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) return files(p);
    return /\.(ts|tsx)$/.test(n) && !/\.test\.ts$/.test(n) ? [p] : [];
  });
}

const call = /(?:\bwindow\s*\.\s*|\bglobalThis\s*\.\s*|(?<![.\w]))(confirm|alert|prompt)\(/g;

test("no file in web/src calls window.confirm, alert or prompt", () => {
  const src = new URL(".", import.meta.url).pathname;
  const found: string[] = [];
  for (const f of files(src)) {
    const lines = readFileSync(f, "utf8").split("\n");
    lines.forEach((l, i) => {
      if (/^\s*(\/\/|\*)/.test(l)) return;
      for (const m of l.matchAll(call)) found.push(`${f.slice(src.length)}:${i + 1}: ${m[0]}`);
    });
  }
  assert.deepEqual(found, [], "use confirmAction or promptText from components/ConfirmDialog instead");
});

test("the check catches each form", () => {
  for (const bad of ["window.confirm('x')", "if (!confirm(msg))", "alert('done')", "window.prompt('Name')", "globalThis.alert(1)"])
    assert.ok([...bad.matchAll(call)].length > 0, bad);
  for (const ok of ["confirmAction({})", "promptText({})", "act.confirm()", "const confirmed = 1"]) assert.equal([...ok.matchAll(call)].length, 0, ok);
});
