import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// The in-app confirm dialog must be the top layer: a panel, menu or
// overlay drawn above it hides the dialog it opened (the Ask panel did,
// on a phone, so a conversation could not be deleted there).
test("the confirm dialog is above every other layer", () => {
  const css = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
  const rules = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)];
  let dialog = -1;
  const others: [string, number][] = [];
  for (const [, sel, body] of rules) {
    const m = /z-index:\s*(\d+)/.exec(body);
    if (!m) continue;
    const z = Number(m[1]);
    if (sel.includes(".confirm-backdrop")) dialog = z;
    else others.push([sel.trim(), z]);
  }
  assert.ok(dialog > 0, "no z-index on .confirm-backdrop");
  for (const [sel, z] of others) assert.ok(z < dialog, `${sel} (z-index ${z}) is drawn above the confirm dialog (${dialog})`);
});
