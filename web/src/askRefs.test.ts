import { test } from "node:test";
import assert from "node:assert/strict";
import { answerRefs } from "./askRefs.ts";

test("finds the fix groups and issues an answer links to", () => {
  const text = [
    "Patch [web-1](/fixes/12:security_updates) first, then **[old kernels](/fixes/12:old_kernels)**.",
    "",
    "## Evidence",
    "- [CVE-2024-3094 on web-1](/findings/88)",
    "- issue #90 is the same package; see also [issue 88](/findings/88)",
    "- [all issues](/fixes/issues), [my work](/fixes/mine), [leaks](/fixes/leaks), [auto](/fixes/automatic)",
    "```",
    "[in code](/fixes/1:security_updates) [x](/findings/1)",
    "```",
    "`[in inline code](/findings/2)` [bad](https://evil.example/fixes/3:x) [bad](/fixes/../x) ![img](/findings/4)",
  ].join("\n");
  assert.deepEqual(answerRefs(text), { fixes: ["12:security_updates", "12:old_kernels"], findings: ["88", "90"] });
});

test("never more than five of each", () => {
  const text = Array.from({ length: 8 }, (_, i) => `[f${i}](/fixes/${i}:security_updates) [i${i}](/findings/${i + 1})`).join("\n");
  const r = answerRefs(text);
  assert.deepEqual(r.fixes, ["0:security_updates", "1:security_updates", "2:security_updates", "3:security_updates", "4:security_updates"]);
  assert.deepEqual(r.findings, ["1", "2", "3", "4", "5"]);
});

test("an answer with no links has none", () => {
  assert.deepEqual(answerRefs("Run sudo apt upgrade on https://example.com"), { fixes: [], findings: [] });
});
