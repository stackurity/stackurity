import { test } from "node:test";
import assert from "node:assert/strict";
import { autoLink, headingOf, lookedAt, structureAnswer } from "./askAnswer.ts";
import { askHref, parseInline } from "./ask.ts";

test("an answer without known headings is not structured", () => {
  assert.equal(structureAnswer("Upgrade openssl on web-1.\n\n- [CVE-1](/findings/1)"), null);
  assert.equal(structureAnswer("## Next steps\nDo it."), null);
  assert.equal(structureAnswer(""), null);
  // A known heading with nothing under it changes nothing.
  assert.equal(structureAnswer("Do it.\n\n## Why\n\n"), null);
});

test("an answer splits into its lead and sections, in a fixed order", () => {
  const a = structureAnswer(
    "Upgrade openssl on [web-1](/assets/3) first.\n\n## Data gaps\nweb-2 has not reported for 9 days.\n\n## Why\nIt fixes 4 critical issues.\n\n## Evidence\n- [CVE-2024-1](/findings/7)\n\n## Alternatives\nPatch only the kernel: fewer reboots, 2 issues stay open.",
  );
  assert.ok(a);
  assert.equal(a.lead, "Upgrade openssl on [web-1](/assets/3) first.");
  assert.deepEqual(
    a.sections.map((s) => s.kind),
    ["why", "evidence", "alternatives", "gaps"],
  );
  assert.equal(a.sections[1].body, "- [CVE-2024-1](/findings/7)");
});

test("heading forms and synonyms the model may use", () => {
  assert.equal(headingOf("## Why"), "why");
  assert.equal(headingOf("### Evidence:"), "evidence");
  assert.equal(headingOf("**Why**"), "why");
  assert.equal(headingOf("**Data gaps:**"), "gaps");
  assert.equal(headingOf("**Trade-offs**:"), "alternatives");
  assert.equal(headingOf("## What I couldn’t check"), "gaps");
  assert.equal(headingOf("## Recommendation"), "lead");
  assert.equal(headingOf("# Alternatives and trade-offs"), "alternatives");
  // Not a heading: words in a sentence, bold inside a line, unknown names.
  assert.equal(headingOf("Why this matters: it is exposed."), null);
  assert.equal(headingOf("**Why** it matters"), null);
  assert.equal(headingOf("## Next steps"), null);
  assert.equal(headingOf("- Evidence"), null);
});

test("a heading over the recommendation is dropped, and headings in code stay code", () => {
  const a = structureAnswer("## Recommendation\nUpgrade nginx.\n\n**Why**\nEOL.\n\n```\n## Why\n```");
  assert.ok(a);
  assert.equal(a.lead, "Upgrade nginx.");
  assert.equal(a.sections.length, 1);
  assert.equal(a.sections[0].body, "EOL.\n\n```\n## Why\n```");
});

test("an answer that starts with a section has an empty lead", () => {
  const a = structureAnswer("## Evidence\n- one\n## Evidence\n- two");
  assert.ok(a);
  assert.equal(a.lead, "");
  assert.deepEqual(a.sections, [{ kind: "evidence", body: "- one\n- two" }]);
});

test("what Ask looked at: reads only, without repeats, linked by number", () => {
  assert.deepEqual(
    lookedAt(["Summarising the earlier conversation", "Reading issue #12", "Listing assets", "Reading issue #12", "Reading the fixes #3", "Reading asset #4", "Trying again with a stronger model", "Reading"]),
    [
      { label: "Reading issue #12", count: 2, to: "/findings/12" },
      { label: "Listing assets", count: 1 },
      { label: "Reading the fixes #3", count: 1, to: "/assets/3" },
      { label: "Reading asset #4", count: 1, to: "/assets/4" },
      { label: "Reading", count: 1 },
    ],
  );
  assert.deepEqual(lookedAt(["Reading issue #12x", "Reading issue #-1", ""]), [{ label: "Reading issue #12x", count: 1 }, { label: "Reading issue #-1", count: 1 }]);
});

test("advisory ids and numbered issues in text become in-app links", () => {
  assert.deepEqual(autoLink("CVE-2024-3094 is on issue #12 and asset #3."), [
    { kind: "link", text: "CVE-2024-3094", to: "/search?q=CVE-2024-3094" },
    { kind: "text", text: " is on " },
    { kind: "link", text: "issue #12", to: "/findings/12" },
    { kind: "text", text: " and " },
    { kind: "link", text: "asset #3", to: "/assets/3" },
    { kind: "text", text: "." },
  ]);
  assert.deepEqual(autoLink("GHSA-35jh-r3h4-6jhm"), [{ kind: "link", text: "GHSA-35jh-r3h4-6jhm", to: "/search?q=GHSA-35jh-r3h4-6jhm" }]);
  // Not ids: no "#", a malformed advisory, an id glued to other text.
  for (const plain of ["issue 2 of 3", "CVE-24-1", "GHSA-aaaa-bbbb-cccc", "xCVE-2024-3094", "see https://evil.example/CVE-2024-3094x"]) {
    assert.ok(
      autoLink(plain).every((p) => p.kind === "text"),
      plain,
    );
  }
});

test("auto links pass the same check as written links", () => {
  assert.equal(askHref("/search?q=CVE-2024-3094"), "/search?q=CVE-2024-3094");
  assert.equal(askHref("/search?q=CVE-2024-3094&x=1"), null);
  assert.equal(askHref("/search?q=anything"), null);
  const parts = parseInline("Fix **CVE-2021-44228** in `CVE-2021-44228` and [issue #5](/findings/5)");
  assert.deepEqual(parts, [
    { kind: "text", text: "Fix " },
    { kind: "bold", parts: [{ kind: "link", text: "CVE-2021-44228", to: "/search?q=CVE-2021-44228" }] },
    { kind: "text", text: " in " },
    { kind: "code", text: "CVE-2021-44228" },
    { kind: "text", text: " and " },
    { kind: "link", text: "issue #5", to: "/findings/5" },
  ]);
});
