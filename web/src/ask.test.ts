import { test } from "node:test";
import assert from "node:assert/strict";
import { askHref, pageOf, parseBlocks, parseInline, SSEParser, type Inline } from "./ask.ts";

function flat(parts: Inline[]): string {
  return parts.map((p) => (p.kind === "bold" ? `**${flat(p.parts)}**` : p.kind === "link" ? `<${p.to}|${p.text}>` : p.text)).join("");
}

test("links only to Stackurity's own pages", () => {
  for (const ok of ["/findings/12", "/assets/3", "/components/7", "/fixes/3:package_upgrade:9", "/fixes", "/fixes/issues", "/help/ai-assistants"]) {
    assert.equal(askHref(ok), ok, ok);
  }
  for (const bad of [
    "https://evil.example/?d=secret",
    "http://localhost/findings/1",
    "//evil.example/findings/1",
    "javascript:alert(1)",
    "data:text/html,<b>x</b>",
    "/findings/1?leak=secret",
    "/findings/1#x",
    "/findings/1/../../logout",
    "/api/v1/tokens",
    "/settings/tokens",
    "/findings/abc",
    "\\\\evil.example\\x",
    "/assets/1 onmouseover=x",
    "",
  ]) {
    assert.equal(askHref(bad), null, bad);
  }
});

test("injection fixtures render as text", () => {
  // An image is never rendered, whatever its address; a foreign link keeps
  // only its words; a bare address is not clickable.
  assert.deepEqual(parseInline("see ![x](https://evil.example/p.png?d=secret) here"), [
    { kind: "text", text: "see " },
    { kind: "text", text: "x" },
    { kind: "text", text: " here" },
  ]);
  assert.deepEqual(parseInline("![](/findings/1)"), []);
  assert.equal(flat(parseInline("[click](https://evil.example/?q=data)")), "click");
  assert.equal(flat(parseInline("go to https://evil.example/x now")), "go to https://evil.example/x now");
  assert.ok(parseInline("go to https://evil.example/x now").every((p) => p.kind === "text"));
  assert.equal(flat(parseInline("<img src=x onerror=alert(1)>")), "<img src=x onerror=alert(1)>");
  assert.ok(parseInline("<img src=x onerror=alert(1)>").every((p) => p.kind === "text"));
  assert.equal(flat(parseInline("[CVE-1 on shop](/findings/7) and **[bad](//evil.example)**")), "</findings/7|CVE-1 on shop> and **bad**");
  assert.equal(flat(parseInline("`[x](/findings/1)`")), "[x](/findings/1)");
});

test("answers split into paragraphs, lists and code", () => {
  const b = parseBlocks("Two issues:\n\n- [one](/findings/1)\n- two\n\n1. first\n2. second\n\n```\ncurl x | sh\n```\n## Heading\ntext");
  assert.deepEqual(
    b.map((x) => x.kind),
    ["p", "list", "list", "code", "p"],
  );
  assert.deepEqual(b[1], { kind: "list", ordered: false, items: ["[one](/findings/1)", "two"] });
  assert.deepEqual(b[3], { kind: "code", text: "curl x | sh" });
  assert.deepEqual(b[4], { kind: "p", lines: ["Heading", "text"] });
});

test("the page open is the assistant's context", () => {
  assert.deepEqual(pageOf("/findings/12"), { kind: "finding", id: "12" });
  assert.deepEqual(pageOf("/assets/3"), { kind: "asset", id: "3" });
  assert.deepEqual(pageOf("/components/9"), { kind: "component", id: "9" });
  assert.deepEqual(pageOf("/fixes/3%3Apackage_upgrade%3A9"), { kind: "fix_group", id: "3:package_upgrade:9" });
  assert.equal(pageOf("/fixes/issues"), null);
  assert.equal(pageOf("/settings"), null);
  assert.equal(pageOf("/findings/12/edit"), null);
});

test("server-sent events across chunks", () => {
  const p = new SSEParser();
  assert.deepEqual(p.push("event: text\ndata: {\"te"), []);
  assert.deepEqual(p.push("xt\":\"Hel\"}\n\n: keep-alive\n\nevent: tool\r\ndata: {\"tool\":\"Reading\"}\r\n\r\nevent: done\ndata: {}\n"), [
    { event: "text", data: { text: "Hel" } },
    { event: "tool", data: { tool: "Reading" } },
  ]);
  assert.deepEqual(p.push("\n"), [{ event: "done", data: {} }]);
  assert.deepEqual(p.push("event: text\ndata: not json\n\n"), []);
});
