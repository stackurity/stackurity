import { test } from "node:test";
import assert from "node:assert/strict";
import { canConfirm, confirmWord, DialogQueue, keyAction, nextFocus, typedMatches } from "./confirm.ts";

const destroy = { title: "Delete asset web-1?", action: "Delete asset", destructive: true, typeToConfirm: "web-1" };
const reversible = { title: "Disable channel ops?", action: "Disable channel" };

test("type to confirm: the name, case-sensitive, spaces trimmed", () => {
  assert.equal(confirmWord(destroy), "web-1");
  assert.equal(canConfirm(destroy, ""), false);
  assert.equal(canConfirm(destroy, "Web-1"), false);
  assert.equal(canConfirm(destroy, "web-"), false);
  assert.equal(canConfirm(destroy, "  web-1 "), true);
  assert.equal(typedMatches("web-1", "web-1"), true);
});

test("type to confirm: 'delete' when the resource has no name", () => {
  assert.equal(confirmWord({ ...destroy, typeToConfirm: undefined }), "delete");
  assert.equal(confirmWord({ ...destroy, typeToConfirm: "   " }), "delete");
  assert.equal(canConfirm({ ...destroy, typeToConfirm: "" }, "Delete"), false);
  assert.equal(canConfirm({ ...destroy, typeToConfirm: "" }, "delete"), true);
});

test("reversible actions need no typing", () => {
  assert.equal(confirmWord(reversible), "");
  assert.equal(canConfirm(reversible, ""), true);
});

test("Esc cancels; Enter never confirms a destructive action", () => {
  assert.equal(keyAction("Escape", destroy, ""), "cancel");
  assert.equal(keyAction("Escape", reversible, ""), "cancel");
  assert.equal(keyAction("Enter", destroy, "web-1"), "block");
  assert.equal(keyAction("Enter", destroy, ""), "block");
  assert.equal(keyAction("Enter", reversible, ""), "confirm");
  assert.equal(keyAction("a", destroy, ""), "none");
});

test("focus is trapped: Tab wraps both ways, and comes back in from outside", () => {
  assert.equal(nextFocus(0, 3, false), 1);
  assert.equal(nextFocus(2, 3, false), 0);
  assert.equal(nextFocus(0, 3, true), 2);
  assert.equal(nextFocus(-1, 3, false), 0);
  assert.equal(nextFocus(-1, 3, true), 2);
  assert.equal(nextFocus(5, 3, false), 0);
  assert.equal(nextFocus(0, 0, false), -1);
});

test("a second request while one is open waits its turn, answered in order", () => {
  const q = new DialogQueue<string>();
  assert.equal(q.push("first"), "first");
  assert.equal(q.push("second"), null);
  assert.equal(q.push("third"), null);
  assert.equal(q.current(), "first");
  assert.equal(q.done(), "second");
  assert.equal(q.current(), "second");
  assert.equal(q.done(), "third");
  assert.equal(q.done(), null);
  assert.equal(q.current(), null);
  // Free again: the next is shown at once.
  assert.equal(q.push("fourth"), "fourth");
});
