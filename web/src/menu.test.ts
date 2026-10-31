import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { menuKeyClose, menuKeyMove, menuPosition } from "./menu.ts";

test("row menu: arrows wrap, Home and End jump, other keys are not the menu's", () => {
  assert.equal(menuKeyMove(-1, 3, "ArrowDown"), 0);
  assert.equal(menuKeyMove(0, 3, "ArrowDown"), 1);
  assert.equal(menuKeyMove(2, 3, "ArrowDown"), 0);
  assert.equal(menuKeyMove(0, 3, "ArrowUp"), 2);
  assert.equal(menuKeyMove(2, 3, "ArrowUp"), 1);
  assert.equal(menuKeyMove(1, 3, "Home"), 0);
  assert.equal(menuKeyMove(1, 3, "End"), 2);
  assert.equal(menuKeyMove(1, 3, "a"), null);
  assert.equal(menuKeyMove(0, 0, "ArrowDown"), null);
});

test("row menu: Escape closes and returns focus to the button; Tab closes", () => {
  assert.equal(menuKeyClose("Escape"), "close-refocus");
  assert.equal(menuKeyClose("Tab"), "close");
  assert.equal(menuKeyClose("Enter"), null);
});

test("row menu: opens under the button, right-aligned, above it near the bottom, never off screen", () => {
  const view = { width: 1280, height: 800 };
  const menu = { width: 200, height: 160 };
  assert.deepEqual(menuPosition({ top: 100, bottom: 132, right: 1200 }, menu, view), { top: 136, left: 1000 });
  // Near the bottom: above the button.
  assert.deepEqual(menuPosition({ top: 700, bottom: 732, right: 1200 }, menu, view), { top: 536, left: 1000 });
  // A button near the left edge: the menu stays on screen.
  assert.equal(menuPosition({ top: 100, bottom: 132, right: 50 }, menu, view).left, 4);
  // A narrow phone screen.
  assert.equal(menuPosition({ top: 100, bottom: 132, right: 390 }, { width: 200, height: 100 }, { width: 390, height: 844 }).left, 186);
});

test("Users fits next to the Settings list: actions in a menu, two-factor as an icon, no Created or Teams columns", () => {
  const src = readFileSync(new URL("./pages/settings/Users.tsx", import.meta.url), "utf8");
  const cols = src.slice(src.indexOf("const columns: Column<User>[]"), src.indexOf("return (\n    <>"));
  const keys = [...cols.matchAll(/key: "([a-z]+)"/g)].map((m) => m[1]);
  assert.deepEqual(keys, ["user", "role", "status", "mfa", "login", "actions"]);
  assert.match(cols, /<RowMenu /);
  assert.match(cols, /<MfaIcon /);
});
