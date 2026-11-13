import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { MENU_ITEM, menuIndex } from "./focus.ts";

test("menu keys: Down and Up wrap, Home and End go to the ends, other keys do nothing", () => {
  assert.equal(menuIndex("ArrowDown", 0, 3), 1);
  assert.equal(menuIndex("ArrowDown", 2, 3), 0);
  assert.equal(menuIndex("ArrowUp", 0, 3), 2);
  assert.equal(menuIndex("ArrowUp", 2, 3), 1);
  assert.equal(menuIndex("Home", 2, 3), 0);
  assert.equal(menuIndex("End", 0, 3), 2);
  // Focus on no item (still on the button): Down to the first, Up to the last.
  assert.equal(menuIndex("ArrowDown", -1, 3), 0);
  assert.equal(menuIndex("ArrowUp", -1, 3), 2);
  assert.equal(menuIndex("Enter", 1, 3), null);
  assert.equal(menuIndex("ArrowDown", 0, 0), null);
});

test("menu items include the radio items of the workspace and project switchers", () => {
  assert.match(MENU_ITEM, /menuitem"/);
  assert.match(MENU_ITEM, /menuitemradio/);
});

// The menus and modal layers must use the shared helpers: a menu that only
// declares role="menu" leaves keyboard users on its button (R003-50), and a
// sheet or dialog without a layer lets focus wander behind it (R003-54, 60).
const src = (p: string) => readFileSync(new URL(p, import.meta.url), "utf8");

test("every role=menu popup takes the shared menu keys", () => {
  for (const f of ["./components/Layout.tsx", "./components/Leaks.tsx"]) {
    const s = src(f);
    const menus = s.match(/role="menu"[^>]*>/g) ?? [];
    assert.ok(menus.length > 0, f);
    for (const m of menus) assert.match(m, /onKeyDown=\{(pop|m)\.onMenuKeyDown\}/, `${f}: ${m}`);
  }
});

test("the More sheet, the Ask panel, the Ask consent and the confirmation dialog are modal layers", () => {
  assert.match(src("./components/Layout.tsx"), /useModal\(moreSheet, more, \{ onEscape: \(\) => setMore\(false\) \}\)/);
  const ask = src("./components/AskPanel.tsx");
  assert.match(ask, /useModal\(panel, open, \{ modal: phone, initial: \(\) => input\.current \?\? notice\.current \}\)/);
  assert.match(ask, /useModal\(box, true, \{ onEscape: onCancel/);
  assert.match(src("./components/ConfirmDialog.tsx"), /useModalLayer\(box, Boolean\(cur\)\)/);
});
