/**
 * Keyboard focus for menus and modal layers, shared by the account,
 * project, workspace and row-action menus, the phone More sheet, the Ask
 * panel on phones, the Ask consent dialog and the confirmation dialog
 * (components/useFocus.ts has the React hooks around these).
 *
 * A menu (role="menu"): opening it moves focus to its first item; Arrow
 * Down and Up move between items and wrap, Home and End go to the first
 * and last; Escape closes it and focus returns to its button.
 *
 * A modal layer: focus moves in, Tab and Shift+Tab stay inside it, and
 * everything else on the page is inert (it cannot be focused, clicked or
 * read by a screen reader) until it closes; focus then returns to the
 * control that opened it. Layers stack: a confirmation opened from the Ask
 * panel isolates the panel too, and closing it gives the panel back.
 */

import { nextFocus } from "./confirm.ts";

export const FOCUSABLE =
  'a[href]:not([aria-disabled="true"]), button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** The items of a menu: menuitem, menuitemradio and menuitemcheckbox. */
export const MENU_ITEM = '[role="menuitem"], [role="menuitemradio"], [role="menuitemcheckbox"]';

/**
 * The menu item to move to on a key, from index cur among count items:
 * Down and Up wrap at the ends, Home and End go to the first and last. null
 * when the key does not move focus. A focus on no item (cur < 0) goes to
 * the first going down and the last going up.
 */
export function menuIndex(key: string, cur: number, count: number): number | null {
  if (count <= 0) return null;
  switch (key) {
    case "ArrowDown":
      return cur < 0 || cur >= count ? 0 : (cur + 1) % count;
    case "ArrowUp":
      return cur < 0 || cur >= count ? count - 1 : (cur - 1 + count) % count;
    case "Home":
      return 0;
    case "End":
      return count - 1;
    default:
      return null;
  }
}

/** The elements of root that take keyboard focus, in order; hidden ones are left out. */
export function focusables(root: ParentNode | null | undefined): HTMLElement[] {
  if (!root) return [];
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((el) => !el.closest("[hidden], [inert]") && el.getClientRects().length > 0);
}

/**
 * Keeps Tab inside root: from the last element Tab goes to the first, from
 * the first Shift+Tab goes to the last, and a focus outside root comes back
 * in. True when the key was handled.
 */
export function trapTab(e: { key: string; shiftKey: boolean; preventDefault: () => void }, root: HTMLElement | null): boolean {
  if (e.key !== "Tab" || !root) return false;
  const items = focusables(root);
  e.preventDefault();
  if (items.length === 0) {
    root.focus();
    return true;
  }
  const i = nextFocus(items.indexOf(document.activeElement as HTMLElement), items.length, e.shiftKey);
  items[i]?.focus();
  return true;
}

// --- modal layers

const layers: HTMLElement[] = [];
let madeInert: HTMLElement[] = [];

/**
 * The elements to make inert so that only el (and its ancestors, which hold
 * it) stays usable: every sibling of el and of each of its ancestors up to
 * the body. Elements already inert by someone else are left alone.
 */
export function inertSiblings(el: HTMLElement): HTMLElement[] {
  const out: HTMLElement[] = [];
  let node: HTMLElement = el;
  while (node.parentElement && node !== document.body) {
    const parent = node.parentElement;
    for (const sib of Array.from(parent.children)) {
      if (sib === node || !(sib instanceof HTMLElement) || sib.inert) continue;
      if (sib.tagName === "SCRIPT" || sib.tagName === "STYLE" || sib.tagName === "TEMPLATE") continue;
      out.push(sib);
    }
    node = parent;
  }
  return out;
}

function applyLayers() {
  for (const el of madeInert) el.inert = false;
  madeInert = [];
  const top = layers[layers.length - 1];
  if (!top || !top.isConnected) return;
  madeInert = inertSiblings(top);
  for (const el of madeInert) el.inert = true;
}

/** Makes everything but el inert until the returned function is called. */
export function pushLayer(el: HTMLElement): () => void {
  layers.push(el);
  applyLayers();
  return () => {
    const i = layers.lastIndexOf(el);
    if (i >= 0) layers.splice(i, 1);
    applyLayers();
  };
}

/** True when el is the top modal layer (or inside it), so its keys are its own. */
export function isTopLayer(el: HTMLElement | null): boolean {
  const top = layers[layers.length - 1];
  return Boolean(el && top && (top === el || top.contains(el)));
}
