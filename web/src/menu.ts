// Keyboard rules of a menu opened from a button (the "⋯" row menu): pure, so
// they are tested without a browser.

/** Where focus goes for a key in an open menu; null when the key is not the menu's. Arrows wrap. */
export function menuKeyMove(current: number, count: number, key: string): number | null {
  if (count === 0) return null;
  switch (key) {
    case "ArrowDown":
      return current < 0 ? 0 : (current + 1) % count;
    case "ArrowUp":
      return current <= 0 ? count - 1 : current - 1;
    case "Home":
      return 0;
    case "End":
      return count - 1;
    default:
      return null;
  }
}

/** What a key does to the menu itself: Escape closes and returns focus to the button; Tab closes and lets focus move on. */
export function menuKeyClose(key: string): "close-refocus" | "close" | null {
  if (key === "Escape") return "close-refocus";
  if (key === "Tab") return "close";
  return null;
}

/**
 * Where the menu opens, in the window's coordinates: under the button,
 * right-aligned to it, and above it when there is no room below. Fixed
 * positioning keeps it out of the table's scroll box, which would clip it.
 */
export function menuPosition(
  button: { top: number; bottom: number; right: number },
  menu: { width: number; height: number },
  view: { width: number; height: number },
  gap = 4,
): { top: number; left: number } {
  const below = button.bottom + gap;
  const top = below + menu.height <= view.height - gap ? below : Math.max(gap, button.top - gap - menu.height);
  const left = Math.min(Math.max(gap, button.right - menu.width), view.width - menu.width - gap);
  return { top, left };
}
