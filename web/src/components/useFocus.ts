import { useCallback, useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type RefObject } from "react";
import { focusables, isTopLayer, MENU_ITEM, menuIndex, pushLayer, trapTab } from "../focus";

/**
 * True while the media query matches (false where there is no window, as
 * when a test renders on the server). Follows changes, such as a phone
 * turned on its side.
 */
export function useMediaQuery(query: string): boolean {
  const get = () => typeof window !== "undefined" && typeof window.matchMedia === "function" && window.matchMedia(query).matches;
  const [match, setMatch] = useState(get);
  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const m = window.matchMedia(query);
    const on = () => setMatch(m.matches);
    on();
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, [query]);
  return match;
}

/** The dashboard's phone layout (the tab bar instead of the sidebar). */
export const PHONE_QUERY = "(max-width: 700px)";

/**
 * A menu button and its role="menu" popup (focus.ts): opening moves focus
 * to the first item, or the last when opened with Arrow Up; the arrows,
 * Home and End move between items; Escape closes and focus returns to the
 * button; Tab or a click outside closes it.
 *
 *   const m = useMenu();
 *   <div ref={m.box}><button ref={m.button} {...m.buttonProps}>…</button>
 *     {m.open && <div role="menu" ref={m.menu} onKeyDown={m.onMenuKeyDown}>…</div>}</div>
 */
export function useMenu() {
  const [open, setOpenState] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  // Which item takes focus when the menu opens: the first, or the last.
  const start = useRef<"first" | "last">("first");
  const setOpen = useCallback((v: boolean, from: "first" | "last" = "first") => {
    start.current = from;
    setOpenState(v);
  }, []);
  const close = useCallback((refocus: boolean) => {
    setOpenState(false);
    if (refocus) button.current?.focus();
  }, []);

  useLayoutEffect(() => {
    if (!open) return;
    const items = Array.from(menu.current?.querySelectorAll<HTMLElement>(MENU_ITEM) ?? []);
    (start.current === "last" ? items[items.length - 1] : items[0])?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpenState(false);
    };
    // Escape anywhere while it is open (focus may still be on the button).
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        close(true);
      }
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, close]);

  const onMenuKeyDown = (e: ReactKeyboardEvent) => {
    if (e.key === "Tab") {
      // Tab leaves the menu, as it would any popup; the page's order continues from the button.
      setOpenState(false);
      return;
    }
    const items = Array.from(menu.current?.querySelectorAll<HTMLElement>(MENU_ITEM) ?? []);
    const i = menuIndex(e.key, items.indexOf(document.activeElement as HTMLElement), items.length);
    if (i === null) return;
    e.preventDefault();
    items[i]?.focus();
  };

  const buttonProps = {
    "aria-haspopup": "menu" as const,
    "aria-expanded": open,
    onClick: () => setOpen(!open),
    onKeyDown: (e: ReactKeyboardEvent) => {
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        setOpen(true, e.key === "ArrowUp" ? "last" : "first");
      }
    },
  };

  return { open, setOpen, close, box, button, menu, onMenuKeyDown, buttonProps };
}

/**
 * A modal layer's focus (focus.ts): while active, focus moves into box
 * (initial, else its first control, else box itself), Tab stays inside,
 * the rest of the page is inert, and Escape calls onEscape. When it ends,
 * focus returns to whatever had it before, if that is still on the page.
 * With modal false (the Ask panel on a wide screen, beside the page) only
 * the focus moving in and back applies.
 */
export function useModal(
  box: RefObject<HTMLElement | null>,
  active: boolean,
  opts: { onEscape?: () => void; initial?: () => HTMLElement | null | undefined; restore?: boolean; modal?: boolean } = {},
) {
  const o = useRef(opts);
  o.current = opts;
  const modal = opts.modal !== false;
  useLayoutEffect(() => {
    const el = box.current;
    if (!active || !el) return;
    const back = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const pop = modal ? pushLayer(el) : () => undefined;
    const first = o.current.initial?.() ?? focusables(el)[0] ?? el;
    if (first === el && !el.hasAttribute("tabindex")) el.tabIndex = -1;
    first.focus();
    const onKey = (e: KeyboardEvent) => {
      if (!modal || !isTopLayer(el)) return;
      if (e.key === "Escape" && o.current.onEscape) {
        e.preventDefault();
        o.current.onEscape();
        return;
      }
      trapTab(e, el);
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      pop();
      if (o.current.restore !== false && back && back.isConnected && !back.closest("[inert]")) back.focus();
    };
  }, [active, modal, box]);
}

/** Background isolation only, for a dialog that moves and keeps focus itself (ConfirmHost). */
export function useModalLayer(box: RefObject<HTMLElement | null>, active: boolean) {
  useLayoutEffect(() => {
    const el = box.current;
    if (!active || !el) return;
    return pushLayer(el);
  }, [active, box]);
}
