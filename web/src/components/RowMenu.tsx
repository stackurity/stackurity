import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import { menuKeyClose, menuKeyMove, menuPosition } from "../menu";
import { IconMore } from "./Icons";

export interface RowMenuItem {
  label: string;
  onSelect: () => void;
  danger?: boolean;
  disabled?: boolean;
}

/**
 * A row's actions behind a "⋯" button: a menu that opens under the button,
 * moves with the arrow keys, Home and End, and closes on Escape (focus back
 * on the button), Tab, a click outside, or scrolling its button off screen.
 */
export function RowMenu({ label, items }: { label: string; items: RowMenuItem[] }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const button = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const shown = items;

  const close = (refocus: boolean) => {
    placed.current = false;
    setOpen(false);
    setPos(null);
    if (refocus) button.current?.focus();
  };

  // Placed once its size is known.
  useLayoutEffect(() => {
    if (!open || !button.current || !menu.current) return;
    const b = button.current.getBoundingClientRect();
    const m = menu.current.getBoundingClientRect();
    setPos(menuPosition(b, m, { width: window.innerWidth, height: window.innerHeight }));
  }, [open]);
  // Focus the first item once the menu is placed and visible (a hidden
  // element cannot take focus).
  const placed = useRef(false);
  useEffect(() => {
    if (!pos || placed.current) return;
    placed.current = true;
    menu.current?.querySelector<HTMLButtonElement>('[role="menuitem"]:not(:disabled)')?.focus({ preventScroll: true });
  }, [pos]);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!menu.current?.contains(t) && !button.current?.contains(t)) close(false);
    };
    // Scrolling moves the menu with its button; once the button is off
    // screen the menu closes.
    const onScroll = (e: Event) => {
      if (menu.current?.contains(e.target as Node) || !button.current || !menu.current) return;
      const b = button.current.getBoundingClientRect();
      if (b.bottom < 0 || b.top > window.innerHeight) return close(false);
      setPos(menuPosition(b, menu.current.getBoundingClientRect(), { width: window.innerWidth, height: window.innerHeight }));
    };
    document.addEventListener("mousedown", onDown);
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onScroll);
    return () => {
      document.removeEventListener("mousedown", onDown);
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onScroll);
    };
  }, [open]);

  const onKey = (e: KeyboardEvent) => {
    const c = menuKeyClose(e.key);
    if (c) {
      if (c === "close-refocus") e.preventDefault();
      close(c === "close-refocus");
      return;
    }
    const all = Array.from(menu.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]:not(:disabled)') ?? []);
    const next = menuKeyMove(all.indexOf(document.activeElement as HTMLButtonElement), all.length, e.key);
    if (next === null) return;
    e.preventDefault();
    all[next]?.focus({ preventScroll: true });
  };

  if (shown.length === 0) return null;
  return (
    <div className="row-menu">
      <button
        ref={button}
        type="button"
        className="btn btn-sm row-menu-button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={label}
        title={label}
        onClick={() => (open ? close(false) : setOpen(true))}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown" && !open) {
            e.preventDefault();
            setOpen(true);
          }
        }}
      >
        <IconMore size={16} />
      </button>
      {open && (
        <div
          ref={menu}
          className="menu row-menu-list"
          role="menu"
          aria-label={label}
          onKeyDown={onKey}
          style={pos ? { top: pos.top, left: pos.left } : { visibility: "hidden", top: 0, left: 0 }}
        >
          {shown.map((i) => (
            <button
              key={i.label}
              type="button"
              role="menuitem"
              tabIndex={-1}
              disabled={i.disabled}
              className={`menu-item${i.danger ? " menu-item-danger" : ""}`}
              onClick={() => {
                close(true);
                i.onSelect();
              }}
            >
              {i.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
