/**
 * The rules of the in-app confirmation dialog (components/ConfirmDialog.tsx),
 * kept free of React so node --test can check them. The browser's own
 * confirm, alert and prompt are never used (no-browser-dialogs.test.ts).
 */

/** What a confirmation asks. */
export interface ConfirmRequest {
  /** The question: "Delete asset web-1?" */
  title: string;
  /** The existing explanation, if any. */
  message?: string;
  /** What happens, on its own line: "Its inventory and history are deleted." */
  consequence?: string;
  /** The button, named for the action: "Delete asset", never "OK". */
  action: string;
  /**
   * Destructive or irreversible: a red button that is enabled only once the
   * person types typeToConfirm (the resource's name, or "delete" when it has
   * none), and that Enter never presses.
   */
  destructive?: boolean;
  typeToConfirm?: string;
}

/** A request for a line of text, in the same dialog. */
export interface PromptRequest {
  title: string;
  message?: string;
  label: string;
  initial?: string;
  action: string;
  /** Allow an empty answer (default: the action stays disabled until something is typed). */
  allowEmpty?: boolean;
}

/** What must be typed for a destructive request; "" when nothing is. */
export function confirmWord(r: ConfirmRequest): string {
  if (!r.destructive) return "";
  const name = (r.typeToConfirm ?? "").trim();
  return name || "delete";
}

/** Case-sensitive, spaces around trimmed. */
export function typedMatches(typed: string, word: string): boolean {
  return typed.trim() === word.trim();
}

/** Whether the action button is enabled. */
export function canConfirm(r: ConfirmRequest, typed: string): boolean {
  const w = confirmWord(r);
  return w === "" || typedMatches(typed, w);
}

/** What a key does in the dialog: cancel, confirm, or nothing special. */
export function keyAction(key: string, r: ConfirmRequest, typed: string): "cancel" | "confirm" | "block" | "none" {
  if (key === "Escape") return "cancel";
  if (key === "Enter") {
    // Enter never confirms a destructive action, wherever the focus is.
    if (r.destructive) return "block";
    return canConfirm(r, typed) ? "confirm" : "block";
  }
  return "none";
}

/**
 * Focus trap: the index to move to on Tab (or Shift+Tab) from index cur
 * among count focusable elements, wrapping at both ends. A focus outside
 * them (cur < 0) goes to the first, or the last going backwards.
 */
export function nextFocus(cur: number, count: number, back: boolean): number {
  if (count <= 0) return -1;
  if (cur < 0 || cur >= count) return back ? count - 1 : 0;
  return back ? (cur - 1 + count) % count : (cur + 1) % count;
}

/**
 * Requests waiting for the one dialog: shown one at a time, in order, so a
 * second confirmation while one is open waits its turn instead of replacing
 * it (and leaving the first promise unanswered).
 */
export class DialogQueue<T> {
  private items: T[] = [];
  private showing: T | null = null;
  /** Adds a request; returns it when it is shown at once, else null. */
  push(item: T): T | null {
    if (this.showing === null) {
      this.showing = item;
      return item;
    }
    this.items.push(item);
    return null;
  }
  /** The request on screen. */
  current(): T | null {
    return this.showing;
  }
  /** The shown request was answered; returns the next to show, or null. */
  done(): T | null {
    this.showing = this.items.shift() ?? null;
    return this.showing;
  }
}
