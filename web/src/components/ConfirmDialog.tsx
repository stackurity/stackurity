import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { canConfirm, confirmWord, keyAction, nextFocus, type ConfirmRequest, type PromptRequest } from "../confirm";

/**
 * One in-app dialog for every confirmation and text prompt, instead of the
 * browser's confirm and prompt: role=alertdialog, focus moves in and stays
 * in, Esc cancels, Enter never confirms a destructive action, and a
 * destructive action needs its resource's name typed first.
 *
 *   if (!(await confirmAction({ title: `Delete asset ${a.name}?`, consequence: "...",
 *     action: "Delete asset", destructive: true, typeToConfirm: a.name }))) return;
 *   const name = await promptText({ title: "New project", label: "Name", action: "Create project" });
 *
 * ConfirmHost is mounted once, at the root.
 */

type Pending =
  | { kind: "confirm"; req: ConfirmRequest; resolve: (ok: boolean) => void }
  | { kind: "prompt"; req: PromptRequest; resolve: (text: string | null) => void };

let open: ((p: Pending) => void) | null = null;
const queue: Pending[] = [];

/** Asks for confirmation; true when the action was confirmed. */
export function confirmAction(req: ConfirmRequest): Promise<boolean> {
  return new Promise((resolve) => show({ kind: "confirm", req, resolve }));
}

/** Asks for a line of text; null when cancelled. */
export function promptText(req: PromptRequest): Promise<string | null> {
  return new Promise((resolve) => show({ kind: "prompt", req, resolve }));
}

function show(p: Pending) {
  if (open) open(p);
  else queue.push(p);
}

const FOCUSABLE = 'button:not([disabled]), input:not([disabled]), [href], select, textarea, [tabindex]:not([tabindex="-1"])';

export function ConfirmHost() {
  const [cur, setCur] = useState<Pending | null>(null);
  const [typed, setTyped] = useState("");
  const box = useRef<HTMLDivElement>(null);
  const back = useRef<HTMLElement | null>(null);

  useEffect(() => {
    open = (p) => {
      back.current = document.activeElement as HTMLElement | null;
      setTyped(p.kind === "prompt" ? (p.req.initial ?? "") : "");
      setCur(p);
    };
    const first = queue.shift();
    if (first) open(first);
    return () => {
      open = null;
    };
  }, []);

  // Focus moves in: the field when there is one, else the action button.
  useEffect(() => {
    if (!cur) return;
    const el = box.current?.querySelector<HTMLElement>("input, .confirm-action:not([disabled])") ?? box.current;
    el?.focus();
    if (el instanceof HTMLInputElement) el.select();
  }, [cur]);

  if (!cur) return null;

  const close = (value: boolean | string | null) => {
    if (cur.kind === "confirm") cur.resolve(value === true);
    else cur.resolve(typeof value === "string" ? value : null);
    setCur(null);
    back.current?.focus?.();
    const next = queue.shift();
    if (next) setTimeout(() => open?.(next), 0);
  };

  const asConfirm: ConfirmRequest =
    cur.kind === "confirm" ? cur.req : { title: cur.req.title, action: cur.req.action, destructive: false };
  const word = confirmWord(asConfirm);
  const ready = cur.kind === "prompt" ? cur.req.allowEmpty || typed.trim() !== "" : canConfirm(asConfirm, typed);
  const done = () => {
    if (!ready) return;
    close(cur.kind === "prompt" ? typed.trim() : true);
  };

  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Tab") {
      const items = Array.from(box.current?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? []);
      const i = nextFocus(items.indexOf(document.activeElement as HTMLElement), items.length, e.shiftKey);
      e.preventDefault();
      items[i]?.focus();
      return;
    }
    // Enter on Cancel cancels, as a click would.
    if (e.key === "Enter" && document.activeElement instanceof HTMLButtonElement && !document.activeElement.classList.contains("confirm-action")) return;
    const k = keyAction(e.key, asConfirm, typed);
    if (k === "cancel") {
      e.preventDefault();
      close(cur.kind === "confirm" ? false : null);
    } else if (k === "block") {
      e.preventDefault();
    } else if (k === "confirm") {
      e.preventDefault();
      done();
    }
  };

  const titleId = "confirm-title";
  const descId = "confirm-desc";
  return (
    <div className="confirm-backdrop" onMouseDown={(e) => e.target === e.currentTarget && close(cur.kind === "confirm" ? false : null)}>
      <div
        ref={box}
        className={`confirm-dialog${asConfirm.destructive ? " confirm-destructive" : ""}`}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
        tabIndex={-1}
        onKeyDown={onKey}
      >
        <h2 id={titleId} className="confirm-title">
          {cur.req.title}
        </h2>
        <div id={descId} className="confirm-body">
          {cur.req.message && <p>{cur.req.message}</p>}
          {cur.kind === "confirm" && cur.req.consequence && <p className="confirm-consequence">{cur.req.consequence}</p>}
          {word && (
            <div className="field">
              <label htmlFor="confirm-type">
                Type <code className="confirm-word">{word}</code> to confirm
              </label>
              <input
                id="confirm-type"
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                aria-invalid={typed !== "" && !ready}
              />
            </div>
          )}
          {cur.kind === "prompt" && (
            <div className="field">
              <label htmlFor="confirm-text">{cur.req.label}</label>
              <input id="confirm-text" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
            </div>
          )}
        </div>
        <div className="confirm-actions">
          <button type="button" className="btn" onClick={() => close(cur.kind === "confirm" ? false : null)}>
            Cancel
          </button>
          <button
            type="button"
            className={`btn confirm-action ${asConfirm.destructive ? "btn-danger" : "btn-primary"}`}
            disabled={!ready}
            onClick={done}
          >
            {cur.req.action}
          </button>
        </div>
      </div>
    </div>
  );
}
