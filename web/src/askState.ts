// Ask Stackurity's panel state kept for this browser tab (sessionStorage),
// so a reload brings the panel back as it was: open or not, the
// conversation, and a question half typed. It is kept per organisation and
// person: a tab that switches organisation, or where someone else signs in
// (after a session expired), never shows another's conversation or draft.
// Storage can be missing or refuse (private windows, blocked site data):
// every access is guarded, and the panel then simply starts closed and
// empty.

import { looksLikeSecret } from "./askSecrets.ts";

export interface AskPanelState {
  open: boolean;
  minimised: boolean;
  conversation: number | null;
  text: string;
}

const KEY = "stackurity.ask.panel.v1";
const MAX_TEXT = 4000;

export const EMPTY_ASK_STATE: AskPanelState = { open: false, minimised: false, conversation: null, text: "" };

type Store = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function storage(): Store | null {
  try {
    return typeof sessionStorage === "undefined" ? null : sessionStorage;
  } catch {
    return null;
  }
}

/** The saved state for person user in workspace ws, or the empty state. */
export function loadAskState(ws: number | undefined, user: number | undefined, store: Store | null = storage()): AskPanelState {
  if (!ws || !user || !store) return { ...EMPTY_ASK_STATE };
  try {
    const raw = store.getItem(KEY);
    if (!raw) return { ...EMPTY_ASK_STATE };
    const v = JSON.parse(raw) as Partial<AskPanelState> & { ws?: number; user?: number };
    if (v.ws !== ws || v.user !== user) return { ...EMPTY_ASK_STATE };
    return {
      open: v.open === true,
      minimised: v.minimised === true,
      conversation: typeof v.conversation === "number" && Number.isSafeInteger(v.conversation) && v.conversation > 0 ? v.conversation : null,
      text: typeof v.text === "string" ? v.text.slice(0, MAX_TEXT) : "",
    };
  } catch {
    return { ...EMPTY_ASK_STATE };
  }
}

/** Saves s for person user in workspace ws; a failure is ignored. */
export function saveAskState(ws: number | undefined, user: number | undefined, s: AskPanelState, store: Store | null = storage()): void {
  if (!ws || !user || !store) return;
  try {
    // A question that holds a secret is not kept for the tab (askSecrets.ts).
    const text = looksLikeSecret(s.text) ? "" : s.text.slice(0, MAX_TEXT);
    store.setItem(KEY, JSON.stringify({ ws, user, ...s, text }));
  } catch {
    // full or refused: the panel works, it just won't survive a reload
  }
}

/** Forgets the state (switching organisation, signing out). */
export function clearAskState(store: Store | null = storage()): void {
  try {
    store?.removeItem(KEY);
  } catch {
    // nothing to do
  }
}

// The Ask settings card (Integrations → AI assistants) and the panel's
// status live in different parts of the page: the shell loads the status
// once, so turning Ask on or off there left an open panel saying it was off
// until a reload (21 Nov 2026). The card announces each saved change and the
// shell reloads the status.
const settingsChanged = new EventTarget();

export function announceAskSettingsChanged(): void {
  settingsChanged.dispatchEvent(new Event("changed"));
}

export function onAskSettingsChanged(fn: () => void): () => void {
  const h = () => fn();
  settingsChanged.addEventListener("changed", h);
  return () => settingsChanged.removeEventListener("changed", h);
}

// Asking from elsewhere on the page (the Dashboard's Ask card, an empty
// state): the panel opens with the question and asks it. The panel is in
// the shell, so it listens rather than being handed the question.
const asked = new EventTarget();

export function askStackurity(question: string): void {
  asked.dispatchEvent(new CustomEvent<string>("ask", { detail: question }));
}

export function onAskStackurity(fn: (question: string) => void): () => void {
  const h = (e: Event) => fn((e as CustomEvent<string>).detail);
  asked.addEventListener("ask", h);
  return () => asked.removeEventListener("ask", h);
}
