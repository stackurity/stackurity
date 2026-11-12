/**
 * The occasional "Any feedback?" card (components/FeedbackNudge.tsx): when it
 * shows, remembered per person in this browser. Pure rules here, so they can
 * be tested; storage failures (private windows, blocked storage) mean the
 * card simply does not show.
 */

const DAY = 24 * 60 * 60 * 1000;

export const NUDGE = {
  /** No card on someone's first day: let them look around first. */
  firstAfterMs: 1 * DAY,
  /** After "Not now" (or the card was shown and ignored), ask again a week later. */
  everyMs: 7 * DAY,
  /** After they sent feedback, leave them alone for two weeks. */
  afterSentMs: 14 * DAY,
  /** Only after a few minutes on the dashboard in this visit, never on arrival. */
  minVisitMs: 3 * 60 * 1000,
} as const;

export interface NudgeState {
  /** When this browser first saw this person (ms since epoch). */
  firstSeen: number;
  /** When the card last showed. */
  lastAsked?: number;
  /** When they last sent feedback (from the card, the menu or anywhere else). */
  lastSent?: number;
  /** "Don't ask again". */
  never?: boolean;
}

/** Whether the card may show now. */
export function shouldNudge(s: NudgeState, now: number): boolean {
  if (s.never) return false;
  if (now - s.firstSeen < NUDGE.firstAfterMs) return false;
  if (s.lastAsked !== undefined && now - s.lastAsked < NUDGE.everyMs) return false;
  if (s.lastSent !== undefined && now - s.lastSent < NUDGE.afterSentMs) return false;
  return true;
}

const key = (userId: number) => `stackurity.feedbackNudge.${userId}`;

function storage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}

/** This person's state, created (first seen now) on the first read. Null when storage is unavailable. */
export function readNudge(userId: number, now: number, store: Storage | null = storage()): NudgeState | null {
  if (!store) return null;
  try {
    const raw = store.getItem(key(userId));
    if (raw) {
      const s = JSON.parse(raw) as Partial<NudgeState>;
      if (typeof s.firstSeen === "number") return s as NudgeState;
    }
    const fresh: NudgeState = { firstSeen: now };
    store.setItem(key(userId), JSON.stringify(fresh));
    return fresh;
  } catch {
    return null;
  }
}

/** Merges a change into this person's state. */
export function updateNudge(userId: number, change: Partial<NudgeState>, now: number, store: Storage | null = storage()): void {
  if (!store) return;
  const cur = readNudge(userId, now, store);
  if (!cur) return;
  try {
    store.setItem(key(userId), JSON.stringify({ ...cur, ...change }));
  } catch {
    /* storage full or blocked: the card just shows again later */
  }
}
