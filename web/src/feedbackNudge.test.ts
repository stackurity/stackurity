import { test } from "node:test";
import assert from "node:assert/strict";
import { NUDGE, readNudge, shouldNudge, updateNudge } from "./feedbackNudge.ts";

const DAY = 24 * 60 * 60 * 1000;
const T0 = Date.UTC(2026, 10, 12);

function memStore(): Storage {
  const m = new Map<string, string>();
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    getItem: (k) => m.get(k) ?? null,
    key: (i) => [...m.keys()][i] ?? null,
    removeItem: (k) => void m.delete(k),
    setItem: (k, v) => void m.set(k, String(v)),
  };
}

test("no card on the first day, then one", () => {
  assert.equal(shouldNudge({ firstSeen: T0 }, T0 + 2 * 60 * 60 * 1000), false);
  assert.equal(shouldNudge({ firstSeen: T0 }, T0 + NUDGE.firstAfterMs), true);
});

test("after the card showed, a week passes before the next", () => {
  const s = { firstSeen: T0, lastAsked: T0 + 2 * DAY };
  assert.equal(shouldNudge(s, T0 + 8 * DAY), false);
  assert.equal(shouldNudge(s, T0 + 9 * DAY), true);
});

test("after feedback was sent, two weeks pass", () => {
  const s = { firstSeen: T0, lastSent: T0 + 2 * DAY };
  assert.equal(shouldNudge(s, T0 + 15 * DAY), false);
  assert.equal(shouldNudge(s, T0 + 16 * DAY), true);
});

test("don't ask again is final", () => {
  assert.equal(shouldNudge({ firstSeen: T0, never: true }, T0 + 365 * DAY), false);
});

test("state is per person and survives a re-read", () => {
  const store = memStore();
  assert.deepEqual(readNudge(7, T0, store), { firstSeen: T0 });
  assert.deepEqual(readNudge(7, T0 + DAY, store), { firstSeen: T0 }, "first seen is kept, not moved");
  updateNudge(7, { lastAsked: T0 + 2 * DAY }, T0 + 2 * DAY, store);
  assert.deepEqual(readNudge(7, T0 + 3 * DAY, store), { firstSeen: T0, lastAsked: T0 + 2 * DAY });
  assert.deepEqual(readNudge(8, T0 + 3 * DAY, store), { firstSeen: T0 + 3 * DAY }, "another person starts fresh");
});

test("no storage or broken storage means no card", () => {
  assert.equal(readNudge(7, T0, null), null);
  const store = memStore();
  store.setItem("stackurity.feedbackNudge.7", "{not json");
  assert.equal(readNudge(7, T0, store), null);
});
