import { test } from "node:test";
import assert from "node:assert/strict";
import { historyGroups, type AskConversation } from "./ask.ts";

const conv = (id: number, updated: Date): AskConversation => ({
  id,
  project_id: null,
  title: `c${id}`,
  model: "",
  created_at: updated.toISOString(),
  updated_at: updated.toISOString(),
  expires_at: updated.toISOString(),
});

test("history groups by day, newest first, without empty groups", () => {
  const now = new Date(2026, 10, 12, 10, 0);
  const got = historyGroups(
    [conv(1, new Date(2026, 10, 12, 9, 0)), conv(2, new Date(2026, 10, 11, 23, 0)), conv(3, new Date(2026, 10, 1)), conv(4, new Date(2026, 10, 12, 9, 30))],
    now,
  );
  assert.deepEqual(
    got.map((g) => [g.label, g.items.map((c) => c.id)]),
    [
      ["Today", [4, 1]],
      ["Yesterday", [2]],
      ["Earlier", [3]],
    ],
  );
  assert.deepEqual(historyGroups([conv(5, new Date(2026, 9, 1))], now).map((g) => g.label), ["Earlier"]);
});
